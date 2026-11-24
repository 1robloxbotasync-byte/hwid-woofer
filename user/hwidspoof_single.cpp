// hwidspoof_single.cpp — one-translation-unit user-mode HWID spoofer
//
// Built by Olivia — https://discord.gg/ojailbreaks
//
// Covers every surface the multi-file build touches that does NOT need ring 0:
//   MachineGuid, ProductId, InstallDate, HwProfileGuid, SQMClient MachineId,
//   WindowsUpdate SusClientId, ComputerHardwareId, SystemInformation mirror,
//   ComputerName (live + pending), NIC MACs (NetworkAddress + miniport bounce),
//   SMBIOS table at mssmbios\Data\SMBiosData (types 0/1/2/3/17/127).
//
// Writes profile.ini, DPAPI-sealed backup.ini and smbios_orig.bin beside the
// exe. Prints masked originals; spoofed values print in full. --restore
// writes everything back. --reveal unmasks. All one file.
//
//   cl /std:c++20 /W4 /permissive- /EHsc /MT /O2 hwidspoof_single.cpp ^
//      advapi32.lib iphlpapi.lib crypt32.lib shell32.lib ole32.lib ^
//      setupapi.lib cfgmgr32.lib rpcrt4.lib bcrypt.lib

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>
#include <wincrypt.h>
#include <dpapi.h>
#include <bcrypt.h>
#include <shellapi.h>
#include <shlobj.h>
#include <iphlpapi.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <devguid.h>
#include <lmcons.h>
#include <rpc.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "bcrypt.lib")

namespace fs = std::filesystem;
using std::string;
using std::wstring;
using std::vector;

// ---------- globals ----------

struct Opts {
    bool do_spoof    = false;
    bool do_restore  = false;
    bool do_verify   = false;
    bool do_status   = false;
    bool dry         = false;
    bool no_registry = false;
    bool no_network  = false;
    bool no_smbios   = false;
    bool reveal      = false;
    bool verbose     = false;
    uint64_t seed    = 0;
    bool seed_set    = false;
    wstring profile;
};

static Opts  g_opt;
static FILE* g_log = nullptr;
static fs::path g_exe_dir;

// ---------- utf-8 / wstring plumbing ----------

static string wtoa(wstring_view w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}
static wstring atow(string_view s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

static void vlog(const char* level, const char* fmt, va_list ap) {
    char buf[4096];
    _vsnprintf_s(buf, _TRUNCATE, fmt, ap);
    SYSTEMTIME t; GetLocalTime(&t);
    char hdr[64];
    _snprintf_s(hdr, _TRUNCATE, "[%02u:%02u:%02u] %-5s ",
        t.wHour, t.wMinute, t.wSecond, level);
    fputs(hdr, stdout); fputs(buf, stdout); fputc('\n', stdout);
    if (g_log) { fputs(hdr, g_log); fputs(buf, g_log); fputc('\n', g_log); fflush(g_log); }
}
static void info(const char* f, ...){ va_list a; va_start(a,f); vlog("INFO",f,a); va_end(a); }
static void warn(const char* f, ...){ va_list a; va_start(a,f); vlog("WARN",f,a); va_end(a); }
static void err (const char* f, ...){ va_list a; va_start(a,f); vlog("ERR" ,f,a); va_end(a); }
static void dbg (const char* f, ...){ if(!g_opt.verbose) return; va_list a; va_start(a,f); vlog("DBG" ,f,a); va_end(a); }

static string mask(string_view s) {
    if (g_opt.reveal) return string(s);
    string out; out.reserve(s.size());
    for (char c : s) out += (c=='-'||c==':'||c=='{'||c=='}'||c==' ') ? c : '*';
    return out;
}

// ---------- RAII ----------

struct ScopedHKey {
    HKEY h{};
    ~ScopedHKey(){ if(h) RegCloseKey(h); }
    operator HKEY() const { return h; }
    HKEY* operator&(){ return &h; }
};
struct ScopedSC {
    SC_HANDLE h{};
    ScopedSC()=default;
    explicit ScopedSC(SC_HANDLE s):h(s){}
    ~ScopedSC(){ if(h) CloseServiceHandle(h); }
    operator SC_HANDLE() const { return h; }
};

// ---------- elevation ----------

static bool is_admin() {
    BOOL ok = FALSE;
    PSID sid = nullptr;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0,0,0,0,0,0, &sid)) {
        CheckTokenMembership(nullptr, sid, &ok);
        FreeSid(sid);
    }
    return ok == TRUE;
}

static int self_elevate(int argc, wchar_t** argv) {
    wchar_t self[MAX_PATH];
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    wstring args;
    for (int i=1;i<argc;++i){ if(i>1) args+=L' '; args+=L'"'; args+=argv[i]; args+=L'"'; }
    SHELLEXECUTEINFOW si{sizeof(si)};
    si.lpVerb   = L"runas";
    si.lpFile   = self;
    si.lpParameters = args.c_str();
    si.nShow    = SW_SHOWNORMAL;
    si.fMask    = SEE_MASK_NOCLOSEPROCESS;
    if (!ShellExecuteExW(&si)) return 1;
    WaitForSingleObject(si.hProcess, INFINITE);
    DWORD rc = 0; GetExitCodeProcess(si.hProcess, &rc);
    CloseHandle(si.hProcess);
    return (int)rc;
}

// ---------- RNG seeded identity ----------

class XorShift64 {
    uint64_t s_;
public:
    explicit XorShift64(uint64_t s) : s_(s ? s : 0xdeadbeefcafebabeULL) {}
    uint64_t next(){
        uint64_t x = s_;
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        return s_ = x;
    }
    uint32_t u32(){ return (uint32_t)next(); }
    uint8_t  u8 (){ return (uint8_t) next(); }
};

static uint64_t os_rand64() {
    uint64_t v = 0;
    BCryptGenRandom(nullptr, (PUCHAR)&v, sizeof(v), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!v) v = (uint64_t)GetTickCount64() * 0x9e3779b97f4a7c15ULL;
    return v;
}

static string hex_str(uint64_t v, int digits){
    static const char* H="0123456789ABCDEF";
    string s(digits,'0');
    for(int i=digits-1;i>=0;--i){ s[i]=H[v&0xF]; v>>=4; }
    return s;
}

static string guid_str(XorShift64& r){
    char buf[40];
    uint32_t a=r.u32(), b=r.u32(), c=r.u32(), d=r.u32();
    // RFC 4122 v4 formatting
    b = (b & 0x0000FFFF) | 0x00004000;
    c = (c & 0x3FFFFFFF) | 0x80000000;
    _snprintf_s(buf, _TRUNCATE,
        "{%08X-%04X-%04X-%04X-%04X%08X}",
        a, (b>>16)&0xFFFF, b&0xFFFF, (c>>16)&0xFFFF, c&0xFFFF, d);
    return buf;
}
static string guid_nobrace(XorShift64& r){
    string g = guid_str(r);
    return g.substr(1, g.size()-2);
}

struct Mac { uint8_t b[6]; };
static Mac gen_mac(XorShift64& r){
    Mac m;
    for(int i=0;i<6;++i) m.b[i]=r.u8();
    m.b[0] = (m.b[0] & 0xFC) | 0x02;  // locally administered, unicast
    return m;
}
static string mac_colon(const Mac& m){
    char b[24];
    _snprintf_s(b,_TRUNCATE,"%02X:%02X:%02X:%02X:%02X:%02X",
        m.b[0],m.b[1],m.b[2],m.b[3],m.b[4],m.b[5]);
    return b;
}
static string mac_plain(const Mac& m){
    char b[16];
    _snprintf_s(b,_TRUNCATE,"%02X%02X%02X%02X%02X%02X",
        m.b[0],m.b[1],m.b[2],m.b[3],m.b[4],m.b[5]);
    return b;
}

struct Identity {
    uint64_t seed;
    string machine_guid;
    string product_id;
    string install_date_hex;   // DWORD-hex, seconds since epoch
    string hw_profile_guid;
    string sqm_machine_id;
    string sus_client_id;
    string computer_hardware_id;
    string system_sku;
    string computer_name;
    // smbios
    string bios_vendor, bios_version, bios_date;
    string sys_manufacturer, sys_product, sys_version, sys_serial, sys_sku, sys_family;
    string sys_uuid;
    string board_manufacturer, board_product, board_version, board_serial;
    string chassis_manufacturer, chassis_version, chassis_serial;
    vector<string> dimm_serials;
    vector<Mac>    macs;
};

static const vector<string> kVendors = {
    "American Megatrends Inc.", "AMI", "Phoenix Technologies Ltd.",
    "Insyde Corp.", "Dell Inc.", "LENOVO"
};
static const vector<string> kSysMakers = {
    "ASUS", "Dell Inc.", "HP", "LENOVO", "Micro-Star International Co., Ltd.",
    "Gigabyte Technology Co., Ltd.", "ASRock"
};
static const vector<string> kSysProducts = {
    "System Product Name", "OptiPlex 7090", "Latitude 7420", "ThinkPad X1 Carbon Gen 10",
    "ROG STRIX B550-F GAMING", "Z790 AORUS ELITE AX", "PRO Z790-A WIFI"
};
static const vector<string> kBoardProducts = {
    "PRIME B550-PLUS", "0A1B2C", "20X1S0CX00", "Z790 AORUS ELITE AX",
    "MS-7D91", "TUF GAMING X570-PLUS"
};
static const vector<string> kChassisMakers = {
    "Default string", "Chassis Manufacture", "Dell Inc.", "LENOVO", "ASUS"
};
static const vector<string> kBiosDates = {
    "09/12/2023","04/18/2024","11/02/2024","01/17/2025","06/05/2025","08/22/2025"
};

template<class T>
static const T& pick(const vector<T>& v, XorShift64& r){
    return v[r.u32() % v.size()];
}

static string serial_token(XorShift64& r, int len){
    static const char* A="ABCDEFGHJKLMNPQRSTUVWXYZ0123456789";
    string s(len,'0');
    for(int i=0;i<len;++i) s[i]=A[r.u32()%34];
    return s;
}
static string bios_ver_token(XorShift64& r){
    char b[32];
    _snprintf_s(b,_TRUNCATE,"%u.%u.%u",
        1 + r.u32()%6, r.u32()%40, 1000 + r.u32()%9000);
    return b;
}

static Identity make_identity(uint64_t seed){
    XorShift64 r(seed);
    Identity id;
    id.seed = seed;
    id.machine_guid    = guid_nobrace(r);
    char pid[32];
    _snprintf_s(pid,_TRUNCATE,"%05u-%03u-%07u-%05u",
        r.u32()%100000, r.u32()%1000, r.u32()%10000000, r.u32()%100000);
    id.product_id = pid;
    id.install_date_hex = hex_str( (uint64_t)time(nullptr) - (uint64_t)(r.u32()%(400*86400)), 8 );
    id.hw_profile_guid   = guid_str(r);
    id.sqm_machine_id    = guid_str(r);
    id.sus_client_id     = guid_nobrace(r);
    id.computer_hardware_id = guid_str(r);
    id.system_sku        = serial_token(r, 10);
    {
        char nm[32];
        _snprintf_s(nm,_TRUNCATE,"DESKTOP-%s", serial_token(r,7).c_str());
        id.computer_name = nm;
    }
    id.bios_vendor       = pick(kVendors, r);
    id.bios_version      = bios_ver_token(r);
    id.bios_date         = pick(kBiosDates, r);
    id.sys_manufacturer  = pick(kSysMakers, r);
    id.sys_product       = pick(kSysProducts, r);
    id.sys_version       = "1.0";
    id.sys_serial        = serial_token(r, 12);
    id.sys_sku           = id.system_sku;
    id.sys_family        = "To be filled by O.E.M.";
    id.sys_uuid          = guid_nobrace(r);
    id.board_manufacturer= id.sys_manufacturer;
    id.board_product     = pick(kBoardProducts, r);
    id.board_version     = "Rev 1.xx";
    id.board_serial      = serial_token(r, 14);
    id.chassis_manufacturer = pick(kChassisMakers, r);
    id.chassis_version   = "N/A";
    id.chassis_serial    = serial_token(r, 12);
    int dimms = 2 + (r.u32()%3);
    for (int i=0;i<dimms;++i) id.dimm_serials.push_back(serial_token(r,10));
    // 4 MAC candidates; the applier picks as many as the machine has NICs
    for (int i=0;i<4;++i) id.macs.push_back(gen_mac(r));
    return id;
}

// ---------- tiny INI ----------

struct Ini {
    std::map<string, std::map<string,string>> data;
    void set(const string& sec, const string& key, const string& val){
        data[sec][key] = val;
    }
    string get(const string& sec, const string& key, const string& dflt="") const {
        auto it = data.find(sec);
        if (it==data.end()) return dflt;
        auto jt = it->second.find(key);
        return jt==it->second.end()? dflt : jt->second;
    }
    string serialize() const {
        std::ostringstream o;
        for (auto& [sec, kv] : data){
            o << "[" << sec << "]\n";
            for (auto& [k,v] : kv) o << k << "=" << v << "\n";
            o << "\n";
        }
        return o.str();
    }
    bool parse(const string& text){
        std::istringstream in(text);
        string line, cur;
        while (std::getline(in,line)){
            if (!line.empty() && line.back()=='\r') line.pop_back();
            if (line.empty() || line[0]==';' || line[0]=='#') continue;
            if (line.front()=='[' && line.back()==']'){ cur=line.substr(1,line.size()-2); continue; }
            auto eq = line.find('=');
            if (eq==string::npos) continue;
            data[cur][line.substr(0,eq)] = line.substr(eq+1);
        }
        return true;
    }
};

static bool write_file_bytes(const fs::path& p, const vector<uint8_t>& bytes){
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    if (!bytes.empty()) f.write((const char*)bytes.data(), bytes.size());
    return (bool)f;
}
static bool read_file_bytes(const fs::path& p, vector<uint8_t>& out){
    std::ifstream f(p, std::ios::binary | std::ios::ate);
    if (!f) return false;
    auto n = f.tellg(); f.seekg(0);
    out.assign((size_t)n, 0);
    if (n>0) f.read((char*)out.data(), n);
    return (bool)f;
}
static bool dpapi_seal(const vector<uint8_t>& in, vector<uint8_t>& out){
    DATA_BLOB i{(DWORD)in.size(), (BYTE*)in.data()}, o{};
    if (!CryptProtectData(&i, L"hwidspoof", nullptr, nullptr, nullptr, 0, &o)) return false;
    out.assign(o.pbData, o.pbData+o.cbData);
    LocalFree(o.pbData);
    return true;
}
static bool dpapi_open(const vector<uint8_t>& in, vector<uint8_t>& out){
    DATA_BLOB i{(DWORD)in.size(), (BYTE*)in.data()}, o{};
    if (!CryptUnprotectData(&i, nullptr, nullptr, nullptr, nullptr, 0, &o)) return false;
    out.assign(o.pbData, o.pbData+o.cbData);
    LocalFree(o.pbData);
    return true;
}

// ---------- registry helpers ----------

static bool reg_open(HKEY root, const wchar_t* sub, REGSAM sam, HKEY& out){
    LONG r = RegOpenKeyExW(root, sub, 0, sam | KEY_WOW64_64KEY, &out);
    return r == ERROR_SUCCESS;
}
static bool reg_create(HKEY root, const wchar_t* sub, REGSAM sam, HKEY& out){
    LONG r = RegCreateKeyExW(root, sub, 0, nullptr, 0, sam | KEY_WOW64_64KEY, nullptr, &out, nullptr);
    return r == ERROR_SUCCESS;
}
static std::optional<string> reg_read_sz(HKEY root, const wchar_t* sub, const wchar_t* name){
    ScopedHKey k;
    if (!reg_open(root, sub, KEY_QUERY_VALUE, k.h)) return std::nullopt;
    wchar_t buf[2048]; DWORD cb = sizeof(buf); DWORD type=0;
    if (RegQueryValueExW(k, name, nullptr, &type, (LPBYTE)buf, &cb) != ERROR_SUCCESS) return std::nullopt;
    if (type != REG_SZ && type != REG_EXPAND_SZ) return std::nullopt;
    size_t n = cb/sizeof(wchar_t);
    while (n && buf[n-1]==L'\0') --n;
    return wtoa(wstring_view(buf, n));
}
static std::optional<uint32_t> reg_read_dw(HKEY root, const wchar_t* sub, const wchar_t* name){
    ScopedHKey k;
    if (!reg_open(root, sub, KEY_QUERY_VALUE, k.h)) return std::nullopt;
    DWORD v=0, cb=sizeof(v), type=0;
    if (RegQueryValueExW(k, name, nullptr, &type, (LPBYTE)&v, &cb)!=ERROR_SUCCESS) return std::nullopt;
    if (type != REG_DWORD) return std::nullopt;
    return v;
}
static std::optional<vector<uint8_t>> reg_read_bin(HKEY root, const wchar_t* sub, const wchar_t* name){
    ScopedHKey k;
    if (!reg_open(root, sub, KEY_QUERY_VALUE, k.h)) return std::nullopt;
    DWORD cb=0, type=0;
    if (RegQueryValueExW(k, name, nullptr, &type, nullptr, &cb)!=ERROR_SUCCESS) return std::nullopt;
    vector<uint8_t> out(cb);
    if (RegQueryValueExW(k, name, nullptr, &type, out.data(), &cb)!=ERROR_SUCCESS) return std::nullopt;
    out.resize(cb);
    return out;
}
static bool reg_write_sz(HKEY root, const wchar_t* sub, const wchar_t* name, string_view value){
    if (g_opt.dry){ dbg("dry: write %S\\%S = %.*s", sub, name, (int)value.size(), value.data()); return true; }
    ScopedHKey k;
    if (!reg_create(root, sub, KEY_SET_VALUE, k.h)) return false;
    wstring w = atow(value);
    DWORD cb = (DWORD)((w.size()+1)*sizeof(wchar_t));
    return RegSetValueExW(k, name, 0, REG_SZ, (const BYTE*)w.c_str(), cb) == ERROR_SUCCESS;
}
static bool reg_write_dw(HKEY root, const wchar_t* sub, const wchar_t* name, uint32_t value){
    if (g_opt.dry){ dbg("dry: write %S\\%S = 0x%08X", sub, name, value); return true; }
    ScopedHKey k;
    if (!reg_create(root, sub, KEY_SET_VALUE, k.h)) return false;
    DWORD v = value;
    return RegSetValueExW(k, name, 0, REG_DWORD, (const BYTE*)&v, sizeof(v)) == ERROR_SUCCESS;
}
static bool reg_write_bin(HKEY root, const wchar_t* sub, const wchar_t* name, const vector<uint8_t>& v){
    if (g_opt.dry){ dbg("dry: write %S\\%S (%zu bytes)", sub, name, v.size()); return true; }
    ScopedHKey k;
    if (!reg_create(root, sub, KEY_SET_VALUE, k.h)) return false;
    return RegSetValueExW(k, name, 0, REG_BINARY, v.data(), (DWORD)v.size()) == ERROR_SUCCESS;
}

// ---------- backup store ----------

struct Backup {
    Ini ini;
    fs::path path;

    bool load(const fs::path& p){
        path = p;
        vector<uint8_t> raw;
        if (!read_file_bytes(p, raw)) return false;
        vector<uint8_t> plain;
        if (dpapi_open(raw, plain)){
            ini.parse(string((const char*)plain.data(), plain.size()));
            return true;
        }
        // old plain text backup
        ini.parse(string((const char*)raw.data(), raw.size()));
        return true;
    }
    bool save() const {
        string text = ini.serialize();
        vector<uint8_t> in(text.begin(), text.end()), out;
        if (!dpapi_seal(in, out)) return false;
        return write_file_bytes(path, out);
    }
    bool has(const string& sec, const string& key) const {
        auto it = ini.data.find(sec); if (it==ini.data.end()) return false;
        return it->second.count(key) > 0;
    }
    void capture_sz(const string& sec, const string& key, HKEY root, const wchar_t* sub, const wchar_t* name){
        if (has(sec,key)) return;                   // never overwrite the true original
        if (auto v = reg_read_sz(root, sub, name)) ini.set(sec, key, *v);
    }
    void capture_dw(const string& sec, const string& key, HKEY root, const wchar_t* sub, const wchar_t* name){
        if (has(sec,key)) return;
        if (auto v = reg_read_dw(root, sub, name)){
            ini.set(sec, key, hex_str(*v, 8));
        }
    }
};

// ---------- registry surfaces ----------

struct RegTarget {
    HKEY root; const wchar_t* sub; const wchar_t* name;
    enum Type { Sz, Dw } type;
    const char* profile_key;
    const char* backup_sec;
};

static const RegTarget kRegTargets[] = {
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid",
      RegTarget::Sz, "machine_guid", "registry" },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductId",
      RegTarget::Sz, "product_id", "registry" },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"InstallDate",
      RegTarget::Dw, "install_date_hex", "registry" },
    { HKEY_LOCAL_MACHINE,
      L"SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001",
      L"HwProfileGuid",
      RegTarget::Sz, "hw_profile_guid", "registry" },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\SQMClient", L"MachineId",
      RegTarget::Sz, "sqm_machine_id", "registry" },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate", L"SusClientId",
      RegTarget::Sz, "sus_client_id", "registry" },
    { HKEY_LOCAL_MACHINE,
      L"SYSTEM\\HardwareConfig",
      L"LastHwid",
      RegTarget::Sz, "computer_hardware_id", "registry" },
    { HKEY_LOCAL_MACHINE,
      L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation",
      L"ComputerHardwareId",
      RegTarget::Sz, "computer_hardware_id", "registry" },
    { HKEY_LOCAL_MACHINE,
      L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation",
      L"SystemSKU",
      RegTarget::Sz, "system_sku", "registry" },
};

static void apply_registry(const Identity& id, Backup& bk){
    for (const auto& t : kRegTargets){
        if (t.type == RegTarget::Sz) bk.capture_sz(t.backup_sec, wtoa(t.name), t.root, t.sub, t.name);
        else                         bk.capture_dw(t.backup_sec, wtoa(t.name), t.root, t.sub, t.name);
    }
    auto pick = [&](const char* k)->string{
        if (!std::strcmp(k,"machine_guid")) return id.machine_guid;
        if (!std::strcmp(k,"product_id")) return id.product_id;
        if (!std::strcmp(k,"install_date_hex")) return id.install_date_hex;
        if (!std::strcmp(k,"hw_profile_guid")) return id.hw_profile_guid;
        if (!std::strcmp(k,"sqm_machine_id")) return id.sqm_machine_id;
        if (!std::strcmp(k,"sus_client_id")) return id.sus_client_id;
        if (!std::strcmp(k,"computer_hardware_id")) return id.computer_hardware_id;
        if (!std::strcmp(k,"system_sku")) return id.system_sku;
        return {};
    };
    for (const auto& t : kRegTargets){
        string v = pick(t.profile_key);
        if (v.empty()) continue;
        bool ok;
        if (t.type == RegTarget::Dw){
            uint32_t d = std::strtoul(v.c_str(), nullptr, 16);
            ok = reg_write_dw(t.root, t.sub, t.name, d);
        } else {
            ok = reg_write_sz(t.root, t.sub, t.name, v);
        }
        if (ok) info("reg  %S -> %s", t.name, v.c_str());
        else    warn("reg  %S failed", t.name);
    }
}

static void restore_registry(const Backup& bk){
    for (const auto& t : kRegTargets){
        auto it = bk.ini.data.find(t.backup_sec);
        if (it==bk.ini.data.end()) continue;
        auto jt = it->second.find(wtoa(t.name));
        if (jt==it->second.end()) continue;
        const string& v = jt->second;
        bool ok;
        if (t.type == RegTarget::Dw){
            uint32_t d = std::strtoul(v.c_str(), nullptr, 16);
            ok = reg_write_dw(t.root, t.sub, t.name, d);
        } else {
            ok = reg_write_sz(t.root, t.sub, t.name, v);
        }
        if (ok) info("reg  %S -> %s  [real, %s]", t.name, mask(v).c_str(), g_opt.reveal?"real":"masked");
        else    warn("reg  %S restore failed", t.name);
    }
}

// ---------- computer name ----------

static void apply_computer_name(const Identity& id, Backup& bk){
    wchar_t cur[MAX_COMPUTERNAME_LENGTH*4+1]; DWORD cb = _countof(cur);
    if (GetComputerNameExW(ComputerNamePhysicalDnsHostname, cur, &cb) && !bk.has("name","ComputerName")){
        bk.ini.set("name", "ComputerName", wtoa(cur));
    }
    bk.capture_sz("name", "ActiveComputerName", HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName",
        L"ComputerName");
    bk.capture_sz("name", "PendingComputerName", HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",
        L"ComputerName");

    wstring w = atow(id.computer_name);
    if (!g_opt.dry){
        if (!SetComputerNameExW(ComputerNamePhysicalDnsHostname, w.c_str()))
            warn("SetComputerNameExW failed (%lu)", GetLastError());
    }
    reg_write_sz(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",
        L"ComputerName", id.computer_name);
    reg_write_sz(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
        L"Hostname", id.computer_name);
    reg_write_sz(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
        L"NV Hostname", id.computer_name);
    info("name %s  (live after reboot)", id.computer_name.c_str());
}

static void restore_computer_name(const Backup& bk){
    string old = bk.ini.data.count("name") && bk.ini.data.at("name").count("ComputerName")
               ? bk.ini.data.at("name").at("ComputerName") : "";
    if (old.empty()){ warn("no original computer name backed up"); return; }
    wstring w = atow(old);
    if (!g_opt.dry) SetComputerNameExW(ComputerNamePhysicalDnsHostname, w.c_str());
    reg_write_sz(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",
        L"ComputerName", old);
    reg_write_sz(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
        L"Hostname", old);
    info("name %s  [real, %s]", mask(old).c_str(), g_opt.reveal?"real":"masked");
}

// ---------- NIC MACs ----------

struct Adapter {
    wstring reg_path;   // \SYSTEM\CurrentControlSet\Control\Class\{4d36e972-...}\0005
    wstring instance_id;
    string  name;
    string  current_mac;
};

static vector<Adapter> enumerate_adapters(){
    vector<Adapter> out;
    HDEVINFO di = SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, nullptr, nullptr, DIGCF_PRESENT);
    if (di == INVALID_HANDLE_VALUE) return out;
    SP_DEVINFO_DATA dd{sizeof(dd)};
    for (DWORD i=0; SetupDiEnumDeviceInfo(di, i, &dd); ++i){
        wchar_t instid[256]; ULONG len=_countof(instid);
        if (CM_Get_Device_IDW(dd.DevInst, instid, len, 0) != CR_SUCCESS) continue;
        wchar_t desc[256]{}; DWORD cb=sizeof(desc);
        SetupDiGetDeviceRegistryPropertyW(di,&dd,SPDRP_FRIENDLYNAME,nullptr,(PBYTE)desc,cb,&cb);
        if (desc[0]==0){ cb=sizeof(desc); SetupDiGetDeviceRegistryPropertyW(di,&dd,SPDRP_DEVICEDESC,nullptr,(PBYTE)desc,cb,&cb); }
        HKEY k = SetupDiOpenDevRegKey(di,&dd,DICS_FLAG_GLOBAL,0,DIREG_DRV,KEY_READ|KEY_WRITE);
        if (k == INVALID_HANDLE_VALUE) continue;
        wchar_t drv[256]{}; DWORD dcb=sizeof(drv), type=0;
        RegQueryValueExW(k, L"NetCfgInstanceId", nullptr, &type, (LPBYTE)drv, &dcb);
        RegCloseKey(k);
        // Build class key subkey path. SetupDi gave us a subkey handle; we need the path too.
        wchar_t clskey[32]{}; DWORD clscb=sizeof(clskey);
        SetupDiGetDeviceRegistryPropertyW(di,&dd,SPDRP_DRIVER,nullptr,(PBYTE)clskey,clscb,&clscb);
        if (clskey[0]==0) continue;
        Adapter a;
        a.instance_id = instid;
        a.name        = wtoa(desc);
        a.reg_path    = wstring(L"SYSTEM\\CurrentControlSet\\Control\\Class\\") + clskey;
        auto cur = reg_read_sz(HKEY_LOCAL_MACHINE, a.reg_path.c_str(), L"NetworkAddress");
        if (cur) a.current_mac = *cur;
        out.push_back(std::move(a));
    }
    SetupDiDestroyDeviceInfoList(di);
    return out;
}

static bool restart_adapter(const wstring& instance_id){
    DEVINST dn;
    if (CM_Locate_DevNodeW(&dn, const_cast<wchar_t*>(instance_id.c_str()), CM_LOCATE_DEVNODE_NORMAL) != CR_SUCCESS)
        return false;
    CM_Disable_DevNode(dn, 0);
    return CM_Enable_DevNode(dn, 0) == CR_SUCCESS;
}

static void apply_network(const Identity& id, Backup& bk){
    auto nics = enumerate_adapters();
    size_t idx = 0;
    for (auto& a : nics){
        if (idx >= id.macs.size()) break;
        string key = wtoa(a.instance_id);
        if (!bk.has("net", key)) bk.ini.set("net", key, a.current_mac);
        string new_mac = mac_plain(id.macs[idx++]);
        if (reg_write_sz(HKEY_LOCAL_MACHINE, a.reg_path.c_str(), L"NetworkAddress", new_mac)){
            info("nic  %s -> %s", a.name.c_str(), new_mac.c_str());
            if (!g_opt.dry) restart_adapter(a.instance_id);
        } else {
            warn("nic  %s write failed", a.name.c_str());
        }
    }
}

static void restore_network(const Backup& bk){
    auto it = bk.ini.data.find("net");
    if (it == bk.ini.data.end()){ warn("no NIC backup"); return; }
    auto nics = enumerate_adapters();
    for (auto& a : nics){
        auto jt = it->second.find(wtoa(a.instance_id));
        if (jt == it->second.end()) continue;
        const string& orig = jt->second;
        if (orig.empty()){
            if (!g_opt.dry){
                ScopedHKey k;
                if (reg_open(HKEY_LOCAL_MACHINE, a.reg_path.c_str(), KEY_SET_VALUE, k.h)){
                    RegDeleteValueW(k, L"NetworkAddress");
                }
            }
            info("nic  %s -> (cleared) [real]", a.name.c_str());
        } else {
            reg_write_sz(HKEY_LOCAL_MACHINE, a.reg_path.c_str(), L"NetworkAddress", orig);
            info("nic  %s -> %s  [real, %s]", a.name.c_str(), mask(orig).c_str(),
                 g_opt.reveal?"real":"masked");
        }
        if (!g_opt.dry) restart_adapter(a.instance_id);
    }
}

// ---------- SMBIOS (user-mode) ----------

static constexpr const wchar_t* kSmbiosKey =
    L"SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data";
static constexpr const wchar_t* kSmbiosVal = L"SMBiosData";

#pragma pack(push,1)
struct SmbHdr {       // the mssmbios registry header (8 bytes)
    uint8_t  used20[2];
    uint8_t  smbios_major;
    uint8_t  smbios_minor;
    uint16_t dmi_rev;
    uint32_t length;
};
struct SmbStructHdr {
    uint8_t  type;
    uint8_t  length;
    uint16_t handle;
};
#pragma pack(pop)

struct SmbStruct {
    uint8_t type{};
    uint8_t length{};
    uint16_t handle{};
    vector<uint8_t> formatted;
    vector<string> strings;
};

static bool parse_smbios(const vector<uint8_t>& raw, size_t header_bytes, vector<SmbStruct>& out){
    out.clear();
    if (raw.size() < header_bytes + 4) return false;
    size_t p = header_bytes;
    while (p + sizeof(SmbStructHdr) <= raw.size()){
        SmbStructHdr h;
        std::memcpy(&h, raw.data()+p, sizeof(h));
        if (h.length < sizeof(SmbStructHdr)) return false;
        if (p + h.length > raw.size()) return false;
        SmbStruct s;
        s.type = h.type; s.length = h.length; s.handle = h.handle;
        s.formatted.assign(raw.begin()+p+sizeof(SmbStructHdr), raw.begin()+p+h.length);
        p += h.length;
        // read string set
        while (p < raw.size()){
            size_t q = p;
            while (q < raw.size() && raw[q] != 0) ++q;
            if (q == raw.size()) return false;
            if (q == p){ ++p; break; }   // double NUL terminates
            s.strings.emplace_back((const char*)raw.data()+p, q-p);
            p = q + 1;
        }
        out.push_back(std::move(s));
        if (h.type == 127) break;
    }
    return true;
}

static vector<uint8_t> serialize_smbios(const vector<uint8_t>& header_bytes,
                                        const vector<SmbStruct>& all){
    vector<uint8_t> out = header_bytes;
    for (const auto& s : all){
        SmbStructHdr h{ s.type, (uint8_t)(sizeof(SmbStructHdr)+s.formatted.size()), s.handle };
        // Guard against length overflow.
        size_t full = sizeof(SmbStructHdr) + s.formatted.size();
        if (full > 0xFF) full = 0xFF;
        h.length = (uint8_t)full;
        auto base = out.size();
        out.resize(base + sizeof(h));
        std::memcpy(out.data()+base, &h, sizeof(h));
        out.insert(out.end(), s.formatted.begin(), s.formatted.end());
        if (s.strings.empty()){
            out.push_back(0); out.push_back(0);
        } else {
            for (auto& str : s.strings){
                out.insert(out.end(), str.begin(), str.end());
                out.push_back(0);
            }
            out.push_back(0);
        }
    }
    // length field update
    if (out.size() >= 8){
        uint32_t table_len = (uint32_t)(out.size() - header_bytes.size());
        std::memcpy(out.data()+4, &table_len, sizeof(uint16_t));  // dmi_rev slot? keep header shape
    }
    return out;
}

static uint8_t string_ref(SmbStruct& s, const string& value){
    if (value.empty()) return 0;
    for (size_t i=0;i<s.strings.size();++i){
        if (s.strings[i] == value) return (uint8_t)(i+1);
    }
    s.strings.push_back(value);
    return (uint8_t)s.strings.size();
}

static void set_string(SmbStruct& s, size_t offset_in_formatted, const string& value){
    if (offset_in_formatted >= s.formatted.size()) return;
    s.formatted[offset_in_formatted] = string_ref(s, value);
}

static void uuid_to_bytes(const string& guid_text, uint8_t out[16]){
    // guid_text is no-brace 8-4-4-4-12
    std::memset(out, 0, 16);
    UUID u{};
    RPC_STATUS r = UuidFromStringA((RPC_CSTR)guid_text.c_str(), &u);
    if (r != RPC_S_OK) return;
    std::memcpy(out, &u, 16);
}

static bool rewrite_smbios(const Identity& id, Backup& bk){
    auto raw = reg_read_bin(HKEY_LOCAL_MACHINE, kSmbiosKey, kSmbiosVal);
    if (!raw){ warn("smbios: SMBiosData missing"); return false; }
    if (raw->size() < 16){ warn("smbios: too short"); return false; }

    constexpr size_t kHdr = 8;
    vector<uint8_t> hdr_bytes(raw->begin(), raw->begin()+kHdr);
    vector<SmbStruct> structs;
    if (!parse_smbios(*raw, kHdr, structs)){
        warn("smbios: parse failed, not patching");
        return false;
    }

    // snapshot original once
    fs::path orig_path = g_exe_dir / "smbios_orig.bin";
    if (!fs::exists(orig_path)){
        vector<uint8_t> sealed;
        if (dpapi_seal(*raw, sealed)) write_file_bytes(orig_path, sealed);
    }

    size_t dimm_idx = 0;
    int fields = 0;
    for (auto& s : structs){
        if (s.type == 0 && s.formatted.size() >= 2){ // BIOS Information
            set_string(s, 0, id.bios_vendor);    ++fields;
            set_string(s, 1, id.bios_version);   ++fields;
            if (s.formatted.size() >= 5) set_string(s, 4, id.bios_date), ++fields;
        } else if (s.type == 1 && s.formatted.size() >= 4){ // System
            set_string(s, 0, id.sys_manufacturer); ++fields;
            set_string(s, 1, id.sys_product);      ++fields;
            set_string(s, 2, id.sys_version);      ++fields;
            set_string(s, 3, id.sys_serial);       ++fields;
            if (s.formatted.size() >= 24){
                uint8_t ub[16]; uuid_to_bytes(id.sys_uuid, ub);
                std::memcpy(s.formatted.data()+4, ub, 16);
                ++fields;
            }
            if (s.formatted.size() >= 26) set_string(s, 25-sizeof(SmbStructHdr), id.sys_sku),    ++fields;
            if (s.formatted.size() >= 27) set_string(s, 26-sizeof(SmbStructHdr), id.sys_family), ++fields;
        } else if (s.type == 2 && s.formatted.size() >= 4){ // Baseboard
            set_string(s, 0, id.board_manufacturer); ++fields;
            set_string(s, 1, id.board_product);      ++fields;
            set_string(s, 2, id.board_version);      ++fields;
            set_string(s, 3, id.board_serial);       ++fields;
        } else if (s.type == 3 && s.formatted.size() >= 4){ // Chassis
            set_string(s, 0, id.chassis_manufacturer); ++fields;
            set_string(s, 2, id.chassis_version);      ++fields;
            set_string(s, 3, id.chassis_serial);       ++fields;
        } else if (s.type == 17 && s.formatted.size() >= 18){ // Memory Device
            if (dimm_idx < id.dimm_serials.size()){
                set_string(s, 20-sizeof(SmbStructHdr), id.dimm_serials[dimm_idx]);
                ++fields;
                ++dimm_idx;
            }
        }
    }
    bk.ini.set("smbios", "snapshot", "captured");

    auto out = serialize_smbios(hdr_bytes, structs);
    // restore header byte-for-byte except the DMI-rev/length pair the kernel ignores on write
    std::memcpy(out.data(), raw->data(), kHdr);
    if (!reg_write_bin(HKEY_LOCAL_MACHINE, kSmbiosKey, kSmbiosVal, out)){
        warn("smbios: write failed");
        return false;
    }
    info("smbios profile fields %d of 21", fields);
    return true;
}

static void restore_smbios(){
    fs::path orig_path = g_exe_dir / "smbios_orig.bin";
    vector<uint8_t> sealed;
    if (!read_file_bytes(orig_path, sealed)){ warn("smbios: no snapshot"); return; }
    vector<uint8_t> plain;
    if (!dpapi_open(sealed, plain)){ warn("smbios: snapshot unreadable (another user?)"); return; }
    if (!reg_write_bin(HKEY_LOCAL_MACHINE, kSmbiosKey, kSmbiosVal, plain)){
        warn("smbios: restore write failed"); return;
    }
    if (!g_opt.dry) fs::remove(orig_path);
    info("smbios restored (%zu bytes)", plain.size());
}

// ---------- verify ----------

static void verify(const Identity& id){
    auto cmp = [&](const char* label, const string& want, const std::optional<string>& got){
        if (!got){ warn("verify %-20s MISSING", label); return; }
        bool m = (*got == want);
        info("verify %-20s %s  live=%s",
            label,
            m ? "MATCH" : "miss ",
            m ? got->c_str() : mask(*got).c_str());
    };
    cmp("MachineGuid",    id.machine_guid,
        reg_read_sz(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid"));
    cmp("ProductId",      id.product_id,
        reg_read_sz(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductId"));
    cmp("HwProfileGuid",  id.hw_profile_guid,
        reg_read_sz(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001", L"HwProfileGuid"));
    cmp("SQM MachineId",  id.sqm_machine_id,
        reg_read_sz(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\SQMClient", L"MachineId"));
    cmp("SusClientId",    id.sus_client_id,
        reg_read_sz(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate", L"SusClientId"));
    wchar_t host[256]; DWORD cb=_countof(host);
    if (GetComputerNameExW(ComputerNamePhysicalDnsHostname, host, &cb))
        cmp("ComputerName", id.computer_name, wtoa(host));
}

// ---------- status ----------

static void status(){
    auto show_sz = [](const char* label, HKEY r, const wchar_t* sub, const wchar_t* name){
        auto v = reg_read_sz(r, sub, name);
        info("%-20s %s", label, v ? mask(*v).c_str() : "(missing)");
    };
    show_sz("MachineGuid",   HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");
    show_sz("ProductId",     HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductId");
    show_sz("HwProfileGuid", HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001", L"HwProfileGuid");
    show_sz("SQM MachineId", HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\SQMClient", L"MachineId");
    show_sz("SusClientId",   HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate", L"SusClientId");

    wchar_t host[256]; DWORD cb=_countof(host);
    if (GetComputerNameExW(ComputerNamePhysicalDnsHostname, host, &cb))
        info("%-20s %s", "ComputerName", mask(wtoa(host)).c_str());

    auto sm = reg_read_bin(HKEY_LOCAL_MACHINE, kSmbiosKey, kSmbiosVal);
    info("%-20s %zu bytes", "SMBiosData", sm ? sm->size() : 0);

    for (auto& a : enumerate_adapters()){
        info("nic %-24s mac(override)=%s", a.name.c_str(),
            a.current_mac.empty() ? "(none)" : mask(a.current_mac).c_str());
    }

    fs::path prof = g_exe_dir / "profile.ini";
    fs::path back = g_exe_dir / "backup.ini";
    fs::path smob = g_exe_dir / "smbios_orig.bin";
    info("profile.ini       %s", fs::exists(prof)?"present":"missing");
    info("backup.ini        %s", fs::exists(back)?"present":"missing");
    info("smbios_orig.bin   %s", fs::exists(smob)?"present":"missing");
}

// ---------- profile I/O ----------

static void identity_to_ini(const Identity& id, Ini& o){
    o.set("id","seed", hex_str(id.seed, 16));
    o.set("id","machine_guid", id.machine_guid);
    o.set("id","product_id",   id.product_id);
    o.set("id","install_date_hex", id.install_date_hex);
    o.set("id","hw_profile_guid",  id.hw_profile_guid);
    o.set("id","sqm_machine_id",   id.sqm_machine_id);
    o.set("id","sus_client_id",    id.sus_client_id);
    o.set("id","computer_hardware_id", id.computer_hardware_id);
    o.set("id","system_sku",       id.system_sku);
    o.set("id","computer_name",    id.computer_name);
    o.set("smbios","bios_vendor",  id.bios_vendor);
    o.set("smbios","bios_version", id.bios_version);
    o.set("smbios","bios_date",    id.bios_date);
    o.set("smbios","sys_manufacturer", id.sys_manufacturer);
    o.set("smbios","sys_product",      id.sys_product);
    o.set("smbios","sys_version",      id.sys_version);
    o.set("smbios","sys_serial",       id.sys_serial);
    o.set("smbios","sys_sku",          id.sys_sku);
    o.set("smbios","sys_family",       id.sys_family);
    o.set("smbios","sys_uuid",         id.sys_uuid);
    o.set("smbios","board_manufacturer", id.board_manufacturer);
    o.set("smbios","board_product",     id.board_product);
    o.set("smbios","board_version",     id.board_version);
    o.set("smbios","board_serial",      id.board_serial);
    o.set("smbios","chassis_manufacturer", id.chassis_manufacturer);
    o.set("smbios","chassis_version",      id.chassis_version);
    o.set("smbios","chassis_serial",       id.chassis_serial);
    for (size_t i=0;i<id.dimm_serials.size();++i){
        char key[32]; _snprintf_s(key,_TRUNCATE,"dimm_%zu", i);
        o.set("smbios", key, id.dimm_serials[i]);
    }
    for (size_t i=0;i<id.macs.size();++i){
        char key[32]; _snprintf_s(key,_TRUNCATE,"mac_%zu", i);
        o.set("nics", key, mac_colon(id.macs[i]));
    }
}

static Identity identity_from_ini(const Ini& in){
    Identity id;
    id.seed = std::strtoull(in.get("id","seed","0").c_str(), nullptr, 16);
    id.machine_guid     = in.get("id","machine_guid");
    id.product_id       = in.get("id","product_id");
    id.install_date_hex = in.get("id","install_date_hex");
    id.hw_profile_guid  = in.get("id","hw_profile_guid");
    id.sqm_machine_id   = in.get("id","sqm_machine_id");
    id.sus_client_id    = in.get("id","sus_client_id");
    id.computer_hardware_id = in.get("id","computer_hardware_id");
    id.system_sku       = in.get("id","system_sku");
    id.computer_name    = in.get("id","computer_name");
    id.bios_vendor      = in.get("smbios","bios_vendor");
    id.bios_version     = in.get("smbios","bios_version");
    id.bios_date        = in.get("smbios","bios_date");
    id.sys_manufacturer = in.get("smbios","sys_manufacturer");
    id.sys_product      = in.get("smbios","sys_product");
    id.sys_version      = in.get("smbios","sys_version");
    id.sys_serial       = in.get("smbios","sys_serial");
    id.sys_sku          = in.get("smbios","sys_sku");
    id.sys_family       = in.get("smbios","sys_family");
    id.sys_uuid         = in.get("smbios","sys_uuid");
    id.board_manufacturer= in.get("smbios","board_manufacturer");
    id.board_product    = in.get("smbios","board_product");
    id.board_version    = in.get("smbios","board_version");
    id.board_serial     = in.get("smbios","board_serial");
    id.chassis_manufacturer = in.get("smbios","chassis_manufacturer");
    id.chassis_version  = in.get("smbios","chassis_version");
    id.chassis_serial   = in.get("smbios","chassis_serial");
    for (int i=0;i<8;++i){
        char k[32]; _snprintf_s(k,_TRUNCATE,"dimm_%d",i);
        auto s = in.get("smbios", k, "");
        if (s.empty()) break;
        id.dimm_serials.push_back(s);
    }
    for (int i=0;i<8;++i){
        char k[32]; _snprintf_s(k,_TRUNCATE,"mac_%d",i);
        auto s = in.get("nics", k, "");
        if (s.empty()) break;
        Mac m{};
        uint8_t* p = m.b;
        for (char c : s){
            if (c==':') continue;
            static auto hx = [](char c){ return (c>='0'&&c<='9')?c-'0':(c>='a'&&c<='f')?c-'a'+10:c-'A'+10; };
            static int half=0;
            if (half==0){ *p = (uint8_t)(hx(c)<<4); half=1; }
            else        { *p |= (uint8_t)hx(c); ++p; half=0; }
        }
        id.macs.push_back(m);
    }
    return id;
}

// ---------- help / args ----------

static void print_help(){
    std::puts(
        "hwidspoof-single — one-file user-mode HWID spoofer\n"
        "  --spoof           generate a new identity, apply every user-mode surface\n"
        "  --restore         put every real value back (DPAPI backup required)\n"
        "  --verify          read live surfaces back and compare to profile.ini\n"
        "  --status          print the current live identity\n"
        "  --dry-run         read everything, write nothing\n"
        "  --no-registry     skip the registry surfaces\n"
        "  --no-network      skip the NIC MAC rewrites\n"
        "  --no-smbios       skip the SMBIOS table rewrite\n"
        "  --reveal          print real values in clear instead of masking\n"
        "  --seed <hex>      deterministic identity from this 64-bit seed\n"
        "  --profile <path>  profile.ini location (default: beside the exe)\n"
        "  -v --verbose      trace every step\n"
        "  -h --help         this text\n"
        "\n"
        "Built by Olivia — https://discord.gg/ojailbreaks\n"
    );
}

static bool parse_args(int argc, wchar_t** argv){
    for (int i=1;i<argc;++i){
        wstring a = argv[i];
        if      (a==L"--spoof")       g_opt.do_spoof = true;
        else if (a==L"--restore")     g_opt.do_restore = true;
        else if (a==L"--verify")      g_opt.do_verify = true;
        else if (a==L"--status")      g_opt.do_status = true;
        else if (a==L"--dry-run")     g_opt.dry = true;
        else if (a==L"--no-registry") g_opt.no_registry = true;
        else if (a==L"--no-network")  g_opt.no_network = true;
        else if (a==L"--no-smbios")   g_opt.no_smbios = true;
        else if (a==L"--reveal")      g_opt.reveal = true;
        else if (a==L"-v" || a==L"--verbose") g_opt.verbose = true;
        else if (a==L"-h" || a==L"--help"   ){ print_help(); std::exit(0); }
        else if (a==L"--seed" && i+1<argc){
            g_opt.seed = std::wcstoull(argv[++i], nullptr, 16);
            g_opt.seed_set = true;
        } else if (a==L"--profile" && i+1<argc){
            g_opt.profile = argv[++i];
        } else {
            err("unknown argument: %s", wtoa(a).c_str());
            return false;
        }
    }
    if (!g_opt.do_spoof && !g_opt.do_restore && !g_opt.do_verify && !g_opt.do_status){
        print_help();
        return false;
    }
    return true;
}

// ---------- main ----------

int wmain(int argc, wchar_t** argv){
    SetConsoleOutputCP(CP_UTF8);

    wchar_t self[MAX_PATH]; GetModuleFileNameW(nullptr, self, MAX_PATH);
    g_exe_dir = fs::path(self).parent_path();

    fs::path logp = g_exe_dir / "hwidspoof.log";
    _wfopen_s(&g_log, logp.c_str(), L"ab");

    if (!parse_args(argc, argv)) return 1;

    if (!is_admin()){
        info("elevating…");
        return self_elevate(argc, argv);
    }

    fs::path profile_path = g_opt.profile.empty() ? (g_exe_dir / L"profile.ini") : fs::path(g_opt.profile);
    fs::path backup_path  = g_exe_dir / "backup.ini";

    Backup bk;
    bk.path = backup_path;
    bk.load(backup_path);  // ok if missing

    if (g_opt.do_status){
        status();
        return 0;
    }

    if (g_opt.do_spoof){
        uint64_t seed = g_opt.seed_set ? g_opt.seed : os_rand64();
        Identity id = make_identity(seed);
        Ini pini; identity_to_ini(id, pini);
        if (!g_opt.dry){
            std::ofstream f(profile_path, std::ios::binary | std::ios::trunc);
            f << pini.serialize();
        }
        info("profile seed=%016llX -> %s",
            (unsigned long long)seed, wtoa(profile_path.wstring()).c_str());

        if (!g_opt.no_registry) apply_registry(id, bk);
        if (!g_opt.no_registry) apply_computer_name(id, bk);
        if (!g_opt.no_smbios)   rewrite_smbios(id, bk);
        if (!g_opt.no_network)  apply_network(id, bk);

        if (!g_opt.dry) bk.save();
        info("done. reboot recommended for name / volume caches.");
        return 0;
    }

    if (g_opt.do_restore){
        if (!g_opt.no_network)  restore_network(bk);
        if (!g_opt.no_smbios)   restore_smbios();
        if (!g_opt.no_registry) restore_registry(bk);
        if (!g_opt.no_registry) restore_computer_name(bk);
        info("restore complete. reboot to settle caches.");
        return 0;
    }

    if (g_opt.do_verify){
        Ini pini;
        vector<uint8_t> raw;
        if (!read_file_bytes(profile_path, raw)){
            err("profile.ini missing — run --spoof first");
            return 1;
        }
        pini.parse(string((const char*)raw.data(), raw.size()));
        Identity id = identity_from_ini(pini);
        verify(id);
        return 0;
    }
    return 0;
}
