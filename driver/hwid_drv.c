/*
 * hwid_drv.sys - kernel half of the HWID spoofer.
 *
 * Three jobs, all deliberately small and bounded:
 *   1. Disk filter. Sits above the disk/partition stacks and rewrites the
 *      serial number in STORAGE_DEVICE_DESCRIPTOR, SMART IDENTIFY data and
 *      ATA PASS-THROUGH identify data as it passes back up.
 *   2. Volume filter. Sits above mounted file systems and rewrites
 *      FileFsVolumeInformation.VolumeSerialNumber.
 *   3. SMBIOS. Rewrites the firmware table in
 *      mssmbios\Data\SMBiosData (system UUID, baseboard/chassis/memory
 *      serials, BIOS strings) so every SMBIOS consumer in user mode reads
 *      the spoofed values, and puts the original bytes back on unload.
 *
 * The driver is a demand-start WDM driver loaded by SCM. It has no PnP role
 * and removes every attachment in DriverUnload.
 */

#include <ntddk.h>
#include <ntstrsafe.h>
#include <ntdddisk.h>
#include <ntddstor.h>
#include <ntddscsi.h>

#include "../shared/hwid_ioctl.h"

/*
 * Some SDK/WDK builds no longer ship the SMART IOCTL even though storahci
 * still implements it. The value is fixed by the ABI.
 */
#ifndef IOCTL_SMART_RCV_DRIVE_DATA
#define IOCTL_SMART_RCV_DRIVE_DATA \
    CTL_CODE(IOCTL_DISK_BASE, 0x001E, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#endif

#define HWID_TAG 'DwiH'
#define HWID_MAX_PARTITIONS 8
#define HWID_MAX_FILTERS (HWID_MAX_DISKS * (1 + HWID_MAX_PARTITIONS) + HWID_MAX_VOLUMES)
#define HWID_SMBIOS_MAX 0x40000UL

typedef enum _HWID_FILTER_KIND {
    HwidFilterDisk = 0,
    HwidFilterPartition = 1,
    HwidFilterVolume = 2
} HWID_FILTER_KIND;

typedef struct _HWID_FILTER {
    LIST_ENTRY ListEntry;
    PDEVICE_OBJECT Self;
    PDEVICE_OBJECT Lower;
    HWID_FILTER_KIND Kind;
    ULONG DiskNumber;
    ULONG VolumeIndex;
} HWID_FILTER, *PHWID_FILTER;

typedef enum _HWID_PATCH_TYPE {
    HwidPatchNone = 0,
    HwidPatchKindStorage,
    HwidPatchKindSmart,
    HwidPatchKindAta,
    HwidPatchKindVolume
} HWID_PATCH_TYPE;

typedef struct _HWID_PATCH_CONTEXT {
    HWID_PATCH_TYPE Type;
    ULONG VolumeSerial;
    CHAR Serial[HWID_MAX_SERIAL_LEN];
} HWID_PATCH_CONTEXT, *PHWID_PATCH_CONTEXT;

/* ------------------------------------------------------------------ */
/* Globals                                                             */
/* ------------------------------------------------------------------ */

static PDRIVER_OBJECT g_DriverObject;
static PDEVICE_OBJECT g_ControlDevice;
static LIST_ENTRY g_Filters;
static KSPIN_LOCK g_FilterLock;

static HWID_CONFIG g_Config;
static KSPIN_LOCK g_ConfigLock;
static ULONG g_ConfigGeneration;

static ERESOURCE g_SmbiosLock;
static BOOLEAN g_SmbiosLockReady;
static PUCHAR g_OriginalSmbios;
static ULONG g_OriginalSmbiosLength;
static PUCHAR g_PatchedSmbios;
static ULONG g_PatchedSmbiosLength;
static ULONG g_SmbiosFieldsPatched;
static BOOLEAN g_SmbiosApplied;

static UNICODE_STRING g_ServiceKeyPath;
static BOOLEAN g_Persisted;

static NTSTATUS HwidWriteSmbiosValue(_In_reads_bytes_(Length) PVOID Data, ULONG Length);
static VOID HwidDropPatchedSmbios(_In_ BOOLEAN RestoreOriginal);
static NTSTATUS HwidSavePersistedConfig(VOID);
static VOID HwidDeletePersistedConfig(VOID);
static NTSTATUS HwidWriteHardwareBios(_In_ const HWID_CONFIG *Config);
/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

static BOOLEAN HwidStringEmpty(_In_ const CHAR *Value)
{
    return (Value == NULL) || (Value[0] == '\0');
}

static VOID HwidCopyAnsi(_Out_writes_z_(DestLen) CHAR *Dest, SIZE_T DestLen, _In_z_ const CHAR *Source)
{
    if (DestLen == 0) {
        return;
    }
    (VOID)RtlStringCchCopyA(Dest, DestLen, Source);
    Dest[DestLen - 1] = '\0';
}

static INT HwidHexNibble(CHAR Ch)
{
    if (Ch >= '0' && Ch <= '9') {
        return Ch - '0';
    }
    if (Ch >= 'a' && Ch <= 'f') {
        return Ch - 'a' + 10;
    }
    if (Ch >= 'A' && Ch <= 'F') {
        return Ch - 'A' + 10;
    }
    return -1;
}

static BOOLEAN HwidParseVolumeSerial(_In_z_ const CHAR *Text, _Out_ PULONG Serial)
{
    ULONG Value = 0;
    SIZE_T Index;

    if (Text == NULL || Serial == NULL) {
        return FALSE;
    }
    for (Index = 0; Index < 8; Index++) {
        INT Nibble = HwidHexNibble(Text[Index]);
        if (Nibble < 0) {
            return FALSE;
        }
        Value = (Value << 4) | (ULONG)Nibble;
    }
    if (Text[8] != '\0') {
        return FALSE;
    }
    *Serial = Value;
    return TRUE;
}

/* Parse "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" into 16 SMBIOS-order bytes. */
static BOOLEAN HwidParseUuid(_In_z_ const CHAR *Text, _Out_writes_(16) UCHAR *Uuid)
{
    SIZE_T Out = 0;
    SIZE_T Index = 0;

    if (Text == NULL || Uuid == NULL) {
        return FALSE;
    }
    while (Text[Index] != '\0') {
        INT High;
        INT Low;

        if (Text[Index] == '-') {
            Index++;
            continue;
        }
        High = HwidHexNibble(Text[Index]);
        Low = (Text[Index + 1] != '\0') ? HwidHexNibble(Text[Index + 1]) : -1;
        if (High < 0 || Low < 0 || Out >= 16) {
            return FALSE;
        }
        Uuid[Out++] = (UCHAR)((High << 4) | Low);
        Index += 2;
    }
    if (Out != 16) {
        return FALSE;
    }

    /*
     * The text form is big-endian inside each of the first three groups;
     * SMBIOS stores those groups little-endian. Without this swap WMI
     * reports a byte-reversed UUID.
     */
    {
        UCHAR Swap;

        Swap = Uuid[0];
        Uuid[0] = Uuid[3];
        Uuid[3] = Swap;
        Swap = Uuid[1];
        Uuid[1] = Uuid[2];
        Uuid[2] = Swap;
        Swap = Uuid[4];
        Uuid[4] = Uuid[5];
        Uuid[5] = Swap;
        Swap = Uuid[6];
        Uuid[6] = Uuid[7];
        Uuid[7] = Swap;
    }
    return TRUE;
}

static VOID HwidSanitizeAnsi(_Inout_updates_(Len) CHAR *Text, SIZE_T Len)
{
    SIZE_T Index;
    for (Index = 0; Index < Len; Index++) {
        if (Text[Index] == '\0') {
            break;
        }
        if ((UCHAR)Text[Index] < 0x20 || (UCHAR)Text[Index] == 0x7F) {
            Text[Index] = ' ';
        }
    }
    Text[Len - 1] = '\0';
}

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

static VOID HwidZeroConfig(VOID)
{
    RtlZeroMemory(&g_Config, sizeof(g_Config));
    g_Config.Size = sizeof(HWID_CONFIG);
    g_Config.Version = HWID_CONFIG_VERSION;
}

static VOID HwidLockedCopyDiskSerial(ULONG Disk, _Out_writes_z_(HWID_MAX_SERIAL_LEN) CHAR *Dest)
{
    KIRQL OldIrql;

    Dest[0] = '\0';
    if (Disk >= HWID_MAX_DISKS) {
        return;
    }
    KeAcquireSpinLock(&g_ConfigLock, &OldIrql);
    HwidCopyAnsi(Dest, HWID_MAX_SERIAL_LEN, g_Config.DiskSerial[Disk]);
    KeReleaseSpinLock(&g_ConfigLock, OldIrql);
}

static BOOLEAN HwidLockedVolumeSerial(ULONG VolumeIndex, _Out_ PULONG Serial)
{
    KIRQL OldIrql;
    BOOLEAN Found = FALSE;

    if (VolumeIndex < HWID_MAX_VOLUMES) {
        KeAcquireSpinLock(&g_ConfigLock, &OldIrql);
        if (!HwidStringEmpty(g_Config.VolumeSerial[VolumeIndex])) {
            Found = HwidParseVolumeSerial(g_Config.VolumeSerial[VolumeIndex], Serial);
        }
        KeReleaseSpinLock(&g_ConfigLock, OldIrql);
    }
    return Found;
}

/* ------------------------------------------------------------------ */
/* SMBIOS image                                                        */
/* ------------------------------------------------------------------ */

static NTSTATUS HwidReadRegistryValue(
    _In_z_ PCWSTR KeyPath,
    _In_z_ PCWSTR ValueName,
    _Outptr_ PVOID *Data,
    _Out_ PULONG DataLength,
    _Out_ PULONG ValueType)
{
    UNICODE_STRING KeyName;
    UNICODE_STRING ValueString;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE KeyHandle = NULL;
    NTSTATUS Status;
    PKEY_VALUE_PARTIAL_INFORMATION Info = NULL;
    ULONG InfoSize = FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + HWID_SMBIOS_MAX;
    ULONG ResultLength = 0;
    PVOID Buffer = NULL;
    ULONG BufferLength;

    *Data = NULL;
    *DataLength = 0;
    *ValueType = 0;

    RtlInitUnicodeString(&KeyName, KeyPath);
    InitializeObjectAttributes(&Attributes, &KeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = ZwOpenKey(&KeyHandle, KEY_READ, &Attributes);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Info = ExAllocatePool2(POOL_FLAG_PAGED, InfoSize, HWID_TAG);
    if (Info == NULL) {
        ZwClose(KeyHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlInitUnicodeString(&ValueString, ValueName);
    Status = ZwQueryValueKey(KeyHandle, &ValueString, KeyValuePartialInformation,
                             Info, InfoSize, &ResultLength);
    if (!NT_SUCCESS(Status) || Info->DataLength == 0 || Info->DataLength > HWID_SMBIOS_MAX) {
        ExFreePoolWithTag(Info, HWID_TAG);
        ZwClose(KeyHandle);
        return NT_SUCCESS(Status) ? STATUS_NOT_FOUND : Status;
    }

    BufferLength = Info->DataLength;
    Buffer = ExAllocatePool2(POOL_FLAG_PAGED, BufferLength, HWID_TAG);
    if (Buffer == NULL) {
        ExFreePoolWithTag(Info, HWID_TAG);
        ZwClose(KeyHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(Buffer, Info->Data, BufferLength);
    *ValueType = Info->Type;
    *Data = Buffer;
    *DataLength = BufferLength;

    ExFreePoolWithTag(Info, HWID_TAG);
    ZwClose(KeyHandle);
    return STATUS_SUCCESS;
}

/*
 * Replace string index N in a SMBIOS structure's string-set. The string is
 * rewritten in place, space-padded to its original length, so every offset
 * and every other string reference stays valid no matter how long the
 * replacement is. Longer replacements are truncated rather than shifting
 * the table.
 */
static VOID HwidReplaceSmbiosString(
    _Inout_updates_(TableLength) UCHAR *Table,
    ULONG TableLength,
    ULONG StringSetOffset,
    UCHAR Index,
    _In_z_ const CHAR *Replacement,
    _Inout_ PULONG FieldsPatched)
{
    ULONG Offset = StringSetOffset;
    ULONG Current = 1;
    SIZE_T ReplacementLength = 0;

    if (Index == 0 || Replacement == NULL || HwidStringEmpty(Replacement)) {
        return;
    }
    while (Replacement[ReplacementLength] != '\0') {
        ReplacementLength++;
    }

    while (Offset < TableLength && Table[Offset] != '\0') {
        ULONG Length = 0;
        while ((Offset + Length) < TableLength && Table[Offset + Length] != '\0') {
            Length++;
        }
        if (Length == 0 || (Offset + Length) >= TableLength) {
            return;
        }
        if (Current == Index) {
            SIZE_T Copy = ReplacementLength;
            if (Copy > Length) {
                Copy = Length;
            }
            RtlCopyMemory(Table + Offset, Replacement, Copy);
            for (SIZE_T Pad = Copy; Pad < Length; Pad++) {
                Table[Offset + Pad] = ' ';
            }
            (*FieldsPatched)++;
            return;
        }
        Offset += Length + 1;
        Current++;
    }
}

/*
 * Locate the first plausible SMBIOS structure. mssmbios stores the raw table,
 * sometimes behind an 8-byte header. Walking four structures and requiring
 * every string set to terminate rejects the header itself: the header bytes
 * look like a type-0 structure with a huge length, which is exactly what the
 * old single-byte check latched onto.
 */
static ULONG HwidFindSmbiosStart(_In_reads_(Length) const UCHAR *Data, ULONG Length)
{
    ULONG Limit = (Length < 128) ? Length : 128;
    ULONG Offset;

    if (Length < 8) {
        return Length;
    }
    for (Offset = 0; Offset + 4 <= Limit; Offset++) {
        ULONG Cursor = Offset;
        ULONG Step;
        BOOLEAN Valid = TRUE;

        if (Data[Offset] != 0) {
            continue;
        }
        if (Data[Offset + 1] < 0x12 || Data[Offset + 1] > 0x40) {
            continue;
        }
        for (Step = 0; Step < 4; Step++) {
            ULONG StructLength;
            ULONG Next;

            if (Cursor + 4 > Length) {
                Valid = FALSE;
                break;
            }
            StructLength = Data[Cursor + 1];
            if (StructLength < 4 || Cursor + StructLength > Length) {
                Valid = FALSE;
                break;
            }
            Next = Cursor + StructLength;
            while (Next + 1 < Length && !(Data[Next] == 0 && Data[Next + 1] == 0)) {
                Next++;
            }
            if (Next + 1 >= Length) {
                Valid = FALSE;
                break;
            }
            Cursor = Next + 2;
        }
        if (Valid) {
            return Offset;
        }
    }
    return Length;
}

static NTSTATUS HwidBuildSmbiosImage(_In_ const HWID_CONFIG *Config)
{
    PUCHAR Image = NULL;
    ULONG ImageLength;
    ULONG Start;
    ULONG Offset;
    ULONG Fields = 0;
    ULONG MemoryIndex = 0;

    if (g_OriginalSmbios == NULL || g_OriginalSmbiosLength < 16) {
        return STATUS_NOT_FOUND;
    }

    ImageLength = g_OriginalSmbiosLength;
    Image = ExAllocatePool2(POOL_FLAG_PAGED, ImageLength, HWID_TAG);
    if (Image == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(Image, g_OriginalSmbios, ImageLength);

    Start = HwidFindSmbiosStart(Image, ImageLength);
    if (Start >= ImageLength) {
        ExFreePoolWithTag(Image, HWID_TAG);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    Offset = Start;
    while (Offset + 4 <= ImageLength) {
        UCHAR Type = Image[Offset];
        UCHAR StructLength = Image[Offset + 1];
        ULONG StringSetOffset;
        ULONG Scan;

        if (StructLength < 4 || (Offset + StructLength) > ImageLength) {
            break;
        }
        StringSetOffset = Offset + StructLength;

        Scan = StringSetOffset;
        while (Scan + 1 < ImageLength && !(Image[Scan] == 0 && Image[Scan + 1] == 0)) {
            Scan++;
        }
        if (Scan + 1 >= ImageLength) {
            break;
        }

        if (Type == 0 && StructLength > 0x08) {
            /* BIOS vendor / version / release date. */
            if (Config->BiosVendor[0]) {
                HwidReplaceSmbiosString(Image, ImageLength, StringSetOffset,
                                        Image[Offset + 0x04], Config->BiosVendor, &Fields);
            }
            if (Config->BiosVersion[0]) {
                HwidReplaceSmbiosString(Image, ImageLength, StringSetOffset,
                                        Image[Offset + 0x05], Config->BiosVersion, &Fields);
            }
            if (Config->BiosReleaseDate[0]) {
                HwidReplaceSmbiosString(Image, ImageLength, StringSetOffset,
                                        Image[Offset + 0x08], Config->BiosReleaseDate, &Fields);
            }
        } else if (Type == 1 && StructLength > 0x08) {
            if (Config->SystemManufacturer[0]) {
                HwidReplaceSmbiosString(Image, ImageLength, StringSetOffset,
                                        Image[Offset + 0x04], Config->SystemManufacturer, &Fields);
            }
            if (Config->SystemProductName[0]) {
                HwidReplaceSmbiosString(Image, ImageLength, StringSetOffset,
                                        Image[Offset + 0x05], Config->SystemProductName, &Fields);
            }
            if (Config->SystemVersion[0]) {
                HwidReplaceSmbiosString(Image, ImageLength, StringSetOffset,
                                        Image[Offset + 0x06], Config->SystemVersion, &Fields);
            }
            if (Config->SystemSerial[0]) {
                HwidReplaceSmbiosString(Image, ImageLength, StringSetOffset,
                                        Image[Offset + 0x07], Config->SystemSerial, &Fields);
            }
            if (Config->SystemUuid[0] && StructLength >= 0x18) {
                UCHAR Uuid[16];
                if (HwidParseUuid(Config->SystemUuid, Uuid)) {
                    RtlCopyMemory(Image + Offset + 0x08, Uuid, sizeof(Uuid));
                    Fields++;
                }
            }
            if (Config->SystemSku[0] && StructLength > 0x19) {
                HwidReplaceSmbiosString(Image, ImageLength, StringSetOffset,
                                        Image[Offset + 0x19], Config->SystemSku, &Fields);
            }
            if (Config->SystemFamily[0] && StructLength > 0x1A) {
                HwidReplaceSmbiosString(Image, ImageLength, StringSetOffset,
                                        Image[Offset + 0x1A], Config->SystemFamily, &Fields);
            }
        } else if (Type == 2 && StructLength > 0x08) {
            if (Config->BaseboardManufacturer[0]) {
                HwidReplaceSmbiosString(Image, ImageLength, StringSetOffset,
                                        Image[Offset + 0x04], Config->BaseboardManufacturer, &Fields);
            }
            if (Config->BaseboardProduct[0]) {
                HwidReplaceSmbiosString(Image, ImageLength, StringSetOffset,
                                        Image[Offset + 0x05], Config->BaseboardProduct, &Fields);
            }
            if (Config->BaseboardVersion[0]) {
                HwidReplaceSmbiosString(Image, ImageLength, StringSetOffset,
                                        Image[Offset + 0x06], Config->BaseboardVersion, &Fields);
            }
            if (Config->BaseboardSerial[0]) {
                HwidReplaceSmbiosString(Image, ImageLength, StringSetOffset,
                                        Image[Offset + 0x07], Config->BaseboardSerial, &Fields);
            }
        } else if (Type == 3 && StructLength > 0x08) {
            if (Config->ChassisManufacturer[0]) {
                HwidReplaceSmbiosString(Image, ImageLength, StringSetOffset,
                                        Image[Offset + 0x04], Config->ChassisManufacturer, &Fields);
            }
            if (Config->ChassisSerial[0]) {
                HwidReplaceSmbiosString(Image, ImageLength, StringSetOffset,
                                        Image[Offset + 0x07], Config->ChassisSerial, &Fields);
            }
            if (Config->ChassisVersion[0]) {
                HwidReplaceSmbiosString(Image, ImageLength, StringSetOffset,
                                        Image[Offset + 0x06], Config->ChassisVersion, &Fields);
            }
        } else if (Type == 17 && StructLength > 0x18) {
            if (MemoryIndex < HWID_MAX_MEMORY && Config->MemorySerial[MemoryIndex][0]) {
                HwidReplaceSmbiosString(Image, ImageLength, StringSetOffset,
                                        Image[Offset + 0x18], Config->MemorySerial[MemoryIndex], &Fields);
                MemoryIndex++;
            }
        } else if (Type == 127) {
            break;
        }

        Offset = Scan + 2;
    }

    /* Publish to the registry first: the value is what consumers read. */
    {
        NTSTATUS WriteStatus = HwidWriteSmbiosValue(Image, ImageLength);
        if (!NT_SUCCESS(WriteStatus)) {
            ExFreePoolWithTag(Image, HWID_TAG);
            return WriteStatus;
        }
    }

    /* Then swap the cached copy used for status reporting. */
    {
        PUCHAR Old;

        ExAcquireResourceExclusiveLite(&g_SmbiosLock, TRUE);
        Old = g_PatchedSmbios;
        g_PatchedSmbios = Image;
        g_PatchedSmbiosLength = ImageLength;
        g_SmbiosFieldsPatched = Fields;
        g_SmbiosApplied = TRUE;
        ExReleaseResourceLite(&g_SmbiosLock);

        if (Old != NULL) {
            ExFreePoolWithTag(Old, HWID_TAG);
        }
    }
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* SMBIOS registry value                                               */
/* ------------------------------------------------------------------ */

/*
 * mssmbios caches the raw firmware table at boot and every SMBIOS consumer
 * in user mode (the WMI MSSmBios provider, Win32_BaseBoard, Win32_BIOS,
 * Win32_PhysicalMemory) reads it back from this one value. Rewriting it is
 * the only way to change what those classes report; a query filter cannot,
 * because the configuration manager fills the caller's buffer after the
 * pre-notification returns.
 *
 * The original bytes are captured in DriverEntry and put back on clear or
 * unload, so the value is never left altered.
 */
static const WCHAR HwidSmbiosKeyPath[] =
    L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\mssmbios\\Data";

static NTSTATUS HwidWriteSmbiosValue(_In_reads_bytes_(Length) PVOID Data, ULONG Length)
{
    UNICODE_STRING KeyName;
    UNICODE_STRING ValueName;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Key = NULL;
    NTSTATUS Status;

    if (Data == NULL || Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&KeyName, HwidSmbiosKeyPath);
    InitializeObjectAttributes(&Attributes, &KeyName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = ZwOpenKey(&Key, KEY_SET_VALUE, &Attributes);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    RtlInitUnicodeString(&ValueName, L"SMBiosData");
    Status = ZwSetValueKey(&Key, &ValueName, 0, REG_BINARY, Data, Length);
    ZwClose(Key);
    return Status;
}

/* ------------------------------------------------------------------ */
/* Persistence                                                         */
/* ------------------------------------------------------------------ */

/* Opens <service>\Parameters. The service key always exists by the time a
 * driver is loaded, so ZwCreateKey only ever creates the subkey. */
static NTSTATUS HwidOpenParameters(_Out_ PHANDLE Key, _In_ ACCESS_MASK Access,
                                   _In_ BOOLEAN Create)
{
    WCHAR Buffer[512];
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    ULONG Chars;
    NTSTATUS Status;

    if (!g_ServiceKeyPath.Buffer || g_ServiceKeyPath.Length == 0) {
        return STATUS_UNSUCCESSFUL;
    }
    Chars = g_ServiceKeyPath.Length / sizeof(WCHAR);
    if ((Chars + 11) >= RTL_NUMBER_OF(Buffer)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlCopyMemory(Buffer, g_ServiceKeyPath.Buffer, g_ServiceKeyPath.Length);
    (VOID)RtlStringCchCopyW(Buffer + Chars, RTL_NUMBER_OF(Buffer) - Chars, L"\\Parameters");

    RtlInitUnicodeString(&Name, Buffer);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    if (Create) {
        Status = ZwCreateKey(Key, Access, &Attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    } else {
        Status = ZwOpenKey(Key, Access, &Attributes);
    }
    return Status;
}

static VOID HwidCopyConfigOut(_Out_ PHWID_CONFIG Dest)
{
    KIRQL OldIrql;

    KeAcquireSpinLock(&g_ConfigLock, &OldIrql);
    RtlCopyMemory(Dest, &g_Config, sizeof(*Dest));
    KeReleaseSpinLock(&g_ConfigLock, OldIrql);
}

static NTSTATUS HwidSavePersistedConfig(VOID)
{
    PHWID_CONFIG Snapshot;
    HANDLE Key = NULL;
    UNICODE_STRING ValueName;
    NTSTATUS Status;

    Snapshot = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*Snapshot), HWID_TAG);
    if (Snapshot == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    HwidCopyConfigOut(Snapshot);

    Status = HwidOpenParameters(&Key, KEY_SET_VALUE, TRUE);
    if (NT_SUCCESS(Status)) {
        RtlInitUnicodeString(&ValueName, L"Config");
        Status = ZwSetValueKey(Key, &ValueName, 0, REG_BINARY, Snapshot, sizeof(*Snapshot));
        ZwClose(Key);
        g_Persisted = NT_SUCCESS(Status);
    }

    ExFreePoolWithTag(Snapshot, HWID_TAG);
    return Status;
}

static NTSTATUS HwidLoadPersistedConfig(VOID)
{
    HANDLE Key = NULL;
    UNICODE_STRING ValueName;
    PKEY_VALUE_PARTIAL_INFORMATION Info;
    ULONG InfoSize = FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + sizeof(HWID_CONFIG);
    ULONG ResultLength = 0;
    KIRQL OldIrql;
    NTSTATUS Status;

    Status = HwidOpenParameters(&Key, KEY_READ, FALSE);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Info = ExAllocatePool2(POOL_FLAG_PAGED, InfoSize, HWID_TAG);
    if (Info == NULL) {
        ZwClose(Key);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlInitUnicodeString(&ValueName, L"Config");
    Status = ZwQueryValueKey(Key, &ValueName, KeyValuePartialInformation, Info, InfoSize,
                             &ResultLength);
    if (NT_SUCCESS(Status) && Info->Type == REG_BINARY &&
        Info->DataLength == sizeof(HWID_CONFIG)) {
        const HWID_CONFIG *Loaded = (const HWID_CONFIG *)Info->Data;
        if (Loaded->Size == sizeof(HWID_CONFIG) && Loaded->Version == HWID_CONFIG_VERSION) {
            KeAcquireSpinLock(&g_ConfigLock, &OldIrql);
            RtlCopyMemory(&g_Config, Loaded, sizeof(HWID_CONFIG));
            g_ConfigGeneration++;
            KeReleaseSpinLock(&g_ConfigLock, OldIrql);
            g_Persisted = TRUE;
        } else {
            Status = STATUS_REVISION_MISMATCH;
        }
    } else {
        Status = STATUS_NOT_FOUND;
    }

    ExFreePoolWithTag(Info, HWID_TAG);
    ZwClose(Key);
    return Status;
}

static VOID HwidDeletePersistedConfig(VOID)
{
    HANDLE Key = NULL;
    UNICODE_STRING ValueName;

    if (NT_SUCCESS(HwidOpenParameters(&Key, KEY_SET_VALUE, FALSE))) {
        RtlInitUnicodeString(&ValueName, L"Config");
        (VOID)ZwDeleteValueKey(Key, &ValueName);
        ZwClose(Key);
    }
    g_Persisted = FALSE;
}

/* ------------------------------------------------------------------ */
/* HARDWARE\DESCRIPTION\System\BIOS                                    */
/* ------------------------------------------------------------------ */

/*
 * The kernel rebuilds this key from SMBIOS at every boot, and a long list of
 * checks read it instead of calling GetSystemFirmwareTable. Writing the same
 * identity here keeps registry readers and IOCTL readers consistent.
 */
static NTSTATUS HwidSetBiosString(_In_ HANDLE Key, _In_z_ PCWSTR Name,
                                  _In_z_ const CHAR *Ansi)
{
    WCHAR Buffer[HWID_MAX_TEXT_LEN];
    UNICODE_STRING ValueName;
    ULONG Index = 0;
    ULONG Bytes;

    if (Ansi == NULL || Ansi[0] == '\0') {
        return STATUS_SUCCESS;
    }
    while (Ansi[Index] != '\0' && Index < (HWID_MAX_TEXT_LEN - 1)) {
        Buffer[Index] = (WCHAR)(UCHAR)Ansi[Index];
        Index++;
    }
    Buffer[Index] = L'\0';
    Bytes = (Index + 1) * sizeof(WCHAR);

    RtlInitUnicodeString(&ValueName, Name);
    return ZwSetValueKey(Key, &ValueName, 0, REG_SZ, Buffer, Bytes);
}

static NTSTATUS HwidWriteHardwareBios(_In_ const HWID_CONFIG *Config)
{
    UNICODE_STRING KeyName;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Key = NULL;
    NTSTATUS Status;

    RtlInitUnicodeString(&KeyName, L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS");
    InitializeObjectAttributes(&Attributes, &KeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    Status = ZwOpenKey(&Key, KEY_SET_VALUE, &Attributes);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    (VOID)HwidSetBiosString(Key, L"SystemManufacturer", Config->SystemManufacturer);
    (VOID)HwidSetBiosString(Key, L"SystemProductName", Config->SystemProductName);
    (VOID)HwidSetBiosString(Key, L"SystemVersion", Config->SystemVersion);
    (VOID)HwidSetBiosString(Key, L"SystemFamily", Config->SystemFamily);
    (VOID)HwidSetBiosString(Key, L"SystemSKU", Config->SystemSku);
    (VOID)HwidSetBiosString(Key, L"BaseBoardManufacturer", Config->BaseboardManufacturer);
    (VOID)HwidSetBiosString(Key, L"BaseBoardProduct", Config->BaseboardProduct);
    (VOID)HwidSetBiosString(Key, L"BaseBoardVersion", Config->BaseboardVersion);
    (VOID)HwidSetBiosString(Key, L"BIOSVendor", Config->BiosVendor);
    (VOID)HwidSetBiosString(Key, L"BIOSVersion", Config->BiosVersion);
    (VOID)HwidSetBiosString(Key, L"BIOSReleaseDate", Config->BiosReleaseDate);

    /* SystemBiosVersion is REG_MULTI_SZ: version + double NUL. */
    if (!HwidStringEmpty(Config->BiosVersion)) {
        WCHAR Multi[HWID_MAX_TEXT_LEN + 2];
        UNICODE_STRING ValueName;
        ULONG Chars = 0;

        while (Config->BiosVersion[Chars] != '\0' && Chars < (HWID_MAX_TEXT_LEN - 1)) {
            Multi[Chars] = (WCHAR)(UCHAR)Config->BiosVersion[Chars];
            Chars++;
        }
        Multi[Chars] = L'\0';
        Multi[Chars + 1] = L'\0';
        RtlInitUnicodeString(&ValueName, L"SystemBiosVersion");
        (VOID)ZwSetValueKey(Key, &ValueName, 0, REG_MULTI_SZ, Multi,
                            (Chars + 2) * sizeof(WCHAR));
    }

    ZwClose(Key);
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Filter forwarding                                                   */
/* ------------------------------------------------------------------ */

static NTSTATUS HwidPassThrough(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    PHWID_FILTER Filter = (PHWID_FILTER)DeviceObject->DeviceExtension;

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(Filter->Lower, Irp);
}

static VOID HwidWriteAtaString(_Out_writes_(DestLength) UCHAR *Dest, ULONG DestLength, _In_z_ const CHAR *Source)
{
    SIZE_T Length = 0;

    for (ULONG Index = 0; Index < DestLength; Index++) {
        Dest[Index] = ' ';
    }
    while (Source[Length] != '\0') {
        Length++;
    }
    if (Length > DestLength) {
        Length = DestLength;
    }
    /* ATA IDENTIFY stores each 16-bit word big-endian. */
    for (SIZE_T Index = 0; Index + 1 < Length; Index += 2) {
        Dest[Index] = (UCHAR)Source[Index + 1];
        Dest[Index + 1] = (UCHAR)Source[Index];
    }
}

static VOID HwidPatchStorageDescriptor(_In_ PIRP Irp, _In_ PHWID_PATCH_CONTEXT Context)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG OutputLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    PSTORAGE_DEVICE_DESCRIPTOR Descriptor;
    ULONG Offset;
    ULONG Space;

    if (Irp->AssociatedIrp.SystemBuffer == NULL || OutputLength < sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
        return;
    }
    Descriptor = (PSTORAGE_DEVICE_DESCRIPTOR)Irp->AssociatedIrp.SystemBuffer;
    if ((size_t)Descriptor->Size <
        FIELD_OFFSET(STORAGE_DEVICE_DESCRIPTOR, RawDeviceProperties)) {
        return;
    }
    Offset = Descriptor->SerialNumberOffset;
    if (Offset == 0 || Offset >= OutputLength) {
        return;
    }
    Space = OutputLength - Offset;
    if (Space < 2) {
        return;
    }
    if (HwidStringEmpty(Context->Serial)) {
        return;
    }
    (VOID)RtlStringCchCopyNA((PCHAR)Descriptor + Offset, Space, Context->Serial, Space - 1);
}

static VOID HwidPatchSmartIdentify(_In_ PIRP Irp, _In_ PHWID_PATCH_CONTEXT Context)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG OutputLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG Minimum = FIELD_OFFSET(SENDCMDOUTPARAMS, bBuffer) + 512;
    PSENDCMDOUTPARAMS Output;

    if (Irp->AssociatedIrp.SystemBuffer == NULL || OutputLength < Minimum) {
        return;
    }
    Output = (PSENDCMDOUTPARAMS)Irp->AssociatedIrp.SystemBuffer;
    if (Output->DriverStatus.bDriverError != 0) {
        return;
    }
    HwidWriteAtaString(Output->bBuffer + 20, 20, Context->Serial);
}

static VOID HwidPatchAtaIdentify(_In_ PIRP Irp, _In_ PHWID_PATCH_CONTEXT Context)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG OutputLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    PATA_PASS_THROUGH_EX Ata;
    ULONG Offset;

    if (Irp->AssociatedIrp.SystemBuffer == NULL || OutputLength < sizeof(ATA_PASS_THROUGH_EX)) {
        return;
    }
    Ata = (PATA_PASS_THROUGH_EX)Irp->AssociatedIrp.SystemBuffer;
    if (Ata->DataTransferLength < 512) {
        return;
    }
    Offset = (ULONG)Ata->DataBufferOffset;
    if (Offset < sizeof(ATA_PASS_THROUGH_EX) || Offset > OutputLength ||
        (OutputLength - Offset) < 512) {
        return;
    }
    /* The dispatch path has already verified this is an IDENTIFY command. */
    HwidWriteAtaString((PUCHAR)Irp->AssociatedIrp.SystemBuffer + Offset + 20, 20, Context->Serial);
}

static VOID HwidPatchVolumeInformation(_In_ PIRP Irp, _In_ PHWID_PATCH_CONTEXT Context)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PFILE_FS_VOLUME_INFORMATION Info;

    if (Irp->AssociatedIrp.SystemBuffer == NULL) {
        return;
    }
    if (!NT_SUCCESS(Irp->IoStatus.Status) && Irp->IoStatus.Status != STATUS_BUFFER_OVERFLOW) {
        return;
    }
    if (Stack->Parameters.QueryVolume.FsInformationClass != FileFsVolumeInformation) {
        return;
    }
    if (Stack->Parameters.QueryVolume.Length < sizeof(FILE_FS_VOLUME_INFORMATION)) {
        return;
    }
    Info = (PFILE_FS_VOLUME_INFORMATION)Irp->AssociatedIrp.SystemBuffer;
    Info->VolumeSerialNumber = Context->VolumeSerial;
}

static NTSTATUS HwidPatchCompletion(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp, _In_ PVOID Context)
{
    PHWID_PATCH_CONTEXT Patch = (PHWID_PATCH_CONTEXT)Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (Patch->Type) {
    case HwidPatchKindStorage:
        HwidPatchStorageDescriptor(Irp, Patch);
        break;
    case HwidPatchKindSmart:
        HwidPatchSmartIdentify(Irp, Patch);
        break;
    case HwidPatchKindAta:
        HwidPatchAtaIdentify(Irp, Patch);
        break;
    case HwidPatchKindVolume:
        HwidPatchVolumeInformation(Irp, Patch);
        break;
    default:
        break;
    }

    ExFreePoolWithTag(Patch, HWID_TAG);

    if (Irp->PendingReturned) {
        IoMarkIrpPending(Irp);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS HwidForwardWithPatch(_In_ PHWID_FILTER Filter, _In_ PIRP Irp, _In_ PHWID_PATCH_CONTEXT Context)
{
    NTSTATUS Status;

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, HwidPatchCompletion, Context, TRUE, TRUE, TRUE);
    Status = IoCallDriver(Filter->Lower, Irp);
    /*
     * The completion routine owns Context once the IRP is on the lower
     * stack, including when IoCallDriver returns a failure status, so it
     * must not be freed here.
     */
    return Status;
}

/* ------------------------------------------------------------------ */
/* Spoof entry points                                                  */
/* ------------------------------------------------------------------ */

static NTSTATUS HwidSpoofStorageQuery(_In_ PHWID_FILTER Filter, _In_ PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PSTORAGE_PROPERTY_QUERY Query;
    PHWID_PATCH_CONTEXT Context;

    if (Filter->DiskNumber >= HWID_MAX_DISKS) {
        return HwidPassThrough(Filter->Self, Irp);
    }
    if (Stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(STORAGE_PROPERTY_QUERY) ||
        Irp->AssociatedIrp.SystemBuffer == NULL) {
        return HwidPassThrough(Filter->Self, Irp);
    }
    Query = (PSTORAGE_PROPERTY_QUERY)Irp->AssociatedIrp.SystemBuffer;
    if (Query->PropertyId != StorageDeviceProperty) {
        return HwidPassThrough(Filter->Self, Irp);
    }

    Context = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*Context), HWID_TAG);
    if (Context == NULL) {
        return HwidPassThrough(Filter->Self, Irp);
    }
    RtlZeroMemory(Context, sizeof(*Context));
    Context->Type = HwidPatchKindStorage;
    HwidLockedCopyDiskSerial(Filter->DiskNumber, Context->Serial);
    if (HwidStringEmpty(Context->Serial)) {
        ExFreePoolWithTag(Context, HWID_TAG);
        return HwidPassThrough(Filter->Self, Irp);
    }
    return HwidForwardWithPatch(Filter, Irp, Context);
}

static NTSTATUS HwidSpoofSmart(_In_ PHWID_FILTER Filter, _In_ PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PSENDCMDINPARAMS Input;
    PHWID_PATCH_CONTEXT Context;

    if (Filter->DiskNumber >= HWID_MAX_DISKS) {
        return HwidPassThrough(Filter->Self, Irp);
    }
    /*
     * Only IDENTIFY returns a 512-byte ID sector at bBuffer. SMART
     * attribute and threshold reads reuse the same IOCTL and must pass
     * through untouched.
     */
    if (Stack->Parameters.DeviceIoControl.InputBufferLength <
            (ULONG)FIELD_OFFSET(SENDCMDINPARAMS, bBuffer) ||
        Irp->AssociatedIrp.SystemBuffer == NULL) {
        return HwidPassThrough(Filter->Self, Irp);
    }
    Input = (PSENDCMDINPARAMS)Irp->AssociatedIrp.SystemBuffer;
    if (Input->irDriveRegs.bCommandReg != 0xEC && Input->irDriveRegs.bCommandReg != 0xA1) {
        return HwidPassThrough(Filter->Self, Irp);
    }

    Context = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*Context), HWID_TAG);
    if (Context == NULL) {
        return HwidPassThrough(Filter->Self, Irp);
    }
    RtlZeroMemory(Context, sizeof(*Context));
    Context->Type = HwidPatchKindSmart;
    HwidLockedCopyDiskSerial(Filter->DiskNumber, Context->Serial);
    if (HwidStringEmpty(Context->Serial)) {
        ExFreePoolWithTag(Context, HWID_TAG);
        return HwidPassThrough(Filter->Self, Irp);
    }
    return HwidForwardWithPatch(Filter, Irp, Context);
}

static NTSTATUS HwidSpoofAta(_In_ PHWID_FILTER Filter, _In_ PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PATA_PASS_THROUGH_EX Ata;
    PHWID_PATCH_CONTEXT Context;

    if (Filter->DiskNumber >= HWID_MAX_DISKS) {
        return HwidPassThrough(Filter->Self, Irp);
    }
    if (Stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ATA_PASS_THROUGH_EX) ||
        Irp->AssociatedIrp.SystemBuffer == NULL) {
        return HwidPassThrough(Filter->Self, Irp);
    }
    Ata = (PATA_PASS_THROUGH_EX)Irp->AssociatedIrp.SystemBuffer;
    if (Ata->CurrentTaskFile[6] != 0xEC && Ata->CurrentTaskFile[6] != 0xA1) {
        return HwidPassThrough(Filter->Self, Irp);
    }

    Context = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*Context), HWID_TAG);
    if (Context == NULL) {
        return HwidPassThrough(Filter->Self, Irp);
    }
    RtlZeroMemory(Context, sizeof(*Context));
    Context->Type = HwidPatchKindAta;
    HwidLockedCopyDiskSerial(Filter->DiskNumber, Context->Serial);
    if (HwidStringEmpty(Context->Serial)) {
        ExFreePoolWithTag(Context, HWID_TAG);
        return HwidPassThrough(Filter->Self, Irp);
    }
    return HwidForwardWithPatch(Filter, Irp, Context);
}

static NTSTATUS HwidSpoofVolumeQuery(_In_ PHWID_FILTER Filter, _In_ PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PHWID_PATCH_CONTEXT Context;
    ULONG Serial = 0;

    if (Stack->Parameters.QueryVolume.FsInformationClass != FileFsVolumeInformation) {
        return HwidPassThrough(Filter->Self, Irp);
    }
    if (Stack->Parameters.QueryVolume.Length < sizeof(FILE_FS_VOLUME_INFORMATION)) {
        return HwidPassThrough(Filter->Self, Irp);
    }
    if (!HwidLockedVolumeSerial(Filter->VolumeIndex, &Serial)) {
        return HwidPassThrough(Filter->Self, Irp);
    }

    Context = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*Context), HWID_TAG);
    if (Context == NULL) {
        return HwidPassThrough(Filter->Self, Irp);
    }
    RtlZeroMemory(Context, sizeof(*Context));
    Context->Type = HwidPatchKindVolume;
    Context->VolumeSerial = Serial;
    return HwidForwardWithPatch(Filter, Irp, Context);
}

static NTSTATUS HwidFilterDispatch(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    PHWID_FILTER Filter = (PHWID_FILTER)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);

    if (Filter == NULL) {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (Stack->MajorFunction == IRP_MJ_QUERY_VOLUME_INFORMATION) {
        if (Filter->Kind == HwidFilterVolume) {
            return HwidSpoofVolumeQuery(Filter, Irp);
        }
        return HwidPassThrough(DeviceObject, Irp);
    }

    if (Stack->MajorFunction == IRP_MJ_DEVICE_CONTROL ||
        Stack->MajorFunction == IRP_MJ_INTERNAL_DEVICE_CONTROL) {
        ULONG Code = Stack->Parameters.DeviceIoControl.IoControlCode;

        if (Filter->Kind != HwidFilterVolume) {
            switch (Code) {
            case IOCTL_STORAGE_QUERY_PROPERTY:
                return HwidSpoofStorageQuery(Filter, Irp);
            case IOCTL_SMART_RCV_DRIVE_DATA:
                return HwidSpoofSmart(Filter, Irp);
            case IOCTL_ATA_PASS_THROUGH:
                return HwidSpoofAta(Filter, Irp);
            default:
                break;
            }
        }
    }

    return HwidPassThrough(DeviceObject, Irp);
}

/* ------------------------------------------------------------------ */
/* Filter attach                                                       */
/* ------------------------------------------------------------------ */

static NTSTATUS HwidAttachFilter(
    _In_z_ PCWSTR TargetName,
    _In_ HWID_FILTER_KIND Kind,
    _In_ ULONG DiskNumber,
    _In_ ULONG VolumeIndex)
{
    UNICODE_STRING Name;
    PFILE_OBJECT FileObject = NULL;
    PDEVICE_OBJECT Target = NULL;
    PDEVICE_OBJECT FilterDevice = NULL;
    PDEVICE_OBJECT Lower = NULL;
    PHWID_FILTER Entry = NULL;
    NTSTATUS Status;
    KIRQL OldIrql;

    RtlInitUnicodeString(&Name, TargetName);
    Status = IoGetDeviceObjectPointer(&Name, FILE_READ_ATTRIBUTES, &FileObject, &Target);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = IoCreateDevice(g_DriverObject,
                            0,
                            NULL,
                            (Kind == HwidFilterVolume) ? FILE_DEVICE_FILE_SYSTEM : FILE_DEVICE_DISK,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &FilterDevice);
    if (!NT_SUCCESS(Status)) {
        ObDereferenceObject(FileObject);
        return Status;
    }

    Entry = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*Entry), HWID_TAG);
    if (Entry == NULL) {
        IoDeleteDevice(FilterDevice);
        ObDereferenceObject(FileObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(Entry, sizeof(*Entry));
    Entry->Kind = Kind;
    Entry->DiskNumber = DiskNumber;
    Entry->VolumeIndex = VolumeIndex;
    Entry->Self = FilterDevice;
    FilterDevice->DeviceExtension = Entry;

    FilterDevice->Flags |= Target->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);
    FilterDevice->Characteristics = Target->Characteristics;
    FilterDevice->AlignmentRequirement = Target->AlignmentRequirement;

    Lower = IoAttachDeviceToDeviceStack(FilterDevice, Target);
    if (Lower == NULL) {
        FilterDevice->DeviceExtension = NULL;
        ExFreePoolWithTag(Entry, HWID_TAG);
        IoDeleteDevice(FilterDevice);
        ObDereferenceObject(FileObject);
        return STATUS_NO_SUCH_DEVICE;
    }
    Entry->Lower = Lower;

    FilterDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    KeAcquireSpinLock(&g_FilterLock, &OldIrql);
    InsertTailList(&g_Filters, &Entry->ListEntry);
    KeReleaseSpinLock(&g_FilterLock, OldIrql);

    ObDereferenceObject(FileObject);
    return STATUS_SUCCESS;
}

static VOID HwidAttachAll(VOID)
{
    WCHAR NameBuffer[128];

    for (ULONG Disk = 0; Disk < HWID_MAX_DISKS; Disk++) {
        (VOID)RtlStringCchPrintfW(NameBuffer, RTL_NUMBER_OF(NameBuffer),
                                  L"\\Device\\Harddisk%lu\\DR0", Disk);
        (VOID)HwidAttachFilter(NameBuffer, HwidFilterDisk, Disk, 0);

        for (ULONG Partition = 1; Partition <= HWID_MAX_PARTITIONS; Partition++) {
            (VOID)RtlStringCchPrintfW(NameBuffer, RTL_NUMBER_OF(NameBuffer),
                                      L"\\Device\\Harddisk%lu\\Partition%lu", Disk, Partition);
            (VOID)HwidAttachFilter(NameBuffer, HwidFilterPartition, Disk, 0);
        }
    }

    for (ULONG Letter = 2; Letter < HWID_MAX_VOLUMES; Letter++) {
        WCHAR DriveBuffer[8];

        DriveBuffer[0] = L'\\';
        DriveBuffer[1] = L'?';
        DriveBuffer[2] = L'?';
        DriveBuffer[3] = L'\\';
        DriveBuffer[4] = (WCHAR)(L'A' + Letter);
        DriveBuffer[5] = L':';
        DriveBuffer[6] = L'\0';

        (VOID)HwidAttachFilter(DriveBuffer, HwidFilterVolume, 0, Letter);
    }
}

static VOID HwidDetachAll(VOID)
{
    for (;;) {
        PLIST_ENTRY Node;
        PHWID_FILTER Entry;
        KIRQL OldIrql;

        KeAcquireSpinLock(&g_FilterLock, &OldIrql);
        if (IsListEmpty(&g_Filters)) {
            KeReleaseSpinLock(&g_FilterLock, OldIrql);
            break;
        }
        Node = RemoveHeadList(&g_Filters);
        KeReleaseSpinLock(&g_FilterLock, OldIrql);

        Entry = CONTAINING_RECORD(Node, HWID_FILTER, ListEntry);
        if (Entry->Lower != NULL) {
            IoDetachDevice(Entry->Lower);
        }
        if (Entry->Self != NULL) {
            Entry->Self->DeviceExtension = NULL;
            IoDeleteDevice(Entry->Self);
        }
        ExFreePoolWithTag(Entry, HWID_TAG);
    }
}

/* ------------------------------------------------------------------ */
/* Control device                                                      */
/* ------------------------------------------------------------------ */

static NTSTATUS HwidCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS HwidGetStatus(_Out_ PHWID_STATUS StatusReport)
{
    PLIST_ENTRY Node;
    KIRQL OldIrql;

    RtlZeroMemory(StatusReport, sizeof(*StatusReport));
    StatusReport->Size = sizeof(HWID_STATUS);
    StatusReport->DriverVersion = HWID_DRIVER_VERSION;

    KeAcquireSpinLock(&g_FilterLock, &OldIrql);
    for (Node = g_Filters.Flink; Node != &g_Filters; Node = Node->Flink) {
        PHWID_FILTER Entry = CONTAINING_RECORD(Node, HWID_FILTER, ListEntry);
        switch (Entry->Kind) {
        case HwidFilterDisk:
            StatusReport->DiskFilters++;
            break;
        case HwidFilterPartition:
            StatusReport->PartitionFilters++;
            break;
        case HwidFilterVolume:
            StatusReport->VolumeFilters++;
            break;
        default:
            break;
        }
    }
    KeReleaseSpinLock(&g_FilterLock, OldIrql);

    ExAcquireResourceSharedLite(&g_SmbiosLock, TRUE);
    StatusReport->SmbiosActive = (g_PatchedSmbios != NULL) ? 1 : 0;
    StatusReport->SmbiosBytes = g_PatchedSmbiosLength;
    StatusReport->SmbiosFieldsPatched = g_SmbiosFieldsPatched;
    ExReleaseResourceLite(&g_SmbiosLock);

    StatusReport->Persisted = g_Persisted ? 1 : 0;

    KeAcquireSpinLock(&g_ConfigLock, &OldIrql);
    StatusReport->ConfigVersion = g_Config.Version;
    StatusReport->ConfigGeneration = g_ConfigGeneration;
    StatusReport->Flags = g_Config.Flags;
    KeReleaseSpinLock(&g_ConfigLock, OldIrql);

    return STATUS_SUCCESS;
}

/*
 * RestoreOriginal is FALSE when a new image is about to be written: putting
 * the firmware bytes back first would flash the real UUID, and any consumer
 * that read the value between the two writes would cache it.
 */
static VOID HwidDropPatchedSmbios(_In_ BOOLEAN RestoreOriginal)
{
    PUCHAR Old;

    ExAcquireResourceExclusiveLite(&g_SmbiosLock, TRUE);
    if (RestoreOriginal && g_SmbiosApplied && g_OriginalSmbios != NULL) {
        (VOID)HwidWriteSmbiosValue(g_OriginalSmbios, g_OriginalSmbiosLength);
    }
    Old = g_PatchedSmbios;
    g_PatchedSmbios = NULL;
    g_PatchedSmbiosLength = 0;
    g_SmbiosFieldsPatched = 0;
    g_SmbiosApplied = FALSE;
    ExReleaseResourceLite(&g_SmbiosLock);

    if (Old != NULL) {
        ExFreePoolWithTag(Old, HWID_TAG);
    }
}

static NTSTATUS HwidSetConfig(_In_reads_bytes_(InputLength) const HWID_CONFIG *NewConfig, ULONG InputLength)
{
    PHWID_CONFIG Local;
    KIRQL OldIrql;
    SIZE_T Index;

    if (InputLength < sizeof(HWID_CONFIG) || NewConfig == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (NewConfig->Size != sizeof(HWID_CONFIG) || NewConfig->Version != HWID_CONFIG_VERSION) {
        return STATUS_REVISION_MISMATCH;
    }

    /*
     * HWID_CONFIG is roughly 5 KB. Keeping it off the 12 KB kernel stack
     * leaves room for the SMBIOS parser and registry work below.
     */
    Local = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*Local), HWID_TAG);
    if (Local == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(Local, NewConfig, sizeof(*Local));

    HwidSanitizeAnsi(Local->SystemUuid, sizeof(Local->SystemUuid));
    HwidSanitizeAnsi(Local->SystemSerial, sizeof(Local->SystemSerial));
    HwidSanitizeAnsi(Local->BaseboardSerial, sizeof(Local->BaseboardSerial));
    HwidSanitizeAnsi(Local->ChassisSerial, sizeof(Local->ChassisSerial));
    HwidSanitizeAnsi(Local->BiosVendor, sizeof(Local->BiosVendor));
    HwidSanitizeAnsi(Local->BiosVersion, sizeof(Local->BiosVersion));
    HwidSanitizeAnsi(Local->BiosReleaseDate, sizeof(Local->BiosReleaseDate));
    HwidSanitizeAnsi(Local->SystemManufacturer, sizeof(Local->SystemManufacturer));
    HwidSanitizeAnsi(Local->SystemProductName, sizeof(Local->SystemProductName));
    HwidSanitizeAnsi(Local->SystemVersion, sizeof(Local->SystemVersion));
    HwidSanitizeAnsi(Local->SystemFamily, sizeof(Local->SystemFamily));
    HwidSanitizeAnsi(Local->SystemSku, sizeof(Local->SystemSku));
    HwidSanitizeAnsi(Local->BaseboardManufacturer, sizeof(Local->BaseboardManufacturer));
    HwidSanitizeAnsi(Local->BaseboardProduct, sizeof(Local->BaseboardProduct));
    HwidSanitizeAnsi(Local->BaseboardVersion, sizeof(Local->BaseboardVersion));
    HwidSanitizeAnsi(Local->ChassisManufacturer, sizeof(Local->ChassisManufacturer));
    HwidSanitizeAnsi(Local->ChassisVersion, sizeof(Local->ChassisVersion));

    for (Index = 0; Index < HWID_MAX_DISKS; Index++) {
        HwidSanitizeAnsi(Local->DiskSerial[Index], HWID_MAX_SERIAL_LEN);
    }
    for (Index = 0; Index < HWID_MAX_VOLUMES; Index++) {
        HwidSanitizeAnsi(Local->VolumeSerial[Index], HWID_MAX_VOLUME_SERIAL_LEN);
    }
    for (Index = 0; Index < HWID_MAX_MEMORY; Index++) {
        HwidSanitizeAnsi(Local->MemorySerial[Index], HWID_MAX_SERIAL_LEN);
    }

    Local->Size = sizeof(HWID_CONFIG);
    Local->Version = HWID_CONFIG_VERSION;

    KeAcquireSpinLock(&g_ConfigLock, &OldIrql);
    RtlCopyMemory(&g_Config, Local, sizeof(g_Config));
    g_ConfigGeneration++;
    KeReleaseSpinLock(&g_ConfigLock, OldIrql);

    /*
     * Only skip the restore when a replacement image is about to be written;
     * a config without the SMBIOS flag must put the firmware bytes back.
     */
    {
        const BOOLEAN applySmbios = (Local->Flags & HWID_CFG_SMBIOS) != 0;
        HwidDropPatchedSmbios(applySmbios ? FALSE : TRUE);
        if (applySmbios) {
            (VOID)HwidBuildSmbiosImage(Local);
            (VOID)HwidWriteHardwareBios(Local);
        }
    }
    if ((Local->Flags & HWID_CFG_PERSIST) != 0) {
        (VOID)HwidSavePersistedConfig();
    } else {
        /* A non-perma apply cancels any earlier stored identity. */
        HwidDeletePersistedConfig();
    }

    ExFreePoolWithTag(Local, HWID_TAG);
    return STATUS_SUCCESS;
}

static NTSTATUS HwidDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG Code = Stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG InputLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG OutputLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID Buffer = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS Status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG Information = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (Code) {
    case HWID_IOCTL_SET_CONFIG:
        Status = HwidSetConfig((const HWID_CONFIG *)Buffer, InputLength);
        break;

    case HWID_IOCTL_GET_STATUS:
        if (Buffer == NULL || OutputLength < sizeof(HWID_STATUS)) {
            Status = STATUS_BUFFER_TOO_SMALL;
        } else {
            Status = HwidGetStatus((PHWID_STATUS)Buffer);
            Information = sizeof(HWID_STATUS);
        }
        break;

    case HWID_IOCTL_CLEAR_CONFIG: {
        KIRQL OldIrql;

        KeAcquireSpinLock(&g_ConfigLock, &OldIrql);
        HwidZeroConfig();
        g_ConfigGeneration++;
        KeReleaseSpinLock(&g_ConfigLock, OldIrql);
        HwidDropPatchedSmbios(TRUE);
        HwidDeletePersistedConfig();
        Status = STATUS_SUCCESS;
        break;
    }

    default:
        break;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS HwidControlDispatch(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);

    switch (Stack->MajorFunction) {
    case IRP_MJ_CREATE:
    case IRP_MJ_CLOSE:
        return HwidCreateClose(DeviceObject, Irp);
    case IRP_MJ_DEVICE_CONTROL:
        return HwidDeviceControl(DeviceObject, Irp);
    default:
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }
}

/*
 * Filter devices and the control device share one driver object, so every
 * entry point routes by device. Without this split a storage IRP would land
 * on the IOCTL handler and a control IOCTL could be forwarded down a disk.
 */
static NTSTATUS HwidDispatch(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    if (DeviceObject == g_ControlDevice) {
        return HwidControlDispatch(DeviceObject, Irp);
    }
    return HwidFilterDispatch(DeviceObject, Irp);
}

/* ------------------------------------------------------------------ */
/* Driver lifetime                                                     */
/* ------------------------------------------------------------------ */

static VOID HwidDriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING SymbolicLink;

    UNREFERENCED_PARAMETER(DriverObject);

    HwidDetachAll();

    /* Put the firmware table back before the snapshot is freed. */
    HwidDropPatchedSmbios(TRUE);

    RtlInitUnicodeString(&SymbolicLink, HWID_SYMLINK_NAME);
    (VOID)IoDeleteSymbolicLink(&SymbolicLink);

    if (g_ControlDevice != NULL) {
        IoDeleteDevice(g_ControlDevice);
        g_ControlDevice = NULL;
    }

    ExAcquireResourceExclusiveLite(&g_SmbiosLock, TRUE);
    if (g_OriginalSmbios != NULL) {
        ExFreePoolWithTag(g_OriginalSmbios, HWID_TAG);
        g_OriginalSmbios = NULL;
    }
    ExReleaseResourceLite(&g_SmbiosLock);

    if (g_ServiceKeyPath.Buffer != NULL) {
        ExFreePoolWithTag(g_ServiceKeyPath.Buffer, HWID_TAG);
        g_ServiceKeyPath.Buffer = NULL;
        g_ServiceKeyPath.Length = 0;
        g_ServiceKeyPath.MaximumLength = 0;
    }

    if (g_SmbiosLockReady) {
        ExDeleteResourceLite(&g_SmbiosLock);
        g_SmbiosLockReady = FALSE;
    }
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING DeviceName;
    UNICODE_STRING SymbolicLink;
    NTSTATUS Status;

    g_DriverObject = DriverObject;
    InitializeListHead(&g_Filters);
    KeInitializeSpinLock(&g_FilterLock);
    KeInitializeSpinLock(&g_ConfigLock);
    ExInitializeResourceLite(&g_SmbiosLock);
    g_SmbiosLockReady = TRUE;
    HwidZeroConfig();

    /* Keep our own copy of \Registry\Machine\...\Services\HwidSpoofer. */
    if (RegistryPath != NULL && RegistryPath->Buffer != NULL && RegistryPath->Length != 0) {
        g_ServiceKeyPath.Buffer = ExAllocatePool2(POOL_FLAG_PAGED,
                                                  RegistryPath->Length + sizeof(WCHAR), HWID_TAG);
        if (g_ServiceKeyPath.Buffer != NULL) {
            RtlCopyMemory(g_ServiceKeyPath.Buffer, RegistryPath->Buffer, RegistryPath->Length);
            g_ServiceKeyPath.Length = RegistryPath->Length;
            g_ServiceKeyPath.MaximumLength = RegistryPath->Length + sizeof(WCHAR);
            g_ServiceKeyPath.Buffer[RegistryPath->Length / sizeof(WCHAR)] = L'\0';
        }
    }

    for (ULONG Index = 0; Index <= IRP_MJ_MAXIMUM_FUNCTION; Index++) {
        DriverObject->MajorFunction[Index] = HwidDispatch;
    }
    DriverObject->DriverUnload = HwidDriverUnload;

    RtlInitUnicodeString(&DeviceName, HWID_DEVICE_NAME);
    Status = IoCreateDevice(DriverObject,
                            0,
                            &DeviceName,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &g_ControlDevice);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }
    g_ControlDevice->Flags |= DO_BUFFERED_IO;

    RtlInitUnicodeString(&SymbolicLink, HWID_SYMLINK_NAME);
    Status = IoCreateSymbolicLink(&SymbolicLink, &DeviceName);
    if (!NT_SUCCESS(Status)) {
        IoDeleteDevice(g_ControlDevice);
        g_ControlDevice = NULL;
        return Status;
    }

    /*
     * Snapshot the firmware table. Every rebuild copies this, so the value
     * on disk can always be put back byte for byte.
     */
    {
        PVOID Data = NULL;
        ULONG DataLength = 0;
        ULONG ValueType = 0;
        Status = HwidReadRegistryValue(HwidSmbiosKeyPath, L"SMBiosData", &Data, &DataLength,
                                       &ValueType);
        if (NT_SUCCESS(Status) && ValueType == REG_BINARY && DataLength <= HWID_SMBIOS_MAX) {
            g_OriginalSmbios = (PUCHAR)Data;
            g_OriginalSmbiosLength = DataLength;
        } else if (Data != NULL) {
            ExFreePoolWithTag(Data, HWID_TAG);
        }
    }

    /*
     * Perma mode: the service is AUTO_START, so the configuration written by
     * --install is reloaded here on every boot. The SMBIOS value is rewritten
     * each time because mssmbios regenerates it from firmware during boot.
     */
    {
        PHWID_CONFIG Boot = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*Boot), HWID_TAG);
        if (Boot != NULL) {
            if (NT_SUCCESS(HwidLoadPersistedConfig())) {
                HwidCopyConfigOut(Boot);
                if ((Boot->Flags & HWID_CFG_SMBIOS) != 0) {
                    (VOID)HwidBuildSmbiosImage(Boot);
                    (VOID)HwidWriteHardwareBios(Boot);
                }
            }
            ExFreePoolWithTag(Boot, HWID_TAG);
        }
    }

    HwidAttachAll();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "HWID: driver loaded, smbios=%lu bytes\n", g_OriginalSmbiosLength);

    return STATUS_SUCCESS;
}
