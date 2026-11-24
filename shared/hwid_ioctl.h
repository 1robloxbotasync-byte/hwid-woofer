#ifndef HWID_IOCTL_H
#define HWID_IOCTL_H

#if defined(_KERNEL_MODE)
#include <ntdef.h>
#else
#include <windows.h>
#endif

/*
 * Shared ABI between hwidspoof.exe and hwid_drv.sys.
 * Both sides are built as x64 by build.ps1; the struct is plain data
 * so the layout is identical in user and kernel mode.
 */

#define HWID_DRIVER_VERSION       0x00010000UL
#define HWID_CONFIG_VERSION       1UL

#define HWID_MAX_DISKS            32
#define HWID_MAX_SERIAL_LEN       64
#define HWID_MAX_TEXT_LEN         96
#define HWID_MAX_VOLUMES          26
#define HWID_MAX_VOLUME_SERIAL_LEN 16
#define HWID_MAX_MEMORY           8

#define HWID_CFG_DISK_SERIAL      0x00000001UL
#define HWID_CFG_VOLUME_SERIAL    0x00000002UL
#define HWID_CFG_SMBIOS           0x00000004UL
/* Keep the configuration in the service key so autostart reloads it. */
#define HWID_CFG_PERSIST          0x00000008UL

/*
 * Names are deliberately boring: they show up in the service list, in
 * \Device, and in loaded-module enumeration. Nothing here needs to advertise
 * what the driver does.
 */
#define HWID_DEVICE_NAME          L"\\Device\\StorHlp"
#define HWID_SYMLINK_NAME         L"\\DosDevices\\StorHlp"
#define HWID_USER_PATH            L"\\\\.\\StorHlp"
#define HWID_SERVICE_NAME         L"StorHlp"
#define HWID_DRIVER_FILE          L"storhlp.sys"

#define HWID_DEVICE_TYPE          FILE_DEVICE_UNKNOWN

#define HWID_IOCTL_SET_CONFIG \
    CTL_CODE(HWID_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define HWID_IOCTL_GET_STATUS \
    CTL_CODE(HWID_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA)
#define HWID_IOCTL_CLEAR_CONFIG \
    CTL_CODE(HWID_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA)

/*
 * DiskSerial[n] applies to physical disk n.
 * VolumeSerial[n] applies to drive letter ('A' + n), as 8 hex characters.
 */
typedef struct _HWID_CONFIG {
    ULONG Size;
    ULONG Version;
    ULONG Flags;
    ULONG Generation;

    CHAR DiskSerial[HWID_MAX_DISKS][HWID_MAX_SERIAL_LEN];
    CHAR VolumeSerial[HWID_MAX_VOLUMES][HWID_MAX_VOLUME_SERIAL_LEN];
    CHAR MemorySerial[HWID_MAX_MEMORY][HWID_MAX_SERIAL_LEN];

    CHAR SystemUuid[40];
    CHAR SystemSerial[HWID_MAX_TEXT_LEN];
    CHAR BaseboardSerial[HWID_MAX_TEXT_LEN];
    CHAR ChassisSerial[HWID_MAX_TEXT_LEN];

    CHAR BiosVendor[HWID_MAX_TEXT_LEN];
    CHAR BiosVersion[HWID_MAX_TEXT_LEN];
    CHAR BiosReleaseDate[16];

    CHAR SystemManufacturer[HWID_MAX_TEXT_LEN];
    CHAR SystemProductName[HWID_MAX_TEXT_LEN];
    CHAR SystemVersion[HWID_MAX_TEXT_LEN];
    CHAR SystemFamily[HWID_MAX_TEXT_LEN];
    CHAR SystemSku[HWID_MAX_TEXT_LEN];

    CHAR BaseboardManufacturer[HWID_MAX_TEXT_LEN];
    CHAR BaseboardProduct[HWID_MAX_TEXT_LEN];
    CHAR BaseboardVersion[HWID_MAX_TEXT_LEN];

    CHAR ChassisManufacturer[HWID_MAX_TEXT_LEN];
    CHAR ChassisVersion[HWID_MAX_TEXT_LEN];
} HWID_CONFIG, *PHWID_CONFIG;

typedef struct _HWID_STATUS {
    ULONG Size;
    ULONG DriverVersion;
    ULONG ConfigVersion;
    ULONG ConfigGeneration;
    ULONG Flags;

    ULONG DiskFilters;
    ULONG PartitionFilters;
    ULONG VolumeFilters;

    ULONG SmbiosActive;
    ULONG SmbiosBytes;
    ULONG SmbiosFieldsPatched;
    ULONG Persisted;
} HWID_STATUS, *PHWID_STATUS;

#endif /* HWID_IOCTL_H */
