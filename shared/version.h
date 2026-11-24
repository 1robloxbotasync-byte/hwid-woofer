/*
 * Version and publisher identity, in one place.
 *
 * Four binaries and five resource scripts read these values. Signing checks,
 * Add/Remove Programs and Explorer's Details tab all quote them, so a build
 * that says 2.4.0 in one file and 2.3.1 in another reads as tampered with.
 * Change the numbers here.
 */
#pragma once

#define HWID_VERSION_MAJOR 2
#define HWID_VERSION_MINOR 4
#define HWID_VERSION_PATCH 1
#define HWID_VERSION_STRING "2.4.1"
#define HWID_VERSION_WIDE L"2.4.1"

#define HWID_PRODUCT_NAME "HWID Spoofer"
#define HWID_PRODUCT_NAME_WIDE L"HWID Spoofer"
#define HWID_COMPANY_NAME "HWID Spoofer Project"
#define HWID_COMPANY_NAME_WIDE L"HWID Spoofer Project"
#define HWID_COPYRIGHT "Copyright (C) 2026 HWID Spoofer Project"
#define HWID_TAGLINE "Firmware, registry and network identity tooling"
