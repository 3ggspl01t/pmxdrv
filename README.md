# pmxdrv.sys

This repository is an archive of my research into the vulnerable `pmxdrv.sys` Windows kernel driver and the proof-of-concept code developed during that research.

The exact driver binary is included under driver/pmxdrv.sys.

## Driver information

| Property | Value |
| --- | --- |
| File name | `pmxdrv.sys` |
| Repository path | `driver/pmxdrv.sys` |
| File type | PE kernel driver |
| Target architecture | x64 |
| Family | Intel PMx |
| Build era | 2010 |
| Reported signer | PAIPTAC |
| MD5 | `0bee791c7c7ace453c134e73633c497d` |
| SHA-1 | `17bdfa70fe84e515183e5fa675d72d5d0e2090e8` |
| SHA-256 | `82b30461dbf40ac15fce6a83b9bad2ebd05b27dea1b784eaa096422fe8927b7b` |
| Kernel device object | `\Device\Pmxdrv` |
| User-mode device path | `\\.\PMXDRV` |
| Physical-memory mapping IOCTL | `0x00222AB8` |

The driver exposes functionality that allows a caller to request mappings of physical memory into user-mode address space. The research in this repository focuses on understanding that primitive and demonstrating its security impact.

## Proof-of-Concept

Two PoCs were developed:

- **PoC #1 — Physical memory read/write:** demonstrates the underlying physical-memory mapping primitive exposed by `pmxdrv.sys`.
- **PoC #2 — SYSTEM token replacement:** builds on that primitive by scanning Windows-described physical memory ranges, locating and validating process objects, resolving the `SYSTEM` and PoC parent-process `EPROCESS` structures, and replacing the parent process token with the `SYSTEM` token.

The following environment was the primary basis of PoC development and validation:

```text
Operating system : Windows 10 Pro 22H2
Build            : 10.0.19045.6466
Architecture     : x64
```

PoC #2 is particularly build-dependent because it relies on Windows kernel structure offsets and observed process-allocation layout. Those assumptions should not be expected to remain valid across Windows builds.

## PoC #1 — Physical memory read/write

PoC #1 establishes the physical-memory primitive independently of the later privilege-escalation logic.

Its purpose is to demonstrate that a user-mode process able to open `\\.\PMXDRV` can request a mapping for caller-selected physical pages and access the returned mapping.

At a high level, PoC #1:

1. Opens `\\.\PMXDRV`.
2. Constructs the reconstructed mapping request.
3. Sends IOCTL `0x00222AB8`.
4. Retrieves the mapped user-mode address.
5. Reads from the mapped physical page.
6. Performs a controlled write.
7. Unmaps the mapping.

This PoC provides the baseline primitive used by PoC #2.

### PoC #1 video demonstration

**Physical memory read/write demonstration**

Demonstration of the `pmxdrv.sys` physical-memory mapping primitive used to perform controlled physical-memory read/write operations from user mode.

https://github.com/user-attachments/assets/a6533490-cd45-44d1-968c-dfa1802ab8dc

## PoC #2 — SYSTEM token replacement

PoC #2 turns the physical-memory primitive into a concrete local privilege-escalation demonstration.

Rather than relying on kernel virtual addresses directly, the PoC searches Windows-described physical memory ranges for candidate process allocations and validates them before identifying the required `EPROCESS` structures.

At a high level, PoC #2:

1. Validates the target Windows build.
2. Resolves the PoC parent process.
3. Opens `\\.\PMXDRV`.
4. Tests the physical-memory primitive.
5. Loads Windows-described physical memory ranges.
6. Scans those ranges for `"Proc"` pool tags.
7. Tests candidate `EPROCESS` displacements.
8. Validates candidate process objects.
9. Resolves the `SYSTEM` and parent-process targets.
10. Reads the `SYSTEM` token reference.
11. Overwrites the parent process `EPROCESS.Token`.
12. Reads the token field back and verifies that the token pointer is stable.

For the Windows 10 build used during development, the relevant EPROCESS offsets were:

| Field | Offset |
| --- | ---: |
| `_EPROCESS.UniqueProcessId` | `0x440` |
| `_EPROCESS.ActiveProcessLinks` | `0x448` |
| `_EPROCESS.Token` | `0x4B8` |
| `_EPROCESS.ImageFileName` | `0x5A8` |

These offsets are build-specific and should be independently verified before adapting the PoC to another Windows version.

### PoC #2 video demonstration

**SYSTEM token replacement demonstration**

End-to-end demonstration of PoC #2 locating validated `EPROCESS` targets in Windows-described physical memory, replacing the parent process token, and demonstrating `NT AUTHORITY\SYSTEM`.

https://github.com/user-attachments/assets/2e1e5dd1-9e56-45ab-a0a6-a11a28d1e245

## Building

Both PoCs are maintained as independent Visual Studio C++ solutions.

Open the appropriate solution:

```text
poc1-physical-memory-rw\pmxdrv_poc1.slnx
```

or:

```text
poc2-token-replacement\pmxdrv_poc2.slnx
```

Build for:

```text
Platform      : x64
Configuration : Release or Debug
```

### PoC #2 character-set setting

PoC #2 was developed using the Visual Studio **non-Unicode** character-set configuration.

Under:

```text
Project Properties
  -> Configuration Properties
    -> Advanced
      -> Character Set
```

set:

```text
Character Set : Use Multi-Byte Character Set
```

The equivalent project-file setting is:

```xml
<CharacterSet>MultiByte</CharacterSet>
```

The source uses narrow-character strings and ANSI Win32 APIs such as `CreateFileA()`. Enabling `UNICODE` / `_UNICODE` without adapting the corresponding strings and APIs may result in type mismatches or compilation errors.

The intended character-set setting should be preserved in the committed `pmxdrv_poc2.vcxproj`.

## Repository layout

The repository preserves the exact driver sample used during the research together with the final PoC source code and the minimum Visual Studio project files needed to reproduce each build.

All explanatory material is kept in this root `README.md`. The individual PoC directories therefore contain only files required to build their respective projects.

```text
pmxdrv/
├── README.md
├── .gitignore
│
├── driver/
│   └── pmxdrv.sys
│
├── poc1-physical-memory-rw/
│   ├── pmxdrv_poc1.slnx
│   ├── pmxdrv_poc1.vcxproj
│   └── pmxdrv_poc1.cpp
│
└── poc2-token-replacement/
    ├── pmxdrv_poc2.slnx
    ├── pmxdrv_poc2.vcxproj
    └── pmxdrv_poc2.cpp
```

Each PoC is intentionally maintained as an independent Visual Studio solution.

If either PoC is split across multiple source files, the corresponding `.h` and additional `.cpp` files should remain in that PoC directory as well.

Files such as `.vcxproj.user`, `.vcxproj.filters`, Visual Studio caches, compiled executables, object files, PDBs, and other build output are excluded from the repository.

The `pmxdrv.sys` binary under `driver/` is the original research sample and is not a build output of either PoC.

## Related blog posts

The reverse engineering of `pmxdrv.sys` and development of the PoCs are documented in more detail in the following posts.

### Driver analysis

1. [From Intel-SA-00086 Detection Tool to Physical Memory: Reverse Engineering pmxdrv.sys](https://3ggspl01t.github.io/posts/reverse-engineering-pmxdrv/)
2. [What Does pmxdrv.sys Expect? Reconstructing the IOCTL Input Structure](https://3ggspl01t.github.io/posts/reconstruct-ioctl-input-structure/)

### PoC #1 development

1. [Why Does My PoC Keep Throwing BSOD? Getting the Structure Packing Right](https://3ggspl01t.github.io/posts/pmxdrv-poc1/)

### PoC #2 development

1. [Exploiting pmxdrv.sys (Part 1): Understanding the Pieces](https://3ggspl01t.github.io/posts/pmxdrv-poc2-part-1/)
2. [Exploiting pmxdrv.sys (Part 2): Finding EPROCESS Reliably](https://3ggspl01t.github.io/posts/pmxdrv-poc2-part-2/)
3. [Exploiting pmxdrv.sys (Part 3): Finding Windows-Described Physical Memory](https://3ggspl01t.github.io/posts/pmxdrv-poc2-part-3/)
4. [Exploiting pmxdrv.sys (Part 4): Implementing the EPROCESS Scanner](https://3ggspl01t.github.io/posts/pmxdrv-poc2-part-4/)
5. [Exploiting pmxdrv.sys (Part 5): Completing PoC #2](https://3ggspl01t.github.io/posts/pmxdrv-poc2-part-5/)

The GitHub repository is intended to be the canonical code and sample archive, while the blog series provides the narrative explanation of how the driver was analyzed and how the PoCs were developed and validated.

## Disclaimer

This repository is provided for educational, defensive, and authorized security-research purposes.

The driver and proof-of-concept material interact with Windows kernel memory and may cause system instability, data loss, or a system crash if used incorrectly or on an unsupported build.

Do not use the material against systems for which you do not have explicit authorization.

The included `pmxdrv.sys` binary is a third-party research sample. Its inclusion does not imply authorship, ownership, or endorsement. Redistribution should be performed only where permitted by the applicable license, terms, and law.
