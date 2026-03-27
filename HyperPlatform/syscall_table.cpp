#include "syscall_table.h"

#include <ntimage.h>
#include "ntdefs.h"
#include "log.h"
#include <cstddef>

#define MAX_SYSCALL_COUNT 0x1000

extern "C" {

// ---------------------------------------------------------------------------
// Syscall hook table.
// Index is the syscall id, value is the hook routine (null if not hooked).
// ---------------------------------------------------------------------------

static SyscallHookRoutine g_syscall_hook_table[MAX_SYSCALL_COUNT];

// ---------------------------------------------------------------------------
// SSN name table.
// Dynamically allocated during SystemGatesInitialize and freed in
// SystemGatesDestroy. Each entry holds a copy of the export name and its SSN.
// ---------------------------------------------------------------------------

struct SsnNameEntry {
  CHAR name[128];
  ULONG32 syscall_id;
};

struct SsnTable {
  SsnNameEntry* entries;  // pool allocation, freed in SystemGatesDestroy
  ULONG length;           // number of valid entries in Entries
};

static SsnTable g_ssn_table = {nullptr, 0};

#define SSN_POOL_TAG 'nssG'

// ---------------------------------------------------------------------------
// Internal: extract SSN from a clean x64 stub.
//   +0  4C 8B D1   mov r10, rcx
//   +3  B8         mov eax, imm32
//   +4  SSN        (ULONG, little-endian)
// ---------------------------------------------------------------------------

static ULONG SsnFromStub(_In_ PUCHAR Stub) {
  if (Stub[0] == 0x4Cu && Stub[1] == 0x8Bu && Stub[2] == 0xD1u &&
      Stub[3] == 0xB8u) {
    return *(PULONG)(Stub + 4);
  }

  return MAXULONG;
}

// ---------------------------------------------------------------------------
// Internal: open ntdll.dll and map it as SEC_IMAGE.
// Caller must unmap MappedBase with ZwUnmapViewOfSection when done.
// ---------------------------------------------------------------------------

static NTSTATUS MapNtdll(_Out_ PVOID* MappedBase, _Out_ SIZE_T* ViewSize) {
  UNICODE_STRING ntdllPath;
  OBJECT_ATTRIBUTES objAttr;
  IO_STATUS_BLOCK ioStatus;
  HANDLE fileHandle = nullptr;
  HANDLE sectionHandle = nullptr;
  NTSTATUS status;

  *MappedBase = nullptr;
  *ViewSize = 0;

  RtlInitUnicodeString(&ntdllPath, L"\\SystemRoot\\System32\\ntdll.dll");
  InitializeObjectAttributes(&objAttr, &ntdllPath,
                             OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr,
                             nullptr);

  status = ZwCreateFile(
      &fileHandle, GENERIC_READ | SYNCHRONIZE, &objAttr, &ioStatus, nullptr,
      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_OPEN,
      FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, nullptr, 0);
  if (!NT_SUCCESS(status)) return status;

  status =
      ZwCreateSection(&sectionHandle, SECTION_MAP_READ | SECTION_QUERY, nullptr,
                      nullptr, PAGE_READONLY, SEC_IMAGE, fileHandle);
  ZwClose(fileHandle);

  if (!NT_SUCCESS(status)) return status;

  status =
      ZwMapViewOfSection(sectionHandle, ZwCurrentProcess(), MappedBase, 0, 0,
                         nullptr, ViewSize, ViewUnmap, 0, PAGE_READONLY);
  ZwClose(sectionHandle);

  return status;
}

// ---------------------------------------------------------------------------
// Internal: count how many Nt* exports in the mapped ntdll have a clean stub,
// so we can allocate exactly the right amount of memory up front.
// ---------------------------------------------------------------------------

static ULONG CountNtExports(_In_ PIMAGE_EXPORT_DIRECTORY ExpDir,
                            _In_ PVOID MappedBase) {
  PULONG nameRvas = (PULONG)((PUCHAR)MappedBase + ExpDir->AddressOfNames);
  PUSHORT nameOrdinals =
      (PUSHORT)((PUCHAR)MappedBase + ExpDir->AddressOfNameOrdinals);
  PULONG funcRvas = (PULONG)((PUCHAR)MappedBase + ExpDir->AddressOfFunctions);
  ULONG count = 0;

  for (ULONG i = 0; i < ExpDir->NumberOfNames; i++) {
    PCSTR exportName = (PCSTR)((PUCHAR)MappedBase + nameRvas[i]);

    if (exportName[0] != 'N' || exportName[1] != 't') continue;

    ULONG ordinal = nameOrdinals[i];
    ULONG rva = funcRvas[ordinal];

    if (rva == 0) continue;

    if (SsnFromStub((PUCHAR)MappedBase + rva) != MAXULONG) count++;
  }

  return count;
}

// ---------------------------------------------------------------------------
// Internal: walk the export directory of a mapped ntdll, allocate
// g_ssn_table to fit exactly the resolved entries, and populate it.
// ---------------------------------------------------------------------------

static NTSTATUS BuildSsnTable(_In_ PVOID MappedBase) {
  g_ssn_table.entries = nullptr;
  g_ssn_table.length = 0;

  PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)MappedBase;
  if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE)
    return STATUS_INVALID_IMAGE_FORMAT;

  PIMAGE_NT_HEADERS64 ntHdr =
      (PIMAGE_NT_HEADERS64)((PUCHAR)MappedBase + dosHdr->e_lfanew);

  if (ntHdr->Signature != IMAGE_NT_SIGNATURE ||
      ntHdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    return STATUS_INVALID_IMAGE_FORMAT;
  }

  PIMAGE_DATA_DIRECTORY expDirEntry =
      &ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

  if (expDirEntry->VirtualAddress == 0 || expDirEntry->Size == 0)
    return STATUS_NOT_FOUND;

  PIMAGE_EXPORT_DIRECTORY expDir =
      (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)MappedBase +
                                expDirEntry->VirtualAddress);

  // count first so we allocate exactly the right size
  ULONG capacity = CountNtExports(expDir, MappedBase);
  if (capacity == 0) return STATUS_NOT_FOUND;

  g_ssn_table.entries = (SsnNameEntry*)ExAllocatePool2(
      POOL_FLAG_NON_PAGED, capacity * sizeof(SsnNameEntry), SSN_POOL_TAG);
  if (g_ssn_table.entries == nullptr) return STATUS_INSUFFICIENT_RESOURCES;

  PULONG nameRvas = (PULONG)((PUCHAR)MappedBase + expDir->AddressOfNames);
  PUSHORT nameOrdinals =
      (PUSHORT)((PUCHAR)MappedBase + expDir->AddressOfNameOrdinals);
  PULONG funcRvas = (PULONG)((PUCHAR)MappedBase + expDir->AddressOfFunctions);

  for (ULONG i = 0; i < expDir->NumberOfNames; i++) {
    PCSTR exportName = (PCSTR)((PUCHAR)MappedBase + nameRvas[i]);

    if (exportName[0] != 'N' || exportName[1] != 't') continue;

    ULONG ordinal = nameOrdinals[i];
    ULONG rva = funcRvas[ordinal];

    if (rva == 0) continue;

    ULONG ssn = SsnFromStub((PUCHAR)MappedBase + rva);
    if (ssn == MAXULONG) continue;

    SsnNameEntry* entry = &g_ssn_table.entries[g_ssn_table.length++];
    entry->syscall_id = (ULONG32)ssn;
    RtlCopyMemory(entry->name, exportName,
                  min(strlen(exportName), sizeof(entry->name) - 1));
    entry->name[sizeof(entry->name) - 1] = '\0';
    HYPERPLATFORM_LOG_DEBUG("Resolved %s %Xh", entry->name, entry->syscall_id);
  }

  return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// Test hooks
// ---------------------------------------------------------------------------

#define PROT_PREFIX L"prot"
#define PROT_PREFIX_LEN (sizeof(PROT_PREFIX) / sizeof(WCHAR) - 1)

static bool ShouldHidePath(_In_ PCUNICODE_STRING full_path) {
  if (full_path == nullptr || full_path->Buffer == nullptr) return false;

  // extract filename component after last backslash
  PWCH buf = full_path->Buffer;
  ULONG len = full_path->Length / sizeof(WCHAR);
  ULONG last_slash = 0;

  for (ULONG i = 0; i < len; i++)
    if (buf[i] == L'\\') last_slash = i + 1;

  UNICODE_STRING filename = {(USHORT)((len - last_slash) * sizeof(WCHAR)),
                             (USHORT)((len - last_slash) * sizeof(WCHAR)),
                             buf + last_slash};

  if (filename.Length < PROT_PREFIX_LEN * sizeof(WCHAR)) return false;

  UNICODE_STRING prefix;
  RtlInitUnicodeString(&prefix, PROT_PREFIX);

  UNICODE_STRING name_prefix = {(USHORT)(PROT_PREFIX_LEN * sizeof(WCHAR)),
                                (USHORT)(PROT_PREFIX_LEN * sizeof(WCHAR)),
                                filename.Buffer};

  return RtlCompareUnicodeString(&name_prefix, &prefix, TRUE) == 0;
}

static bool CheckAndHide(_In_ POBJECT_ATTRIBUTES obj_attrs,
                         _In_ GpRegisters* gp_regs,
                         _In_ const char* syscall_name) {
  __try {
    ProbeForRead(obj_attrs, sizeof(OBJECT_ATTRIBUTES), sizeof(UCHAR));
    ProbeForRead(obj_attrs->ObjectName, sizeof(UNICODE_STRING), sizeof(UCHAR));
    ProbeForRead(obj_attrs->ObjectName->Buffer, obj_attrs->ObjectName->Length,
                 sizeof(WCHAR));

    if (ShouldHidePath(obj_attrs->ObjectName)) {
      HYPERPLATFORM_LOG_DEBUG("%s protected: \"%wZ\"", syscall_name,
                              obj_attrs->ObjectName);
      gp_regs->ax = (ULONG_PTR)STATUS_NO_SUCH_FILE;
      return false;  // short-circuit
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    gp_regs->ax = (ULONG_PTR)GetExceptionCode();
    return false;
  }

  return true;  // forward
}

bool SyscallHookRoutineNtOpenFile(ULONG64 return_address,
                                  MachineFrame* machine_frame,
                                  GpRegisters* gp_regs) {
  UNREFERENCED_PARAMETER(return_address);
  UNREFERENCED_PARAMETER(machine_frame);
  return CheckAndHide((POBJECT_ATTRIBUTES)gp_regs->r8, gp_regs, "NtOpenFile");
}

bool SyscallHookRoutineNtCreateFile(ULONG64 return_address,
                                    MachineFrame* machine_frame,
                                    GpRegisters* gp_regs) {
  UNREFERENCED_PARAMETER(return_address);
  UNREFERENCED_PARAMETER(machine_frame);
  return CheckAndHide((POBJECT_ATTRIBUTES)gp_regs->r8, gp_regs, "NtCreateFile");
}

bool SyscallHookRoutineNtQuerySystemInformation(ULONG64 return_address,
  MachineFrame* machine_frame, GpRegisters* gp_regs) {
  UNREFERENCED_PARAMETER(return_address);
  UNREFERENCED_PARAMETER(machine_frame);

  if (gp_regs->r10 == SystemFirmwareTableInformation) {
    // minimum size must cover the header fields before TableBuffer
    const ULONG kHeaderSize =
        offsetof(SYSTEM_FIRMWARE_TABLE_INFORMATION, TableBuffer);

    if (gp_regs->r8 < kHeaderSize) {
      gp_regs->ax = (ULONG_PTR)STATUS_INFO_LENGTH_MISMATCH;
      return false;
    }

    PSYSTEM_FIRMWARE_TABLE_INFORMATION sfti =
        (PSYSTEM_FIRMWARE_TABLE_INFORMATION)gp_regs->dx;

    ULONG provider = 0;
    ULONG action = 0;
    ULONG table_id = 0;
    ULONG buf_len = 0;

    __try {
      ProbeForRead(sfti, kHeaderSize, sizeof(UCHAR));
      provider = sfti->ProviderSignature;
      action = (ULONG)sfti->Action;
      table_id = sfti->TableID;
      buf_len = sfti->TableBufferLength;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      gp_regs->ax = (ULONG_PTR)GetExceptionCode();
      return false;
    }

    // log the provider as a 4-char string e.g. 'RSMB', 'ACPI', 'FIRM'
    char provider_str[5] = {};
    RtlCopyMemory(provider_str, &provider, 4);

    HYPERPLATFORM_LOG_DEBUG(
        "NtQuerySystemInformation(SystemFirmwareTableInformation)"
        " provider='%s' action=%lu table_id=%08lXh buf_len=%lu",
        provider_str, action, table_id, buf_len);

    // block all firmware table queries - SMBIOS ('RSMB') and raw firmware
    // ('FIRM') both expose VM artifacts like vendor strings and OEM fields.
    // ACPI tables can also leak hypervisor presence via DSDT/SSDT signatures.
    // returning STATUS_NOT_SUPPORTED is what a locked-down environment returns
    // and is less suspicious than STATUS_ACCESS_DENIED.
    gp_regs->ax = (ULONG_PTR)STATUS_NOT_SUPPORTED;
    HYPERPLATFORM_LOG_DEBUG("blocked firmware table query provider='%s'",
                            provider_str);
    return false;
  }

  return true;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

NTSTATUS SyscallTableInitialize() {
  PAGED_CODE();
  NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

  RtlZeroMemory(g_syscall_hook_table, sizeof(g_syscall_hook_table));

  PVOID mappedBase = nullptr;
  SIZE_T viewSize = 0;

  NTSTATUS status = MapNtdll(&mappedBase, &viewSize);
  if (!NT_SUCCESS(status)) {
    HYPERPLATFORM_LOG_DEBUG("MapNtdll failed %lXh", status);
    return status;
  }

  BuildSsnTable(mappedBase);

  ZwUnmapViewOfSection(ZwCurrentProcess(), mappedBase);

  bool hooks_status = true;
  hooks_status &= SyscallTableHookSetByName( // used to bypass the vmp vm checks
     "NtQuerySystemInformation", SyscallHookRoutineNtQuerySystemInformation);
  hooks_status &= SyscallTableHookSetByName(
    "NtOpenFile", SyscallHookRoutineNtOpenFile);
  hooks_status &= SyscallTableHookSetByName(
    "NtCreateFile", SyscallHookRoutineNtCreateFile);
  HYPERPLATFORM_LOG_DEBUG("Hooks status: %x", hooks_status);

  return STATUS_SUCCESS;
}

void SyscallTableDestroy() {
  RtlZeroMemory(g_syscall_hook_table, sizeof(g_syscall_hook_table));

  if (g_ssn_table.entries != nullptr) {
    ExFreePoolWithTag(g_ssn_table.entries, SSN_POOL_TAG);
    g_ssn_table.entries = nullptr;
    g_ssn_table.length = 0;
  }
}

void SyscallTableHookSet(_In_ ULONG32 SyscallId, _In_ SyscallHookRoutine Hook) {
  NT_ASSERT(SyscallId < MAX_SYSCALL_COUNT);
  g_syscall_hook_table[SyscallId] = Hook;
}

SyscallHookRoutine
SyscallTableHookGet(_In_ ULONG32 SyscallId) {
  NT_ASSERT(SyscallId < MAX_SYSCALL_COUNT);
  return g_syscall_hook_table[SyscallId];
}

ULONG32
SyscallTableGetSyscallIdByName(_In_ PCSTR Name) {
  for (ULONG i = 0; i < g_ssn_table.length; i++) {
    if (strcmp(g_ssn_table.entries[i].name, Name) == 0)
      return g_ssn_table.entries[i].syscall_id;
  }

  return MAXULONG32;
}

PCSTR SyscallTableGetNameBySyscallId(_In_ ULONG32 SyscallId) {
  for (ULONG i = 0; i < g_ssn_table.length; i++) {
    if (g_ssn_table.entries[i].syscall_id == SyscallId)
      return g_ssn_table.entries[i].name;
  }

  return nullptr;
}

bool SyscallTableHookSetByName(_In_ PCSTR Name, _In_ SyscallHookRoutine Hook) {
  ULONG32 syscallId = SyscallTableGetSyscallIdByName(Name);
  if (syscallId == MAXULONG32) return false;

  SyscallTableHookSet(syscallId, Hook);
  return true;
}

}  // extern "C"