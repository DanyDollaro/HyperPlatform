#include "process_tracer.h"

#include "log.h"

extern "C" {

PCWSTR g_sandboxed_processes_paths[] = {
  L"\\??\\C:\\Users\\WDKRemoteUser\\Desktop\\sand.exe",
  L"\\??\\C:\\Users\\WDKRemoteUser\\Desktop\\sand1.exe",
  L"\\??\\C:\\Users\\WDKRemoteUser\\Desktop\\sand2.exe",
  L"\\??\\C:\\Users\\WDKRemoteUser\\Desktop\\sand3.exe",
  L"\\??\\C:\\Users\\WDKRemoteUser\\Desktop\\sand4.exe",
  L"\\??\\C:\\Users\\WDKRemoteUser\\Desktop\\sand5.exe",
  L"\\??\\C:\\Users\\WDKRemoteUser\\Desktop\\sand6.exe",
  L"\\??\\C:\\Users\\WDKRemoteUser\\Desktop\\sand7.exe",
  L"" // This array MUST terminate with an empty entry
};

// Spin lock to protect sandboxed_eprocesses_head
KSPIN_LOCK sandboxed_eprocesses_lock;

// Each list entry is embedded in this structure
typedef struct _SANDBOXED_EPROCESS_ENTRY {
  LIST_ENTRY ListEntry;
  PEPROCESS Process;
  HANDLE ProcessId;
} SANDBOXED_EPROCESS_ENTRY, *PSANDBOXED_EPROCESS_ENTRY;

LIST_ENTRY sandboxed_eprocesses_head;

VOID ProcessDeletionCallback(
  _Inout_ PEPROCESS Process,
  _In_ HANDLE ProcessId
) {
  KLOCK_QUEUE_HANDLE lqh;
  KeAcquireInStackQueuedSpinLock(&sandboxed_eprocesses_lock, &lqh);

  for (PLIST_ENTRY entry = sandboxed_eprocesses_head.Flink;
       entry != &sandboxed_eprocesses_head; entry = entry->Flink) {
    PSANDBOXED_EPROCESS_ENTRY node =
        CONTAINING_RECORD(entry, SANDBOXED_EPROCESS_ENTRY, ListEntry);

    if (node->ProcessId == ProcessId) {
      HYPERPLATFORM_LOG_DEBUG(
          "Removing process from sandbox due to termination { eprocess: %llXh, "
          "id: %Xh } ",
          Process, ProcessId
      );
      RemoveEntryList(entry);
      KeReleaseInStackQueuedSpinLock(&lqh);
      ExFreePoolWithTag(node, 'cPxS');
      ObDereferenceObject(Process);
      return;
    }
  }

  KeReleaseInStackQueuedSpinLock(&lqh);
}

VOID ProcessCreationCallback(
  _Inout_ PEPROCESS Process,
  _In_ HANDLE ProcessId,
  _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
) {
  UNREFERENCED_PARAMETER(CreateInfo);

  PSANDBOXED_EPROCESS_ENTRY node = (PSANDBOXED_EPROCESS_ENTRY)ExAllocatePool2(
      POOL_FLAG_NON_PAGED, sizeof(SANDBOXED_EPROCESS_ENTRY), 'cPxS');

  if (!node) return;

  // Keep the EPROCESS alive for the lifetime of the entry
  ObReferenceObject(Process);
  node->Process = Process;
  node->ProcessId = ProcessId;
  
  KLOCK_QUEUE_HANDLE lqh;
  KeAcquireInStackQueuedSpinLock(&sandboxed_eprocesses_lock, &lqh);
  InsertTailList(&sandboxed_eprocesses_head, &node->ListEntry);
  KeReleaseInStackQueuedSpinLock(&lqh);

  HYPERPLATFORM_LOG_DEBUG("Added process to sandbox { eprocess: %llXh, id: %Xh } ", Process,
    ProcessId);
}

// Returns TRUE if the image path belongs to a sandboxed path prefix,
// or if it starts with the WSL device path (\Device\lxss), or is a
// system process (no ImageFileName / kernel address space).
static BOOLEAN ShouldSkipProcess(
  _In_ PPS_CREATE_NOTIFY_INFO CreateInfo
) {

  // Skip processes with no image path (e.g. System, Idle)
  if (!CreateInfo->ImageFileName || CreateInfo->ImageFileName->Length == 0)
    return TRUE;

  // Skip processes without a full (rooted) path
  if (CreateInfo->ImageFileName->Buffer[0] != L'\\') return TRUE;

  return FALSE;
}

static BOOLEAN IsPathSandboxed(_In_ PCUNICODE_STRING ImageFileName) {
  for (ULONG i = 0; g_sandboxed_processes_paths[i][0] != L'\0'; ++i) {
    UNICODE_STRING candidate;
    RtlInitUnicodeString(&candidate, g_sandboxed_processes_paths[i]);
    if (RtlPrefixUnicodeString(&candidate, ImageFileName, TRUE)) return TRUE;
  }
  return FALSE;
}

VOID
ProcessCreationOrDeletionCallback(
  _Inout_ PEPROCESS Process,
  _In_ HANDLE ProcessId,
  _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
) {
  if (CreateInfo) {
    if (ShouldSkipProcess(CreateInfo)) return;

    if (IsPathSandboxed(CreateInfo->ImageFileName))
      ProcessCreationCallback(Process, ProcessId, CreateInfo);
  } else {
    ProcessDeletionCallback(Process, ProcessId);
  }
}

NTSTATUS
ProcessTracerInitialize() {
  KeInitializeSpinLock(&sandboxed_eprocesses_lock);
  InitializeListHead(&sandboxed_eprocesses_head);
  return PsSetCreateProcessNotifyRoutineEx(ProcessCreationOrDeletionCallback,
                                           FALSE);
}

NTSTATUS
ProcessTracerDestroy() {
  NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(
      ProcessCreationOrDeletionCallback, TRUE);

  // Drain the list and release all references
  KLOCK_QUEUE_HANDLE lqh;
  KeAcquireInStackQueuedSpinLock(&sandboxed_eprocesses_lock, &lqh);

  while (!IsListEmpty(&sandboxed_eprocesses_head)) {
    PLIST_ENTRY entry = RemoveHeadList(&sandboxed_eprocesses_head);
    PSANDBOXED_EPROCESS_ENTRY node =
        CONTAINING_RECORD(entry, SANDBOXED_EPROCESS_ENTRY, ListEntry);

    KeReleaseInStackQueuedSpinLock(&lqh);
    ObDereferenceObject(node->Process);
    ExFreePoolWithTag(node, 'cPxS');
    KeAcquireInStackQueuedSpinLock(&sandboxed_eprocesses_lock, &lqh);
  }

  KeReleaseInStackQueuedSpinLock(&lqh);
  return status;
}

bool ProcessTracerIsProcessSandboxed() {
  PEPROCESS current = PsGetCurrentProcess();

  KLOCK_QUEUE_HANDLE lqh;
  KeAcquireInStackQueuedSpinLock(&sandboxed_eprocesses_lock, &lqh);

  for (PLIST_ENTRY entry = sandboxed_eprocesses_head.Flink;
       entry != &sandboxed_eprocesses_head; entry = entry->Flink) {
    PSANDBOXED_EPROCESS_ENTRY node =
        CONTAINING_RECORD(entry, SANDBOXED_EPROCESS_ENTRY, ListEntry);

    if (node->Process == current) {
      KeReleaseInStackQueuedSpinLock(&lqh);
      return true;
    }
  }

  KeReleaseInStackQueuedSpinLock(&lqh);
  return false;
}

}  // extern "C"