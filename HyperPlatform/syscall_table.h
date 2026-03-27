#pragma once

#include <ntddk.h>
#include <ntimage.h>

#include "vmm.h"
#include "ia32_type.h"

extern "C" {

typedef bool (*SyscallHookRoutine)(ULONG64 return_address, MachineFrame* machine_frame,
    GpRegisters* gp_regs);

NTSTATUS
SyscallTableInitialize();

void
SyscallTableDestroy();

void
SyscallTableHookSet(
    _In_ ULONG32            SyscallId,
    _In_ SyscallHookRoutine Hook
);

SyscallHookRoutine
SyscallTableHookGet(
    _In_ ULONG32 SyscallId
);

ULONG32
SyscallTableGetSyscallIdByName(
    _In_ PCSTR Name
);

PCSTR SyscallTableGetNameBySyscallId(
    _In_ ULONG32 SyscallId
);

bool SyscallTableHookSetByName(
    _In_ PCSTR Name,
    _In_ SyscallHookRoutine Hook
);


} // extern "C"