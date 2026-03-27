#pragma once

#include "ia32_type.h"
#include "vmm.h"

extern "C" {

void AsmSyscallGateEntry();

void SystemGatesInitialize();

bool SyscallGate(ULONG64 return_address, MachineFrame* machine_frame,
                 GpRegisters* gp_regs);

}
