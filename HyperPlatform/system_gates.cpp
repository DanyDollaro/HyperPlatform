#include "system_gates.h"
#include "Zydis.h"
#include "log.h"
#include "syscall_table.h"

extern "C" {

// defined in x64.asm
void AsmSystemGateEntryInitialize();

void SystemGatesInitialize() { AsmSystemGateEntryInitialize(); }

bool SyscallGate(ULONG64 return_address, MachineFrame* machine_frame,
  GpRegisters* gp_regs) {
  // HYPERPLATFORM_LOG_DEBUG("syscall %llXh returning at %llXh", gp_regs->ax,
  //   return_address, machine_frame->sp);

  auto syscall_hook_callback = SyscallTableHookGet(gp_regs->ax & 0xFFF);
  if (!syscall_hook_callback) {
    // forward the syscall to the original handler
    return true;
  }

  return syscall_hook_callback(return_address, machine_frame, gp_regs);
}

}
