#pragma once

#include <ntddk.h>

extern "C" {
NTSTATUS ProcessTracerInitialize();

NTSTATUS ProcessTracerDestroy();

bool ProcessTracerIsProcessSandboxed();
}