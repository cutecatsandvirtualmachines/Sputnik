#pragma once
#include "PayLoad.h"

#include <SELib/Globals.h>

extern PSPUTNIK_T PayLoadDataPtr;
#define INTEL_VMEXIT_HANDLER_SIG "\x65\xC6\x04\x25\x6D\x00\x00\x00\x00\x48\x8B\x4C\x24\x00\x48\x8B\x54\x24\x00\xE8\x00\x00\x00\x00\xE9"
#define INTEL_VMEXIT_HANDLER_MASK "xxxxxxxxxxxxx?xxxx?x????x"

#define AMD_VMEXIT_HANDLER_SIG "\xE8\x00\x00\x00\x00\x48\x89\x04\x24\xE9"
#define AMD_VMEXIT_HANDLER_MASK "x????xxxxx"

static_assert(sizeof(AMD_VMEXIT_HANDLER_SIG) == sizeof(AMD_VMEXIT_HANDLER_MASK), "signature does not match mask size!");

#define HV_ALLOC_SIZE 0x1400000
static_assert(sizeof(INTEL_VMEXIT_HANDLER_SIG) == sizeof(INTEL_VMEXIT_HANDLER_MASK), "signature does not match mask size!");
static_assert(sizeof(INTEL_VMEXIT_HANDLER_SIG) == 26, "signature is invalid length!");

/// <summary>
/// manually map module into hyper-v's extended relocation section...
/// </summary>
/// <param name="SputnikData">all the data needed to map the module...</param>
/// <param name="ImageBase">base address of the payload...</param>
/// <returns></returns>
VOID* MapModule(PSPUTNIK_T SputnikData, VOID* ImageBase);

/// <summary>
/// hook vmexit handler...
/// </summary>
/// <param name="HypervBase">base address of hyper-v</param>
/// <param name="HypervSize">hyper-v size (SizeOfImage in memory)</param>
/// <param name="VmExitHook">vmexit hook function address (where to jump too)</param>
/// <returns></returns>
VOID* HookVmExit(VOID* HypervBase, VOID* HypervSize, VOID* VmExitHook);

/// <summary>
/// populates a SPUTNIK_T structure passed by reference...
/// </summary>
/// <param name="SputnikData">pass by ref SPUTNIK_T...</param>
/// <param name="HypervAlloc">hyper-v module base...</param>
/// <param name="HypervAllocSize">hyper-v module size...</param>
/// <param name="PayLoadBase">payload base address...</param>
/// <param name="PayLoadSize">payload module size...</param>
VOID MakeSputnikData
(
	PSPUTNIK_T SputnikData,
	VOID* HypervAlloc,
	UINT64 HypervAllocSize,
	VOID* PayLoadBase,
	UINT64 PayLoadSize
);