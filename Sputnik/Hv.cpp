#include "Hv.h"
#include <SELib/Identity.h>

PSPUTNIK_T PayLoadDataPtr = NULL;
VOID* MapModule(PSPUTNIK_T SputnikData, VOID* ImageBase)
{
	if (!SputnikData || !ImageBase)
		return NULL;

	UINT8* base = (UINT8*)ImageBase;
	EFI_IMAGE_DOS_HEADER* dosHeaders = (EFI_IMAGE_DOS_HEADER*)base;
	if (dosHeaders->e_magic != EFI_IMAGE_DOS_SIGNATURE)
		return NULL;

	EFI_IMAGE_NT_HEADERS64* ntHeaders = (EFI_IMAGE_NT_HEADERS64*)(base + dosHeaders->e_lfanew);
	if (ntHeaders->Signature != EFI_IMAGE_NT_SIGNATURE)
		return NULL;

	MemCopy((UINT8*)SputnikData->ModuleBase, base, ntHeaders->OptionalHeader.SizeOfHeaders);
	EFI_IMAGE_SECTION_HEADER* sections = (EFI_IMAGE_SECTION_HEADER*)((UINT8*)&ntHeaders->OptionalHeader + ntHeaders->FileHeader.SizeOfOptionalHeader);
	for (UINT32 i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) 
	{
		EFI_IMAGE_SECTION_HEADER* section = &sections[i];
		if (section->SizeOfRawData)
		{
			MemCopy
			(
				(UINT8*)SputnikData->ModuleBase + section->VirtualAddress,
				base + section->PointerToRawData,
				section->SizeOfRawData
			);
		}
	}

	EFI_IMAGE_EXPORT_DIRECTORY* ExportDir = (EFI_IMAGE_EXPORT_DIRECTORY*)(
		SputnikData->ModuleBase + ntHeaders->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	UINT32* Address = (UINT32*)(SputnikData->ModuleBase + ExportDir->AddressOfFunctions);
	UINT32* Name = (UINT32*)(SputnikData->ModuleBase + ExportDir->AddressOfNames);
	UINT16* Ordinal = (UINT16*)(SputnikData->ModuleBase + ExportDir->AddressOfNameOrdinals);

	const int toFind = 2;
	int found = 0;
	for (UINT16 i = 0; i < ExportDir->AddressOfFunctions; i++)
	{
		if (found == toFind)
			break;

		if (AsciiStrStr((CHAR8*)SputnikData->ModuleBase + Name[i], "identity_map"))
		{
			auto& identity = *(identity::IDENTITY_MAPPING*)(SputnikData->ModuleBase + Address[Ordinal[i]]);
			identity.Init();
			found++;
		}
		else if (AsciiStrStr((CHAR8*)SputnikData->ModuleBase + Name[i], "sputnik_context"))
		{
			*(SPUTNIK_T*)(SputnikData->ModuleBase + Address[Ordinal[i]]) = *SputnikData;
			found++;
		}
	}

	// Resolve relocations
	EFI_IMAGE_DATA_DIRECTORY* baseRelocDir = &ntHeaders->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (baseRelocDir->VirtualAddress) 
	{
		EFI_IMAGE_BASE_RELOCATION* reloc = (EFI_IMAGE_BASE_RELOCATION*)(SputnikData->ModuleBase + baseRelocDir->VirtualAddress);
		for (UINT32 currentSize = 0; currentSize < baseRelocDir->Size; ) 
		{
			UINT32 relocCount = (reloc->SizeOfBlock - sizeof(EFI_IMAGE_BASE_RELOCATION)) / sizeof(UINT16);
			UINT16* relocData = (UINT16*)((UINT8*)reloc + sizeof(EFI_IMAGE_BASE_RELOCATION));
			UINT8* relocBase = (UINT8*)SputnikData->ModuleBase + reloc->VirtualAddress;

			for (UINT32 i = 0; i < relocCount; ++i, ++relocData) 
			{
				UINT16 data = *relocData;
				UINT16 type = data >> 12;
				UINT16 offset = data & 0xFFF;

				switch (type) 
				{
				case EFI_IMAGE_REL_BASED_ABSOLUTE:
					break;
				case EFI_IMAGE_REL_BASED_DIR64: 
				{
					UINT64* rva = (UINT64*)(relocBase + offset);
					*rva = (UINT64)(SputnikData->ModuleBase + (*rva - ntHeaders->OptionalHeader.ImageBase));
					break;
				}
				default:
					return NULL;
				}
			}

			currentSize += reloc->SizeOfBlock;
			reloc = (EFI_IMAGE_BASE_RELOCATION*)relocData;
		}
	}

	return (VOID*)(SputnikData->ModuleBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
}

VOID MakeSputnikData
(
	PSPUTNIK_T SputnikData,
	VOID* HypervAlloc,
	UINT64 HypervAllocSize,
	VOID* PayLoadBase,
	UINT64 PayLoadSize
)
{
	SputnikData->HypervModuleBase = (UINT64)HypervAlloc;
	SputnikData->HypervModuleSize = HypervAllocSize;
	SputnikData->ModuleBase = (UINT64)PayLoadBase;
	SputnikData->ModuleSize = PayLoadSize;

	VOID* VmExitHandler =
		FindPattern(
			HypervAlloc,
			HypervAllocSize,
			(VOID*)INTEL_VMEXIT_HANDLER_SIG,
			(VOID*)INTEL_VMEXIT_HANDLER_MASK
		);

	if (VmExitHandler)
	{
		/*
			.text:FFFFF80000237436                 mov     rcx, [rsp+arg_18] ; rcx = pointer to stack that contians all register values
			.text:FFFFF8000023743B                 mov     rdx, [rsp+arg_28]
			.text:FFFFF80000237440                 call    vmexit_c_handler	 ; RIP relative call
			.text:FFFFF80000237445                 jmp     loc_FFFFF80000237100
		*/

		UINT64 VmExitHandlerCall = ((UINT64)VmExitHandler) + 19; // + 19 bytes to -> call vmexit_c_handler
		UINT64 VmExitHandlerCallRip = (UINT64)VmExitHandlerCall + 5; // + 5 bytes because "call vmexit_c_handler" is 5 bytes
		UINT64 VmExitFunction = VmExitHandlerCallRip + *(INT32*)((UINT64)(VmExitHandlerCall + 1)); // + 1 to skip E8 (call) and read 4 bytes (RVA)
		SputnikData->VmExitHandlerRva = ((UINT64)PayLoadEntry(PayLoadBase)) - (UINT64)VmExitFunction;
	}
	else // else AMD
	{
		VOID* VmExitHandlerCall =
			FindPattern(
				HypervAlloc,
				HypervAllocSize,
				(VOID*)AMD_VMEXIT_HANDLER_SIG,
				(VOID*)AMD_VMEXIT_HANDLER_MASK
			);

		UINT64 VmExitHandlerCallRip = (UINT64)VmExitHandlerCall + 5; // + 5 bytes because "call vmexit_c_handler" is 5 bytes
		UINT64 VmExitHandlerFunc = VmExitHandlerCallRip + *(INT32*)((UINT64)VmExitHandlerCall + 1); // + 1 to skip E8 (call) and read 4 bytes (RVA)
		SputnikData->VmExitHandlerRva = ((UINT64)PayLoadEntry(PayLoadBase)) - VmExitHandlerFunc;

		UINT64 VmcbOffsetsAddr = (UINT64)FindPattern(HypervAlloc, HypervAllocSize, (VOID*)"\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x48\x8B\x88\x00\x00\x00\x00\x48\x8B\x81\x00\x00\x00\x00\x48\x8B\x88", (VOID*)"xxxxx????xxx????xxx????xxx");

		VmcbOffsetsAddr += 5;
		SputnikData->VmcbBase = *(UINT32*)VmcbOffsetsAddr;
		VmcbOffsetsAddr += 3 + 4;
		SputnikData->VmcbLink = *(UINT32*)VmcbOffsetsAddr;
		VmcbOffsetsAddr += 3 + 4;
		SputnikData->VmcbOff = *(UINT32*)VmcbOffsetsAddr;
	}
}

VOID* HookVmExit(VOID* HypervBase, VOID* HypervSize, VOID* VmExitHook)
{
	VOID* VmExitHandler =
		FindPattern(
			HypervBase,
			(UINT64)HypervSize,
			(VOID*)INTEL_VMEXIT_HANDLER_SIG,
			(VOID*)INTEL_VMEXIT_HANDLER_MASK
		);

	if (VmExitHandler)
	{
		/*
			.text:FFFFF80000237436                 mov     rcx, [rsp+arg_18] ; rcx = pointer to stack that contians all register values
			.text:FFFFF8000023743B                 mov     rdx, [rsp+arg_28]
			.text:FFFFF80000237440                 call    vmexit_c_handler	 ; RIP relative call
			.text:FFFFF80000237445                 jmp     loc_FFFFF80000237100
		*/

		UINT64 VmExitHandlerCall = ((UINT64)VmExitHandler) + 19; // + 19 bytes to -> call vmexit_c_handler
		UINT64 VmExitHandlerCallRip = (UINT64)VmExitHandlerCall + 5; // + 5 bytes because "call vmexit_c_handler" is 5 bytes
		UINT64 VmExitFunction = VmExitHandlerCallRip + *(INT32*)((UINT64)(VmExitHandlerCall + 1)); // + 1 to skip E8 (call) and read 4 bytes (RVA)
		INT32 NewVmExitRVA = ((INT64)VmExitHook) - VmExitHandlerCallRip;
		*(INT32*)((UINT64)(VmExitHandlerCall + 1)) = NewVmExitRVA;
		return (VOID*)VmExitFunction;
	}
	else // else AMD
	{
		VOID* VmExitHandlerCall =
			FindPattern(
				HypervBase,
				(UINT64)HypervSize,
				(VOID*)AMD_VMEXIT_HANDLER_SIG,
				(VOID*)AMD_VMEXIT_HANDLER_MASK
			);

		UINT64 VmExitHandlerCallRip = ((UINT64)VmExitHandlerCall) + 5; // + 5 bytes to next instructions address...
		UINT64 VmExitHandlerFunction = VmExitHandlerCallRip + *(INT32*)(((UINT64)VmExitHandlerCall) + 1); // + 1 to skip E8 (call) and read 4 bytes (RVA)
		INT32 NewVmExitHandlerRVA = ((INT64)VmExitHook) - VmExitHandlerCallRip;
		*(INT32*)((UINT64)VmExitHandlerCall + 1) = NewVmExitHandlerRVA;
		return (VOID*)VmExitHandlerFunction;
	}
}