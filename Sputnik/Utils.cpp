#include "Utils.h"

BOOLEAN CheckMask(VOID* base, VOID* pattern, VOID* mask)
{
	CHAR8* _base = (CHAR8*)base;
	CHAR8* _pattern = (CHAR8*)pattern;
	CHAR8* _mask = (CHAR8*)mask;

	for (; *_mask; ++_base, ++_pattern, ++_mask)
		if (*_mask == 'x' && *_base != *_pattern)
			return FALSE;

	return TRUE;
}

VOID* FindPattern(VOID* base, UINTN size, VOID* pattern, VOID* mask)
{
	CHAR8* _base = (CHAR8*)base;
	CHAR8* _pattern = (CHAR8*)pattern;
	CHAR8* _mask = (CHAR8*)mask;

	size -= AsciiStrLen(_mask);
	for (UINTN i = 0; i <= size; ++i)
	{
		VOID* addr = &_base[i];
		if (CheckMask(addr, pattern, mask))
			return addr;
	}
	return NULL;
}

VOID* GetExport(VOID* ModuleBase, VOID* exp)
{
	CHAR8* _base = (CHAR8*)ModuleBase;
	CHAR8* _export = (CHAR8*)exp;

	EFI_IMAGE_DOS_HEADER* dosHeaders = (EFI_IMAGE_DOS_HEADER*)_base;
	if (dosHeaders->e_magic != EFI_IMAGE_DOS_SIGNATURE)
		return NULL;

	EFI_IMAGE_NT_HEADERS64* ntHeaders = (EFI_IMAGE_NT_HEADERS64*)(_base + dosHeaders->e_lfanew);
	UINT32 exportsRva = ntHeaders->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	EFI_IMAGE_EXPORT_DIRECTORY* exports = (EFI_IMAGE_EXPORT_DIRECTORY*)(_base + exportsRva);
	UINT32* nameRva = (UINT32*)(_base + exports->AddressOfNames);

	for (UINT32 i = 0; i < exports->NumberOfNames; ++i)
	{
		CHAR8* func = (CHAR8*)(_base + nameRva[i]);
		if (AsciiStrCmp(func, _export) == 0)
		{
			UINT32* funcRva = (UINT32*)(_base + exports->AddressOfFunctions);
			UINT16* ordinalRva = (UINT16*)(_base + exports->AddressOfNameOrdinals);
			return (VOID*)(((UINT64)_base) + funcRva[ordinalRva[i]]);
		}
	}
	return NULL;
}

VOID MemCopy(VOID* dest, VOID* src, UINTN size) 
{
	for (UINT8* d = (UINT8*)dest, *s = (UINT8*)src; size--; *d++ = *s++);
}