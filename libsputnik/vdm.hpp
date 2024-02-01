#pragma once

#include <windows.h>
#include <cstdint>
#include <iostream>
#include <string>
#include <filesystem>
#include <atlstr.h>
#include <winternl.h>

#include "libsputnik.hpp"
#include <ntstatus.h>

#define TARGET_CR3_SYSTEM 0

class SELibVdm {
	ULONG64 _callbackAddress;
	ULONG64 _ntoskrnlAddress;

	ULONG64 _gameCr3;

	static constexpr auto SystemModuleInformation = 11;
	static constexpr auto SystemHandleInformation = 16;
	static constexpr auto SystemExtendedHandleInformation = 64;

	typedef struct _RTL_PROCESS_MODULE_INFORMATION
	{
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		DWORD32 ImageSize;
		DWORD32 Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR FullPathName[256];
	} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

	typedef struct _RTL_PROCESS_MODULES
	{
		DWORD32 NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[1];
	} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

public:
	SELibVdm() {
		_callbackAddress = 0;
		_ntoskrnlAddress = 0;
		_gameCr3 = 0;
	}

	SELibVdm(ULONG64 sklibKey, ULONG64 callbackAddress, ULONG64 cr3 = 0) {
		_callbackAddress = callbackAddress;
		_ntoskrnlAddress = GetKernelModuleAddress("ntoskrnl.exe");
		_gameCr3 = cr3;
	}

	__forceinline void Init(ULONG64 callbackAddress, ULONG64 cr3 = 0) {
		_callbackAddress = callbackAddress;
		_ntoskrnlAddress = GetKernelModuleAddress("ntoskrnl.exe");
		_gameCr3 = cr3;
	}

	__forceinline BOOLEAN ReadMemory(ULONG64 Source, PVOID Destination, SIZE_T NumberOfBytes, ULONG64 cr3 = ~0ull)
	{
		return sputnik::read_virt((ULONG64)Destination, Source, NumberOfBytes, cr3 != ~0ull ? cr3 : _gameCr3) == 0;
	}

	__forceinline BOOLEAN WriteMemory(ULONG64 Destination, PVOID Source, SIZE_T NumberOfBytes, ULONG64 cr3 = ~0ull)
	{
		return sputnik::write_virt(Destination, (ULONG64)Source, NumberOfBytes, cr3 != ~0ull ? cr3 : _gameCr3) == 0;
	}

	__forceinline BOOLEAN CallbackInvoke(PVOID pContext) {
		if (!_callbackAddress) {
			return FALSE;
		}

		NTSTATUS ntStatus = -1;
		BOOLEAN bRes = CallKernelFunction(&ntStatus, _callbackAddress, pContext);
		return bRes && (ntStatus == 0);
	}

	__forceinline void SetCR3(ULONG64 cr3) {
		_gameCr3 = cr3;
	}

	template<typename T, typename ...A>
	BOOLEAN CallKernelFunction(T* out_result, ULONG64 kernel_function_address, const A ...arguments) {
		constexpr auto call_void = std::is_same_v<T, void>;

		if constexpr (!call_void) {
			if (!out_result)
				return false;
		}
		else {
			UNREFERENCED_PARAMETER(out_result);
		}

		if (!kernel_function_address)
			return false;

		// Setup function call
		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (ntdll == 0) {
			return false;
		}

		const auto NtAddAtom = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtAddAtom"));
		if (!NtAddAtom)
		{
			return false;
		}

		uint8_t kernel_injected_jmp[] = {
			0x48, 0x83, 0xec, 0x38,										//sub rsp, 38h
			0x48, 0xc7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00,	0x00,		//mov qword ptr[rsp + 30h], 0h
			0x48, 0xc7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00,	0x00,		//mov qword ptr[rsp + 28h], 0h
			0x48, 0xc7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00,	0x00,		//mov qword ptr[rsp + 20h], 0h
			0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //movabs rax, 0
			0xff, 0xd0,													//call rax
			0x48, 0x83, 0xc4, 0x38,										//add rsp, 38h
			0xc3														//ret
		};
		uint8_t original_kernel_function[sizeof(kernel_injected_jmp)];
		*(ULONG64*)&kernel_injected_jmp[33] = kernel_function_address;

		static ULONG64 kernel_NtAddAtom = GetKernelModuleExport("NtAddAtom");
		if (!kernel_NtAddAtom) {
			return false;
		}

		if (!ReadMemory(kernel_NtAddAtom, &original_kernel_function, sizeof(kernel_injected_jmp), TARGET_CR3_SYSTEM)) {
			return false;
		}

		// Overwrite the pointer with kernel_function_address
		if (!WriteMemory(kernel_NtAddAtom, &kernel_injected_jmp, sizeof(kernel_injected_jmp), TARGET_CR3_SYSTEM)) {
			return false;
		}

		// Call function
		if constexpr (!call_void) {
			using FunctionFn = T(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

			*out_result = Function(arguments...);
		}
		else {
			using FunctionFn = void(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

			Function(arguments...);
		}

		// Restore the pointer/jmp
		return WriteMemory(kernel_NtAddAtom, original_kernel_function, sizeof(kernel_injected_jmp), TARGET_CR3_SYSTEM);
	}

	__forceinline ULONG64 GetKernelModuleExport(const std::string& function_name) {
		if (!_ntoskrnlAddress)
			return 0;

		IMAGE_DOS_HEADER dos_header = { 0 };
		IMAGE_NT_HEADERS64 nt_headers = { 0 };

		if (!ReadMemory(_ntoskrnlAddress, &dos_header, sizeof(dos_header), TARGET_CR3_SYSTEM) || (dos_header.e_magic != IMAGE_DOS_SIGNATURE) ||
			!ReadMemory(_ntoskrnlAddress + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers), TARGET_CR3_SYSTEM) || (nt_headers.Signature != IMAGE_NT_SIGNATURE))
		{
			return 0;
		}

		const auto export_base = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		const auto export_base_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

		if (!export_base || !export_base_size)
		{
			return 0;
		}

		const auto export_data = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(VirtualAlloc(nullptr, export_base_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		memset(export_data, 0, export_base_size);
		if (!ReadMemory(_ntoskrnlAddress + export_base, export_data, export_base_size, TARGET_CR3_SYSTEM))
		{
			VirtualFree(export_data, 0, MEM_RELEASE);
			return 0;
		}

		const auto delta = reinterpret_cast<ULONG64>(export_data) - export_base;

		const auto name_table = reinterpret_cast<ULONG32*>(export_data->AddressOfNames + delta);
		const auto ordinal_table = reinterpret_cast<UINT16*>(export_data->AddressOfNameOrdinals + delta);
		const auto function_table = reinterpret_cast<ULONG32*>(export_data->AddressOfFunctions + delta);

		for (auto i = 0u; i < export_data->NumberOfNames; ++i) {
			const std::string current_function_name = std::string(reinterpret_cast<char*>(name_table[i] + delta));

			if (!_stricmp(current_function_name.c_str(), function_name.c_str())) {
				const auto function_ordinal = ordinal_table[i];
				if (function_table[function_ordinal] <= 0x1000) {
					// Wrong function address?
					return 0;
				}
				const auto function_address = _ntoskrnlAddress + function_table[function_ordinal];

				if (function_address >= _ntoskrnlAddress + export_base && function_address <= _ntoskrnlAddress + export_base + export_base_size) {
					VirtualFree(export_data, 0, MEM_RELEASE);
					return 0; // No forwarded exports on 64bit?
				}

				VirtualFree(export_data, 0, MEM_RELEASE);
				return function_address;
			}
		}

		VirtualFree(export_data, 0, MEM_RELEASE);
		return 0;
	}

	__forceinline ULONG64 GetKernelModuleAddress(const std::string& module_name) {
		void* buffer = nullptr;
		DWORD buffer_size = 0;

		NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation), buffer, buffer_size, &buffer_size);

		while (status == STATUS_INFO_LENGTH_MISMATCH) {
			buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation), buffer, buffer_size, &buffer_size);
		}

		if (!NT_SUCCESS(status)) {
			if (buffer != nullptr)
				VirtualFree(buffer, 0, MEM_RELEASE);
			return 0;
		}

		const auto modules = static_cast<PRTL_PROCESS_MODULES>(buffer);
		if (!modules)
			return 0;

		for (auto i = 0u; i < modules->NumberOfModules; ++i) {
			const std::string current_module_name = std::string(reinterpret_cast<char*>(modules->Modules[i].FullPathName) + modules->Modules[i].OffsetToFileName);

			if (!_stricmp(current_module_name.c_str(), module_name.c_str()))
			{
				const ULONG64 result = reinterpret_cast<ULONG64>(modules->Modules[i].ImageBase);

				VirtualFree(buffer, 0, MEM_RELEASE);
				return result;
			}
		}

		VirtualFree(buffer, 0, MEM_RELEASE);
		return 0;
	}
};

