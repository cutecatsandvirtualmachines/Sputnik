#pragma once
#include <intrin.h>
#include <communication.hpp>

#ifndef _KERNEL_MODE
#include <Windows.h>
#include <iostream>
#endif

#define PAGE_4KB 0x1000
#define PAGE_2MB PAGE_4KB * 512
#define PAGE_1GB PAGE_2MB * 512

#define STORAGE_MAX_INDEX 127

using u8 = unsigned char;
using u16 = unsigned short;
using u32 = unsigned int;
using u64 = unsigned long long;

namespace sputnik
{
	extern UINT64 VMEXIT_KEY;

	using guest_virt_t = u64;
	using guest_phys_t = u64;
	using host_virt_t = u64;
	using host_phys_t = u64;

	void set_vmcall_key(u64 key);

	/// <summary>
	/// this function is used to cause a vmexit as though its calling a function...
	/// </summary>
	extern "C" auto hypercall(u64 code, PCOMMAND_DATA param1, u64 param2, u64 key) -> VMX_ROOT_ERROR;

	template<typename T>
	auto hypercall(u64 code, T param1, u64 param2, u64 key) -> VMX_ROOT_ERROR
	{
		return hypercall(code, (PCOMMAND_DATA)param1, param2, key);
	}

	auto current_dirbase() -> guest_phys_t;

	auto root_dirbase() -> guest_phys_t;

	auto current_ept_base() -> guest_phys_t;

	auto vmcb() -> host_phys_t;

	VMX_ROOT_ERROR set_ept_base(guest_phys_t nCr3);

	void set_ept_handler(guest_virt_t handler);

	VMX_ROOT_ERROR disable_ept();

	VMX_ROOT_ERROR enable_ept();

	auto read_phys(guest_phys_t phys_addr, guest_virt_t buffer, u64 size) -> VMX_ROOT_ERROR;

	auto write_phys(guest_phys_t phys_addr, guest_virt_t buffer, u64 size) -> VMX_ROOT_ERROR;

	auto read_virt(guest_virt_t virt_addr, guest_virt_t buffer, u64 size, u64 target_cr3) -> VMX_ROOT_ERROR;

	auto write_virt(guest_virt_t virt_addr, guest_virt_t buffer, u64 size, u64 target_cr3) -> VMX_ROOT_ERROR;

	__forceinline auto malloc_locked(u64 size) -> guest_virt_t
	{
#ifndef _KERNEL_MODE
		auto p = malloc(size);
		if (!VirtualLock(p, size)) {
			if (!SetProcessWorkingSetSize(OpenProcess(PROCESS_ALL_ACCESS | PROCESS_SET_QUOTA, FALSE, GetCurrentProcessId()), 0x200 * 0x200 * 0x1000, 0x200 * 0x200 * 0x1000)) {
				if (p)
					free(p);
				return 0;
			}
			VirtualLock(p, size);
		}
		return (guest_virt_t)p;
#else
		return 0;
#endif
	}

	__forceinline auto malloc_locked_aligned(u64 size, u64 alignment) -> guest_virt_t
	{
#ifndef _KERNEL_MODE
		auto p = _aligned_malloc(size, alignment);
		if (!VirtualLock(p, size)) {
			if (!SetProcessWorkingSetSize(OpenProcess(PROCESS_ALL_ACCESS | PROCESS_SET_QUOTA, FALSE, GetCurrentProcessId()), 0x200 * 0x200 * 0x1000, 0x200 * 0x200 * 0x1000)) {
				if (p)
					free(p);
				return 0;
			}
			VirtualLock(p, size);
		}
		return (guest_virt_t)p;
#else
		return 0;
#endif
	}

	__forceinline auto free_locked(guest_virt_t p)
	{
#ifndef _KERNEL_MODE
		free((void*)p);
#endif
	}

	auto virt_to_phy(guest_virt_t p, u64 dirbase = 0) -> guest_phys_t;

	template<typename T>
	T storage_get(u64 id) {
		COMMAND_DATA data = { 0 };
		data.storage.bWrite = false;
		data.storage.id = id;
		auto status = hypercall(VMCALL_STORAGE_QUERY, &data, 0, VMEXIT_KEY);

		if (status != VMX_ROOT_ERROR::SUCCESS) {
			return T();
		}
		return (T)data.storage.uint64;
	}

	template<typename T>
	void storage_set(u64 id, T value) {
		COMMAND_DATA data = { 0 };
		data.storage.bWrite = true;
		data.storage.id = id;
		data.storage.uint64 = (UINT64)value;
		hypercall(VMCALL_STORAGE_QUERY, &data, 0, VMEXIT_KEY);
	}
}