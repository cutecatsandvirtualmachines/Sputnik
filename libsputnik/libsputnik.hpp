#pragma once
#include <intrin.h>
#include <type_traits>

#include <communication.hpp>

#define PAGE_4KB 0x1000
#define PAGE_2MB PAGE_4KB * 512
#define PAGE_1GB PAGE_2MB * 512

using u8 = unsigned char;
using u16 = unsigned short;
using u32 = unsigned int;
using u64 = unsigned long long;

namespace sputnik
{
	// code comments itself...
	using guest_virt_t = u64;
	using guest_phys_t = u64;
	using host_virt_t = u64;
	using host_phys_t = u64;

	void set_vmcall_key(u64 key);

	/// <summary>
	/// this function is used to cause a vmexit as though its calling a function...
	/// </summary>
	extern "C" auto hypercall(u64 code, PCOMMAND_DATA param1, u64 param2, u64 key) -> VMX_ROOT_ERROR;

	/// <summary>
	/// gets the current cores CR3 value (current address space pml4)...
	/// </summary>
	/// <returns>returns the guest cr3 value...</returns>
	auto current_dirbase() -> guest_phys_t;

	/// <summary>
	/// reads guest physical memory...
	/// </summary>
	/// <param name="phys_addr">physical address to read...</param>
	/// <param name="buffer">buffer (guest virtual address) to read into...</param>
	/// <param name="size">number of bytes to read (can only be 0x1000 or less)...</param>
	/// <returns>STATUS_SUCCESS if the read was successful...</returns>
	auto read_phys(guest_phys_t phys_addr, guest_virt_t buffer, u64 size) -> VMX_ROOT_ERROR;

	/// <summary>
	/// write guest physical memory...
	/// </summary>
	/// <param name="phys_addr">physical address to read</param>
	/// <param name="buffer">guest virtual address to write from...</param>
	/// <param name="size">number of bytes to write</param>
	/// <returns></returns>
	auto write_phys(guest_phys_t phys_addr, guest_virt_t buffer, u64 size) -> VMX_ROOT_ERROR;

	auto read_virt(guest_virt_t virt_addr, guest_virt_t buffer, u64 size, u64 target_cr3) -> VMX_ROOT_ERROR;

	auto write_virt(guest_virt_t virt_addr, guest_virt_t buffer, u64 size, u64 target_cr3) -> VMX_ROOT_ERROR;

	auto current_ept_base() -> guest_phys_t;

	auto malloc_locked(u64 size) -> guest_virt_t;

	auto malloc_locked_aligned(u64 size, u64 alignment) -> guest_virt_t;

	auto free_locked(guest_virt_t p);

	auto virt_to_phy(guest_virt_t p, u64 dirbase = 0) -> guest_phys_t;
}