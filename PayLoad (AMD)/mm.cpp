#include "mm.h"
#include "debug.h"
#include <SELib/Identity.h>


#define PTI_SHIFT  12L
#define PDI_SHIFT  21L
#define PPI_SHIFT  30L
#define PXI_SHIFT  39L

__declspec(dllexport) identity::IDENTITY_MAPPING identity_map;

constexpr u64 mapped_host_phys_pml = 360;

char* pIdentity = (char*)((mapped_host_phys_pml << PXI_SHIFT) | 0xffff000000000000);
u64 pIdentityAsU64 = (u64)((mapped_host_phys_pml << PXI_SHIFT) | 0xffff000000000000);

auto mm::init() -> u64
{
	cpuid_eax_01 cpuid_value;
	__cpuid((int*)&cpuid_value, 1);

	if (InitialisedIndex[(cpuid_value
		.cpuid_additional_information
		.initial_apic_id)])
	{
		return VMX_ROOT_ERROR::SUCCESS;
	}

	{
		auto mapping = &identity_map;

		hyperv_pml4[mapped_host_phys_pml].value = 0;
		hyperv_pml4[mapped_host_phys_pml].present = true;
		hyperv_pml4[mapped_host_phys_pml].writeable = true;
		hyperv_pml4[mapped_host_phys_pml].user_supervisor = true;
		hyperv_pml4[mapped_host_phys_pml].pfn = translate((UINT64)&mapping->pdpt[0]) / PAGE_SIZE;

		for (UINT64 EntryIndex = 0; EntryIndex < 512; EntryIndex++)
		{
			mapping->pdpt[EntryIndex].Flags = 0;
			mapping->pdpt[EntryIndex].Present = true;
			mapping->pdpt[EntryIndex].Write = true;
			mapping->pdpt[EntryIndex].Supervisor = true;
			mapping->pdpt[EntryIndex].PageFrameNumber = translate((UINT64)&mapping->pdt[EntryIndex][0]) / PAGE_SIZE;
		}

		for (UINT64 EntryGroupIndex = 0; EntryGroupIndex < 512; EntryGroupIndex++)
		{
			for (UINT64 EntryIndex = 0; EntryIndex < 512; EntryIndex++)
			{
				mapping->pdt[EntryGroupIndex][EntryIndex].Flags = 0;
				mapping->pdt[EntryGroupIndex][EntryIndex].Present = true;
				mapping->pdt[EntryGroupIndex][EntryIndex].Write = true;
				mapping->pdt[EntryGroupIndex][EntryIndex].LargePage = true;
				mapping->pdt[EntryGroupIndex][EntryIndex].Supervisor = true;
				mapping->pdt[EntryGroupIndex][EntryIndex].PageFrameNumber = (EntryGroupIndex * 512) + EntryIndex;
			}
		}

		mapping->pa = translate((UINT64)mapping->pml4);
	}

	volatile CR3 cr3 = { 0 };
	cr3.Flags = __readcr3();
	__writecr3(cr3.Flags);

	int* p = (int*)map_guest_phys(0x200000);
	volatile int test = *p;

	InitialisedIndex[(cpuid_value
		.cpuid_additional_information
		.initial_apic_id)] = 1;

	return VMX_ROOT_ERROR::SUCCESS;
}

auto mm::map_guest_phys(guest_phys_t phys_addr, map_type_t map_type) -> u64
{
	//const auto host_phys =
		//translate_guest_physical(
			//phys_addr, map_type);

	//if (!host_phys)
		//return {};

	return map_page(phys_addr, map_type);
}

auto mm::map_guest_virt(guest_phys_t dirbase, guest_virt_t virt_addr, map_type_t map_type) -> u64
{
	const auto guest_phys = 
		translate_guest_virtual(
			dirbase, virt_addr, map_type);

	if (!guest_phys)
		return {};

	return map_guest_phys(guest_phys, map_type);
}

auto mm::map_page(host_phys_t phys_addr, map_type_t map_type) -> u64
{
	return pIdentityAsU64 + phys_addr;
}

auto mm::translate(host_virt_t host_virt) -> u64
{
	__try {
		virt_addr_t virt_addr{ host_virt };
		virt_addr_t cursor{ (u64)hyperv_pml4 };

		if (!reinterpret_cast<ppml4e>(cursor.value)[virt_addr.pml4_index].present)
			return 0;

		cursor.pt_index = virt_addr.pml4_index;
		if (!reinterpret_cast<ppdpte>(cursor.value)[virt_addr.pdpt_index].present)
			return 0;

		// handle 1gb large page...
		if (reinterpret_cast<ppdpte>(cursor.value)[virt_addr.pdpt_index].large_page)
			return (reinterpret_cast<ppdpte>(cursor.value)
				[virt_addr.pdpt_index].pfn << 30) + virt_addr.offset_1gb;

		cursor.pd_index = virt_addr.pml4_index;
		cursor.pt_index = virt_addr.pdpt_index;
		if (!reinterpret_cast<ppde>(cursor.value)[virt_addr.pd_index].present)
			return 0;

		// handle 2mb large page...
		if (reinterpret_cast<ppde>(cursor.value)[virt_addr.pd_index].large_page)
			return (reinterpret_cast<ppde>(cursor.value)
				[virt_addr.pd_index].pfn << 21) + virt_addr.offset_2mb;

		cursor.pdpt_index = virt_addr.pml4_index;
		cursor.pd_index = virt_addr.pdpt_index;
		cursor.pt_index = virt_addr.pd_index;
		if (!reinterpret_cast<ppte>(cursor.value)[virt_addr.pt_index].present)
			return 0;

		return (reinterpret_cast<ppte>(cursor.value)
			[virt_addr.pt_index].pfn << 12) + virt_addr.offset_4kb;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return 0;
	}
}

auto mm::translate_guest_virtual(guest_phys_t dirbase, guest_virt_t guest_virt, map_type_t map_type) -> u64
{
	CR3 cr3 = { 0 };
	cr3.Flags = dirbase;
	dirbase = cr3.AddressOfPageDirectory * 0x1000;
	virt_addr_t virt_addr{ guest_virt };

	const auto pml4 =
		reinterpret_cast<pml4e*>(
			map_guest_phys(dirbase, map_type));

	if (!pml4 || !pml4[virt_addr.pml4_index].present)
		return {};

	const auto pdpt =
		reinterpret_cast<pdpte*>(map_guest_phys(
			pml4[virt_addr.pml4_index].pfn << 12, map_type));

	if (!pdpt || !pdpt[virt_addr.pdpt_index].present)
		return {};

	// handle 1gb pages...
	if (pdpt[virt_addr.pdpt_index].large_page)
		return (pdpt[virt_addr.pdpt_index].pfn << 12) + virt_addr.offset_1gb;

	const auto pd =
		reinterpret_cast<pde*>(map_guest_phys(
			pdpt[virt_addr.pdpt_index].pfn << 12, map_type));

	if (!pd || !pd[virt_addr.pd_index].present)
		return {};

	// handle 2mb pages...
	if (pd[virt_addr.pd_index].large_page)
		return (pd[virt_addr.pd_index].pfn << 12) + virt_addr.offset_2mb;

	const auto pt =
		reinterpret_cast<pte*>(map_guest_phys(
			pd[virt_addr.pd_index].pfn << 12, map_type));

	if (!pt || !pt[virt_addr.pt_index].present)
		return {};

	return (pt[virt_addr.pt_index].pfn << 12) + virt_addr.offset_4kb;
}

auto mm::translate_guest_physical(guest_phys_t phys_addr, map_type_t map_type) -> u64
{
	phys_addr_t guest_phys{ phys_addr };
	const auto vmcb = svm::get_vmcb();

	const auto npt_pml4 = 
		reinterpret_cast<pnpt_pml4e>(
			map_page(vmcb->NestedPageTableCr3(), map_type));

	if (!npt_pml4[guest_phys.pml4_index].present)
		return {};

	const auto npt_pdpt = 
		reinterpret_cast<pnpt_pdpte>(
			map_page(npt_pml4[guest_phys.pml4_index].pfn << 12, map_type));

	if (!npt_pdpt[guest_phys.pdpt_index].present)
		return {};

	const auto npt_pd = 
		reinterpret_cast<pnpt_pde>(
			map_page(npt_pdpt[guest_phys.pdpt_index].pfn << 12, map_type));

	if (!npt_pd[guest_phys.pd_index].present)
		return {};

	// handle 2mb pages...
	if (reinterpret_cast<pnpt_pde_2mb>(npt_pd)[guest_phys.pd_index].large_page)
		return (reinterpret_cast<pnpt_pde_2mb>(npt_pd)
			[guest_phys.pd_index].pfn << 21) + guest_phys.offset_2mb;

	const auto npt_pt =
		reinterpret_cast<pnpt_pte>(
			map_page(npt_pd[guest_phys.pd_index].pfn << 12, map_type));

	if (!npt_pt[guest_phys.pt_index].present)
		return {};

	return (npt_pt[guest_phys.pt_index].pfn << 12) + guest_phys.offset_4kb;
}

auto mm::read_guest_phys(guest_phys_t dirbase, guest_phys_t guest_phys,
	guest_virt_t guest_virt, u64 size) -> VMX_ROOT_ERROR
{
	// handle reading over page boundaries of both src and dest...
	while (size)
	{
		auto dest_current_size = PAGE_4KB - 
			virt_addr_t{ guest_virt }.offset_4kb;

		if (size < dest_current_size)
			dest_current_size = size;

		auto src_current_size = PAGE_4KB - 
			phys_addr_t{ guest_phys }.offset_4kb;

		if (size < src_current_size)
			src_current_size = size;

		auto current_size = 
			min(dest_current_size, src_current_size);

		const auto mapped_dest =
			reinterpret_cast<void*>(
				map_guest_virt(dirbase, guest_virt, map_type_t::map_dest));

		if (!mapped_dest)
			return VMX_ROOT_ERROR::INVALID_GUEST_VIRTUAL;

		const auto mapped_src =
			reinterpret_cast<void*>(
				map_guest_phys(guest_phys, map_type_t::map_src));

		if (!mapped_src)
			return VMX_ROOT_ERROR::INVALID_GUEST_PHYSICAL;

		__try {
			memcpy(mapped_dest, mapped_src, current_size);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return VMX_ROOT_ERROR::PAGE_FAULT;
		}
		guest_phys += current_size;
		guest_virt += current_size;
		size -= current_size;
	}

	return VMX_ROOT_ERROR::SUCCESS;
}

auto mm::write_guest_phys(guest_phys_t dirbase, 
	guest_phys_t guest_phys, guest_virt_t guest_virt, u64 size) -> VMX_ROOT_ERROR
{
	// handle reading over page boundaries of both src and dest...
	while (size)
	{
		auto dest_current_size = PAGE_4KB -
			virt_addr_t{ guest_virt }.offset_4kb;

		if (size < dest_current_size)
			dest_current_size = size;

		auto src_current_size = PAGE_4KB -
			phys_addr_t{ guest_phys }.offset_4kb;

		if (size < src_current_size)
			src_current_size = size;

		auto current_size =
			min(dest_current_size, src_current_size);

		const auto mapped_src =
			reinterpret_cast<void*>(
				map_guest_virt(dirbase, guest_virt, map_type_t::map_src));

		if (!mapped_src)
			return VMX_ROOT_ERROR::INVALID_GUEST_VIRTUAL;

		const auto mapped_dest =
			reinterpret_cast<void*>(
				map_guest_phys(guest_phys, map_type_t::map_dest));

		if (!mapped_src)
			return VMX_ROOT_ERROR::INVALID_GUEST_PHYSICAL;

		__try {
			memcpy(mapped_dest, mapped_src, current_size);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return VMX_ROOT_ERROR::PAGE_FAULT;
		}
		guest_phys += current_size;
		guest_virt += current_size;
		size -= current_size;
	}

	return VMX_ROOT_ERROR::SUCCESS;
}

auto mm::copy_guest_virt(guest_phys_t dirbase_src, guest_virt_t virt_src,
	guest_virt_t dirbase_dest, guest_virt_t virt_dest, u64 size) -> VMX_ROOT_ERROR
{
	while (size)
	{
		auto dest_size = PAGE_4KB - virt_addr_t{ virt_dest }.offset_4kb;
		if (size < dest_size)
			dest_size = size;

		auto src_size = PAGE_4KB - virt_addr_t{ virt_src }.offset_4kb;
		if (size < src_size)
			src_size = size;

		const auto mapped_src =
			reinterpret_cast<void*>(
				map_guest_virt(dirbase_src, virt_src, map_type_t::map_src));

		if (!mapped_src)
			return VMX_ROOT_ERROR::INVALID_GUEST_VIRTUAL;

		const auto mapped_dest =
			reinterpret_cast<void*>(
				map_guest_virt(dirbase_dest, virt_dest, map_type_t::map_dest));

		if (!mapped_dest)
			return VMX_ROOT_ERROR::INVALID_GUEST_VIRTUAL;

		auto current_size = min(dest_size, src_size);
		__try {
			memcpy(mapped_dest, mapped_src, current_size);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return VMX_ROOT_ERROR::PAGE_FAULT;
		}

		virt_src += current_size;
		virt_dest += current_size;
		size -= current_size;
	}

	return VMX_ROOT_ERROR::SUCCESS;
}