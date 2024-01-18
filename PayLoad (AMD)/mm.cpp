#include "mm.h"
#include "debug.h"

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
	cpuid_eax_01 cpuid_value;
	__cpuid((int*)&cpuid_value, 1);

	mm::pt[(cpuid_value
		.cpuid_additional_information
		.initial_apic_id * 2)
			+ (unsigned)map_type].pfn = phys_addr >> 12;

	__invlpg(reinterpret_cast<void*>(
		get_map_virt(virt_addr_t{ phys_addr }.offset_4kb, map_type)));

	return get_map_virt(virt_addr_t{ phys_addr }.offset_4kb, map_type);
}

auto mm::get_map_virt(u16 offset, map_type_t map_type) -> u64
{
	cpuid_eax_01 cpuid_value;
	__cpuid((int*)&cpuid_value, 1);
	virt_addr_t virt_addr{ MAPPING_ADDRESS_BASE };

	virt_addr.pt_index = (cpuid_value
		.cpuid_additional_information
		.initial_apic_id * 2)
			+ (unsigned)map_type;

	return virt_addr.value + offset;
}

auto mm::translate(host_virt_t host_virt) -> u64
{
	virt_addr_t virt_addr{ host_virt };
	virt_addr_t cursor{ (u64)hyperv_pml4 };

	if (!reinterpret_cast<ppml4e>(cursor.value)[virt_addr.pml4_index].present)
		return {};

	cursor.pt_index = virt_addr.pml4_index;
	if (!reinterpret_cast<ppdpte>(cursor.value)[virt_addr.pdpt_index].present)
		return {};

	// handle 1gb large page...
	if (reinterpret_cast<ppdpte>(cursor.value)[virt_addr.pdpt_index].large_page)
		return (reinterpret_cast<ppdpte>(cursor.value)
			[virt_addr.pdpt_index].pfn << 30) + virt_addr.offset_1gb;

	cursor.pd_index = virt_addr.pml4_index;
	cursor.pt_index = virt_addr.pdpt_index;
	if (!reinterpret_cast<ppde>(cursor.value)[virt_addr.pd_index].present)
		return {};

	// handle 2mb large page...
	if (reinterpret_cast<ppde>(cursor.value)[virt_addr.pd_index].large_page)
		return (reinterpret_cast<ppde>(cursor.value)
			[virt_addr.pd_index].pfn << 21) + virt_addr.offset_2mb;

	cursor.pdpt_index = virt_addr.pml4_index;
	cursor.pd_index = virt_addr.pdpt_index;
	cursor.pt_index = virt_addr.pd_index;
	if (!reinterpret_cast<ppte>(cursor.value)[virt_addr.pt_index].present)
		return {};

	return (reinterpret_cast<ppte>(cursor.value)
		[virt_addr.pt_index].pfn << 12) + virt_addr.offset_4kb;
}

auto mm::translate_guest_virtual(guest_phys_t dirbase, guest_virt_t guest_virt, map_type_t map_type) -> u64
{
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

		memcpy(mapped_dest, mapped_src, current_size);
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

		memcpy(mapped_dest, mapped_src, current_size);
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
		memcpy(mapped_dest, mapped_src, current_size);

		virt_src += current_size;
		virt_dest += current_size;
		size -= current_size;
	}

	return VMX_ROOT_ERROR::SUCCESS;
}