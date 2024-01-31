#include <Arch/Pte.h>

#include "libsputnik.hpp"

namespace identity {
	typedef struct _IDENTITY_MAPPING {
		__declspec(align(0x1000)) Pte::Tables<Pte::Mode::longMode4Level>::Pml4e pml4[512];
		__declspec(align(0x1000)) Pte::Tables<Pte::Mode::longMode4Level>::Pml4e::Pdpe<Pte::PageSize::nonPse> pdpt[512];
		__declspec(align(0x1000)) Pte::Tables<Pte::Mode::longMode4Level>::Pml4e::Pdpe<Pte::PageSize::nonPse>::Pde<Pte::PageSize::pse> pdt[512][512];
	} IDENTITY_MAPPING, * PIDENTITY_MAPPING;

	constexpr unsigned long long mapped_host_phys_pml = 0x10;

	int Init(DWORD64 cr3);
	unsigned long long phyToVirt(unsigned long long pa);
}