#include "identity.hpp"

char* pIdentity = (char*)(identity::mapped_host_phys_pml << 39);
unsigned long long pIdentityAsU64 = (unsigned long long)(identity::mapped_host_phys_pml << 39);

int identity::Init(DWORD64 cr3) {
	identity::IDENTITY_MAPPING* mapping = (identity::IDENTITY_MAPPING*)sputnik::malloc_locked_aligned(sizeof(identity::IDENTITY_MAPPING), 0x1000);
	RtlZeroMemory(mapping, sizeof(*mapping));

	mapping->pml4[0].layout.P = true;
	mapping->pml4[0].layout.RW = true;
	mapping->pml4[0].layout.US = true;
	mapping->pml4[0].layout.PDP = sputnik::virt_to_phy((UINT64)&mapping->pdpt[0]) / 0x1000;

	for (UINT64 EntryIndex = 0; EntryIndex < 512; EntryIndex++)
	{
		mapping->pdpt[EntryIndex].layout.P = true;
		mapping->pdpt[EntryIndex].layout.RW = true;
		mapping->pdpt[EntryIndex].layout.US = true;
		mapping->pdpt[EntryIndex].layout.PD = sputnik::virt_to_phy((UINT64)&mapping->pdt[EntryIndex][0]) / 0x1000;
	}

	for (UINT64 EntryGroupIndex = 0; EntryGroupIndex < 512; EntryGroupIndex++)
	{
		for (UINT64 EntryIndex = 0; EntryIndex < 512; EntryIndex++)
		{
			mapping->pdt[EntryGroupIndex][EntryIndex].page2Mb.P = true;
			mapping->pdt[EntryGroupIndex][EntryIndex].page2Mb.RW = true;
			mapping->pdt[EntryGroupIndex][EntryIndex].page2Mb.PS = true;
			mapping->pdt[EntryGroupIndex][EntryIndex].page2Mb.US = true;
			mapping->pdt[EntryGroupIndex][EntryIndex].page2Mb.PhysicalPageFrameNumber = (EntryGroupIndex * 512) + EntryIndex;
		}
	}

	Pte::Tables<Pte::Mode::longMode4Level>::Pml4e* ppml4 = (Pte::Tables<Pte::Mode::longMode4Level>::Pml4e*)sputnik::malloc_locked(0x1000);
	RtlZeroMemory(ppml4, 0x1000);
	if (sputnik::read_phys(cr3, (u64)ppml4, 0x1000) != VMX_ROOT_ERROR::SUCCESS) {
		return false;
	}

	ppml4[identity::mapped_host_phys_pml].raw = mapping->pml4[0].raw;
	sputnik::write_phys(cr3, (u64)ppml4, 0x1000);

	return true;
}

unsigned long long identity::phyToVirt(unsigned long long pa)
{
    return pIdentityAsU64 + pa;
}
