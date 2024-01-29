#include "identity.hpp"

char* pIdentity = (char*)(identity::mapped_host_phys_pml << 39);
unsigned long long pIdentityAsU64 = (unsigned long long)(identity::mapped_host_phys_pml << 39);

unsigned long long identity::phyToVirt(unsigned long long pa)
{
    return pIdentityAsU64 + pa;
}
