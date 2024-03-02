#include "main.h"
#include "comms.h"

#include <threading.h>

#include <libsputnik.hpp>

#pragma warning (disable:4302)
#pragma warning (disable:4311)

NTSTATUS SetEPTCache() {
    DWORD dwCore = CPU::GetCPUIndex();

    sputnik::set_ept_base(vmm::vGuestStates[dwCore].eptState.nCR3.Flags);

    return STATUS_SUCCESS;
}

NTSTATUS MapModuleToVmxRoot(identity::PhysicalAccess& phy, PPML4T pPML4) {
    VIRT_ADD_MAP virtAddMap = { 0 };
    virtAddMap.Flags = (DWORD64)winternl::pDriverBase;

    CR3 Cr3Host = { 0 };
    Cr3Host.Flags = sputnik::root_dirbase();
    Cr3Host.Flags = Cr3Host.AddressOfPageDirectory * PAGE_SIZE;

    for (int i = 256; i < 512; i++) {
        PML4E_64 pml4e = { 0 };
        auto res = sputnik::read_phys((Cr3Host.AddressOfPageDirectory * PAGE_SIZE) + (i * 8), (DWORD64)&pml4e, 8);
        if (!pml4e.Present) {
            auto writeRes = sputnik::write_phys((Cr3Host.AddressOfPageDirectory * PAGE_SIZE) + (i * 8), (DWORD64)pPML4 + (i * 8), 8);
        }
        else {
            for (int j = 0; j < 512; j++) {
                if (!pPML4->entry[j].Present)
                    continue;

                PDPTE_64* ppdpte = (PDPTE_64*)phy.phys2virt(pPML4->entry[j].PageFrameNumber * PAGE_SIZE);
                PDPTE_64 pdpte = { 0 };
                res = sputnik::read_phys((pml4e.PageFrameNumber * PAGE_SIZE) + (j * 8), (DWORD64)&pdpte, 8);
                if (!pdpte.Present) {
                    auto writeRes = sputnik::write_phys((pml4e.PageFrameNumber * PAGE_SIZE) + (j * 8), (DWORD64)ppdpte + (j * 8), 8);
                }
            }
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS SetSvmState() {
    DWORD dwCore = CPU::GetCPUIndex();

    PHYSICAL_ADDRESS phy = { 0 };
    phy.QuadPart = sputnik::vmcb();
    if(!vmm::vGuestStates[dwCore].SvmState)
        vmm::vGuestStates[dwCore].SvmState = (SVM::SVMState*)cpp::kMallocTryAllZero(sizeof(SVM::SVMState));
    vmm::vGuestStates[dwCore].SvmState->GuestVmcb = (Svm::Vmcb*)MmMapIoSpace(phy, PAGE_SIZE, MEMORY_CACHING_TYPE::MmNonCached);

    DbgMsgForce("SVM state %d: 0x%llx - %p", dwCore, phy.QuadPart, vmm::vGuestStates[dwCore].SvmState->GuestVmcb);

    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryPath) {
    SKLib::Init();
    DbgMsg("[ENTRY] Current driver name: %ls", SKLib::CurrentDriverName);

    if (!MmIsAddressValid(SKLib::pUserInfo)
        || !MmIsAddressValid(pRegistryPath)
        || !MmIsAddressValid(pDriverObj)
        //|| !MmIsAddressValid(SKLib::pUserInfo->cleanupData.pPreHv)
        ) {
        DbgMsg("[ENTRY] User info is invalid: %p", SKLib::pUserInfo);
        return SKLIB_USER_INFO_INVALID;
    }
    *SKLib::pUserInfo = *(USERMODE_INFO*)pRegistryPath;

    offsets = SKLib::pUserInfo->offsets;

    winternl::InitImageInfo(pDriverObj);

    if (SKLib::pUserInfo->pIdtCopy) {
        KeSetSystemAffinityThread(1ull << SKLib::pUserInfo->cpuIdx);
        IDTGateDescriptor64* pOrigIDT = (IDTGateDescriptor64*)CPU::GetIdtBase();
        Memory::WriteProtected(pOrigIDT, SKLib::pUserInfo->pIdtCopy, 20 * sizeof(IDTGateDescriptor64));
        DbgMsg("[POST-HV] Restored modified IDT for core: 0x%llx", SKLib::pUserInfo->cpuIdx);
        KeRevertToUserAffinityThread();

        KAFFINITY affinity = { 0 };
        affinity = (1ULL << CPU::GetCPUCount()) - 1;
        ULONG ulLen = 0;
        winternl::ZwSetInformationProcess(NtCurrentProcess(), PROCESSINFOCLASS::ProcessAffinityMask, &affinity, sizeof(affinity));
    }

    identity::Init();

    sputnik::set_vmcall_key(SKLib::pUserInfo->vmcallKey);
    DbgMsgForce("[VMCALL] Key set to: 0x%llx", SKLib::pUserInfo->vmcallKey);
    sputnik::storage_set(VMX_ROOT_STORAGE::CALLBACK_ADDRESS, comms::Entry);
    sputnik::storage_set(VMX_ROOT_STORAGE::DRIVER_BASE_PA, Memory::VirtToPhy(winternl::pDriverBase));
    sputnik::storage_set(VMX_ROOT_STORAGE::NTOSKRNL_CR3, PsProcessDirBase(PsInitialSystemProcess));

    vmm::Init();

    BOOLEAN bEptHidden = EPT::HideDriver();
    if (!bEptHidden) {
        return SKLIB_EPT_FAILED;
    }

    PROCESSOR_RUN_INFO procInfo;
    procInfo.Flags = ~0ull;
    procInfo.bHighIrql = FALSE;

    DWORD64 dwTest = 0;
    if (!NT_SUCCESS(CPU::RunOnAllCPUs(sputnik::read_phys, procInfo, 0, (DWORD64)&dwTest, 8)))
        return SKLIB_SETUP_FAILED;

    if (!comms::Init()) {
        DbgMsg("[COMMS] Failed init!");
        return SKLIB_LOAD_FAILED;
    }

    if (MmIsAddressValid(SKLib::pUserInfo->cleanupData.pPreHv)) {
        threading::Sleep(1000);
        PE pe(SKLib::pUserInfo->cleanupData.pPreHv);
        RtlZeroMemory(SKLib::pUserInfo->cleanupData.pPreHv, pe.imageSize());
        ExFreePool(SKLib::pUserInfo->cleanupData.pPreHv);
        DbgMsg("[CLEANUP] Cleaned up pre-hv driver!");
    }

    sputnik::set_ept_handler((sputnik::guest_virt_t)EPT::HandlePageHookExit);
    DbgMsg("Handler set success: 0x%llx", EPT::HandlePageHookExit);

    if (!NT_SUCCESS(CPU::RunOnAllCPUs(SetSvmState, procInfo)))
        return SKLIB_SETUP_FAILED;

    auto pPML4 = paging::CopyPML4Mapping();

    CR3 newCR3 = { 0 };
    newCR3.Flags = __readcr3();
    newCR3.AddressOfPageDirectory = Memory::VirtToPhy(pPML4) >> 12;

    constexpr u64 mapped_host_phys_pml = 360;

    vmm::pIdentityMap = (PVOID)((mapped_host_phys_pml << 39L) | 0xffff000000000000);
    vmm::hostCR3 = newCR3;

    {
        identity::PhysicalAccess phy;
        if (!NT_SUCCESS(CPU::RunOnAllCPUs(MapModuleToVmxRoot, procInfo, phy, pPML4)))
            return SKLIB_SETUP_FAILED;
    }

    if (!NT_SUCCESS(CPU::RunOnAllCPUs(SetEPTCache, procInfo)))
        return SKLIB_SETUP_FAILED;

    return STATUS_SUCCESS;
}