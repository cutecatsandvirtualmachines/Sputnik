#include "main.h"
#include "comms.h"

#include <threading.h>

#include <libsputnik.hpp>

#pragma warning (disable:4302)
#pragma warning (disable:4311)

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
    sputnik::storage_set(0, comms::Entry);

    comms::Init();

    paging::RestoreMapPage();

    winternl::FixSectionPermissions();

    if (MmIsAddressValid(SKLib::pUserInfo->cleanupData.pPreHv)) {
        threading::Sleep(1000);
        PE pe(SKLib::pUserInfo->cleanupData.pPreHv);
        RtlZeroMemory(SKLib::pUserInfo->cleanupData.pPreHv, pe.imageSize());
        ExFreePool(SKLib::pUserInfo->cleanupData.pPreHv);
        DbgMsg("[CLEANUP] Cleaned up pre-hv driver!");
    }

    return STATUS_SUCCESS;
}