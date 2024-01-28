#include "libsputnik.hpp"
#include <Windows.h>
#include <iostream>

UINT64 VMEXIT_KEY = 0;

void sputnik::set_vmcall_key(u64 key)
{
    VMEXIT_KEY = key;
}

auto sputnik::current_dirbase()->guest_phys_t
{
    COMMAND_DATA* command = (COMMAND_DATA*)_aligned_malloc(sizeof(COMMAND_DATA), 0x1000);
    memset(command, 0, sizeof(*command));
    auto result = hypercall(VMCALL_TYPE::VMCALL_GET_CR3, command, 0, VMEXIT_KEY);
    UINT64 cr3 = command->cr3.value;
    _aligned_free(command);

    if (result != VMX_ROOT_ERROR::SUCCESS)
        return {};

    return cr3;
}

auto sputnik::read_phys(guest_phys_t phys_addr, guest_virt_t buffer, u64 size) -> VMX_ROOT_ERROR
{
    COMMAND_DATA* command = (COMMAND_DATA*)_aligned_malloc(sizeof(COMMAND_DATA), 0x1000);
    command->read.length = size;
    command->read.pOutBuf = (PVOID)buffer;
    command->read.pTarget = (PVOID)phys_addr;
    auto status = hypercall(VMCALL_TYPE::VMCALL_READ_PHY, command, 0, VMEXIT_KEY);
    _aligned_free(command);
    return status;
}

auto sputnik::write_phys(guest_phys_t phys_addr, guest_virt_t buffer, u64 size) -> VMX_ROOT_ERROR
{
    COMMAND_DATA* command = (COMMAND_DATA*)_aligned_malloc(sizeof(COMMAND_DATA), 0x1000);
    command->write.length = size;
    command->write.pInBuf = (PVOID)buffer;
    command->write.pTarget = (PVOID)phys_addr;
    auto status = hypercall(VMCALL_TYPE::VMCALL_WRITE_PHY, command, 0, VMEXIT_KEY);
    _aligned_free(command);
    return status;
}

auto sputnik::read_virt(guest_virt_t virt_addr, guest_virt_t buffer, u64 size, u64 target_cr3) -> VMX_ROOT_ERROR
{
    COMMAND_DATA* command = (COMMAND_DATA*)_aligned_malloc(sizeof(COMMAND_DATA), 0x1000);
    command->read.length = size;
    command->read.pOutBuf = (PVOID)virt_addr;
    command->read.pTarget = (PVOID)buffer;
    auto status = hypercall(VMCALL_TYPE::VMCALL_READ_VIRT, command, target_cr3, VMEXIT_KEY);
    _aligned_free(command);
    return status;
}

auto sputnik::write_virt(guest_virt_t virt_addr, guest_virt_t buffer, u64 size, u64 target_cr3) -> VMX_ROOT_ERROR
{
    COMMAND_DATA* command = (COMMAND_DATA*)_aligned_malloc(sizeof(COMMAND_DATA), 0x1000);
    command->write.length = size;
    command->write.pInBuf = (PVOID)buffer;
    command->write.pTarget = (PVOID)virt_addr;
    auto status = hypercall(VMCALL_TYPE::VMCALL_WRITE_VIRT, command, target_cr3, VMEXIT_KEY);
    _aligned_free(command);
    return status;
}