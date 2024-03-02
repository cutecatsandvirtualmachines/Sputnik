#include "libsputnik.hpp"


UINT64 sputnik::VMEXIT_KEY = 0;

void sputnik::set_vmcall_key(u64 key)
{
    VMX_ROOT_ERROR result = VMX_ROOT_ERROR::VMXROOT_TRANSLATE_FAILURE;
    result = hypercall(VMCALL_TYPE::VMCALL_SET_COMM_KEY, 0, key, VMEXIT_KEY);
    VMEXIT_KEY = key;
}

auto sputnik::current_dirbase()->guest_phys_t
{
    COMMAND_DATA command = { 0 };
    auto result = hypercall(VMCALL_TYPE::VMCALL_GET_CR3, &command, 0, VMEXIT_KEY);

    if (result != VMX_ROOT_ERROR::SUCCESS) {
        return {};
    }

    return command.cr3.value;
}

auto sputnik::root_dirbase() -> guest_phys_t
{
    COMMAND_DATA command = { 0 };
    auto result = hypercall(VMCALL_TYPE::VMCALL_GET_CR3_ROOT, &command, 0, VMEXIT_KEY);

    if (result != VMX_ROOT_ERROR::SUCCESS) {
        return {};
    }

    return command.cr3.value;
}

auto sputnik::current_ept_base() -> guest_phys_t
{
    COMMAND_DATA command = { 0 };
    auto result = hypercall(VMCALL_TYPE::VMCALL_GET_EPT_BASE, &command, 0, VMEXIT_KEY);

    if (result != VMX_ROOT_ERROR::SUCCESS) {
        return {};
    }

    return command.cr3.value;
}

auto sputnik::vmcb() -> host_phys_t
{
    COMMAND_DATA command = { 0 };
    auto result = hypercall(VMCALL_TYPE::VMCALL_GET_VMCB, &command, 0, VMEXIT_KEY);

    if (result != VMX_ROOT_ERROR::SUCCESS) {
        return {};
    }

    return command.pa;
}

VMX_ROOT_ERROR sputnik::set_ept_base(guest_phys_t nCr3) {
    COMMAND_DATA command = { 0 };
    command.cr3.value = nCr3;
    auto result = hypercall(VMCALL_TYPE::VMCALL_SET_EPT_BASE, &command, 0, VMEXIT_KEY);
    return result;
}

void sputnik::set_ept_handler(guest_virt_t handler) {
    storage_set(EPT_HANDLER_ADDRESS, handler);
}

VMX_ROOT_ERROR sputnik::disable_ept()
{
    return hypercall(VMCALL_TYPE::VMCALL_DISABLE_EPT, 0, 0, VMEXIT_KEY);
}

VMX_ROOT_ERROR sputnik::enable_ept()
{
    return hypercall(VMCALL_TYPE::VMCALL_ENABLE_EPT, 0, 0, VMEXIT_KEY);
}

auto sputnik::read_phys(guest_phys_t phys_addr, guest_virt_t buffer, u64 size) -> VMX_ROOT_ERROR
{
    COMMAND_DATA command = { 0 };
    command.read.length = size;
    command.read.pOutBuf = (PVOID)buffer;
    command.read.pTarget = (PVOID)phys_addr;
    return hypercall(VMCALL_TYPE::VMCALL_READ_PHY, &command, 0, VMEXIT_KEY);
}

auto sputnik::write_phys(guest_phys_t phys_addr, guest_virt_t buffer, u64 size) -> VMX_ROOT_ERROR
{
    COMMAND_DATA command = { 0 };
    command.write.length = size;
    command.write.pInBuf = (PVOID)buffer;
    command.write.pTarget = (PVOID)phys_addr;
    return hypercall(VMCALL_TYPE::VMCALL_WRITE_PHY, &command, 0, VMEXIT_KEY);
}

auto sputnik::read_virt(guest_virt_t virt_addr, guest_virt_t buffer, u64 size, u64 target_cr3) -> VMX_ROOT_ERROR
{
    COMMAND_DATA command = { 0 };
    command.read.length = size;
    command.read.pOutBuf = (PVOID)virt_addr;
    command.read.pTarget = (PVOID)buffer;
    return hypercall(VMCALL_TYPE::VMCALL_READ_VIRT, &command, target_cr3, VMEXIT_KEY);
}

auto sputnik::write_virt(guest_virt_t virt_addr, guest_virt_t buffer, u64 size, u64 target_cr3) -> VMX_ROOT_ERROR
{
    COMMAND_DATA command = { 0 };
    command.write.length = size;
    command.write.pInBuf = (PVOID)buffer;
    command.write.pTarget = (PVOID)virt_addr;
    return hypercall(VMCALL_TYPE::VMCALL_WRITE_VIRT, &command, target_cr3, VMEXIT_KEY);
}

auto sputnik::virt_to_phy(guest_virt_t p, u64 dirbase) -> guest_phys_t
{
    COMMAND_DATA command = { 0 };
    command.translation.va = (void*)p;
    auto status = hypercall(VMCALL_TYPE::VMCALL_VIRT_TO_PHY, &command, dirbase, VMEXIT_KEY);
    if (status != VMX_ROOT_ERROR::SUCCESS) {
        return 0;
    }
    return command.translation.pa;
}
