#include "exception.h"

#include <Windows.h>

auto vmexit_handler(void* unknown, void* unknown2, svm::pguest_context context) -> svm::pgs_base_struct;

IDT exception::HostIdt = { 0 };
Seg::DescriptorTableRegister<Seg::Mode::longMode> exception::IdtReg = { 0 };

struct _HYPERV_EXIT_HANDLER_PARAMS {
    void* unknown;
    void* unknown2;
    svm::pguest_context context;
    Seg::DescriptorTableRegister<Seg::Mode::longMode> idt;
    void* rsp;
};

inline static _HYPERV_EXIT_HANDLER_PARAMS CoreParams[256] = { 0 };

void exception::SaveOrigParams(void* unknown, void* unknown2, svm::pguest_context context, Seg::DescriptorTableRegister<Seg::Mode::longMode> idt, void* rsp)
{
    auto core = CPU::ApicId();
    CoreParams[core].unknown = unknown;
    CoreParams[core].unknown2 = unknown2;
    CoreParams[core].context = context;
    CoreParams[core].idt = idt;
    CoreParams[core].rsp = rsp;
}

void exception::seh_handler_ecode_vm(PIDT_REGS_ECODE regs)
{
    auto rva = regs->rip - svm::sputnik_context.record_base;
    auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS64*>(
        svm::sputnik_context.record_base +
        reinterpret_cast<IMAGE_DOS_HEADER*>(svm::sputnik_context.record_base)->e_lfanew);

    auto exception =
        &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

    auto functions =
        reinterpret_cast<RUNTIME_FUNCTION*>(
            svm::sputnik_context.record_base + exception->VirtualAddress);

    for (auto idx = 0; idx < exception->Size / sizeof(RUNTIME_FUNCTION); ++idx)
    {
        auto function = &functions[idx];
        if (!(rva >= function->BeginAddress && rva < function->EndAddress))
            continue;

        auto unwind_info =
            reinterpret_cast<UNWIND_INFO*>(
                svm::sputnik_context.record_base + function->UnwindData);

        if (!(unwind_info->Flags & UNW_FLAG_EHANDLER))
            continue;

        auto scope_table =
            reinterpret_cast<SCOPE_TABLE*>(
                reinterpret_cast<UINT64>(&unwind_info->UnwindCode[
                    (unwind_info->CountOfCodes + 1) & ~1]) + sizeof(UINT32));

        for (UINT32 entry = 0; entry < scope_table->Count; ++entry)
        {
            auto scope_record = &scope_table->ScopeRecord[entry];
            if (rva >= scope_record->BeginAddress && rva < scope_record->EndAddress)
            {
                regs->rip = svm::sputnik_context.record_base + scope_record->JumpTarget;
                return;
            }
        }
    }

    auto core = CPU::ApicId();

    regs->rcx = (UINT64)CoreParams[core].unknown;
    regs->rdx = (UINT64)CoreParams[core].unknown2;
    regs->r8 = (UINT64)CoreParams[core].context;
    regs->rsp = (UINT64)CoreParams[core].rsp;

    regs->rip = reinterpret_cast<u64>(&vmexit_handler) - svm::sputnik_context.vcpu_run_rva;
    __lidt(&CoreParams[core].idt);
}

void exception::seh_handler_vm(PIDT_REGS regs)
{
    auto rva = regs->rip - svm::sputnik_context.record_base;
    auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS64*>(
        svm::sputnik_context.record_base +
        reinterpret_cast<IMAGE_DOS_HEADER*>(svm::sputnik_context.record_base)->e_lfanew);

    auto exception =
        &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

    auto functions =
        reinterpret_cast<RUNTIME_FUNCTION*>(
            svm::sputnik_context.record_base + exception->VirtualAddress);

    for (auto idx = 0; idx < exception->Size / sizeof(RUNTIME_FUNCTION); ++idx)
    {
        auto function = &functions[idx];
        if (!(rva >= function->BeginAddress && rva < function->EndAddress))
            continue;

        auto unwind_info =
            reinterpret_cast<UNWIND_INFO*>(
                svm::sputnik_context.record_base + function->UnwindData);

        if (!(unwind_info->Flags & UNW_FLAG_EHANDLER))
            continue;

        auto scope_table =
            reinterpret_cast<SCOPE_TABLE*>(
                reinterpret_cast<UINT64>(&unwind_info->UnwindCode[
                    (unwind_info->CountOfCodes + 1) & ~1]) + sizeof(UINT32));

        for (UINT32 entry = 0; entry < scope_table->Count; ++entry)
        {
            auto scope_record = &scope_table->ScopeRecord[entry];
            if (rva >= scope_record->BeginAddress && rva < scope_record->EndAddress)
            {
                regs->rip = svm::sputnik_context.record_base + scope_record->JumpTarget;
                return;
            }
        }
    }

    auto core = CPU::ApicId();

    regs->rcx = (UINT64)CoreParams[core].unknown;
    regs->rdx = (UINT64)CoreParams[core].unknown2;
    regs->r8 = (UINT64)CoreParams[core].context;
    regs->rsp = (UINT64)CoreParams[core].rsp;

    regs->rip = reinterpret_cast<u64>(&vmexit_handler) - svm::sputnik_context.vcpu_run_rva;
    __lidt(&CoreParams[core].idt);
}
