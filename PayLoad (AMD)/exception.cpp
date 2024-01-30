#include "exception.h"

#include <Windows.h>

IDT exception::HostIdt = { 0 };
Seg::DescriptorTableRegister<Seg::Mode::longMode> exception::IdtReg = { 0 };

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
}
