#include "types.h"
#include "mm.h"
#include "debug.h"
#include "exception.h"

#include <communication.hpp>
#include <SELib/Vmcall.h>
#include <SELib/ia32.h>
#include <SELib/Ept.h>
#include <SELib/hvgdk.h>
#include <Arch/Interrupts.h>

bool bSetupDone = false;
bool bCpuidVmcallCalled = false;

UINT64 storageData[128] = { 0 };

typedef BOOLEAN (*fnEptHandler) (UINT64 GuestPhysicalAddr);

COMMAND_DATA GetCommand(svm::Vmcb* vmcb, UINT64 pCmd) {
	COMMAND_DATA cmd = { 0 };
	mm::copy_guest_virt(vmcb->Cr3(), (u64)pCmd, __readcr3(), (u64)&cmd, sizeof(cmd));
	return cmd;
}

bool HandleCpuid(svm::Vmcb* vmcb, svm::pguest_context context) {
	if(!vmcall::IsVmcall(context->r9))
		return false;

	bCpuidVmcallCalled = true;

	switch (context->rcx) {
	case VMCALL_GET_CR3: {
		COMMAND_DATA cmd = { 0 };
		cmd.cr3.value = vmcb->Cr3();
		vmcb->Rax() = mm::copy_guest_virt(__readcr3(), (u64)&cmd, vmcb->Cr3(), (u64)context->rdx, sizeof(cmd));

		break;
	}
	case VMCALL_GET_CR3_ROOT: {
		COMMAND_DATA cmd = { 0 };
		cmd.cr3.value = __readcr3();
		vmcb->Rax() = mm::copy_guest_virt(__readcr3(), (u64)&cmd, vmcb->Cr3(), (u64)context->rdx, sizeof(cmd));

		break;
	}
	case VMCALL_GET_EPT_BASE: {
		COMMAND_DATA cmd = { 0 };
		cmd.cr3.value = vmcb->NestedPageTableCr3();
		vmcb->Rax() = mm::copy_guest_virt(__readcr3(), (u64)&cmd, vmcb->Cr3(), (u64)context->rdx, sizeof(cmd));
		break;
	}
	case VMCALL_SET_EPT_BASE: {
		auto cmd = GetCommand(vmcb, context->rdx);
		if (!cmd.cr3.value) {
			vmcb->Rax() = VMX_ROOT_ERROR::VMXROOT_TRANSLATE_FAILURE;
			break;
		}

		vmcb->NestedPageTableCr3() = cmd.cr3.value;
		vmcb->ControlArea.TlbControl.layout.TlbControl = 0x1;
		vmcb->ControlArea.GMETEnable = false;
		bitmap::SetBit(&storageData[EPT_OS_INIT_BITMAP], CPU::ApicId(), true);

		vmcb->Rax() = VMX_ROOT_ERROR::SUCCESS;
		break;
	}
	case VMCALL_READ_PHY: {
		auto cmd = GetCommand(vmcb, context->rdx);
		if (!cmd.read.pOutBuf) {
			vmcb->Rax() = VMX_ROOT_ERROR::VMXROOT_TRANSLATE_FAILURE;
			break;
		}

		vmcb->Rax() = mm::read_guest_phys(vmcb->Cr3(), (u64)cmd.read.pTarget, (u64)cmd.read.pOutBuf, cmd.read.length);

		break;
	}
	case VMCALL_WRITE_PHY: {
		auto cmd = GetCommand(vmcb, context->rdx);
		if (!cmd.write.pInBuf) {
			vmcb->Rax() = VMX_ROOT_ERROR::VMXROOT_TRANSLATE_FAILURE;
			break;
		}

		vmcb->Rax() = mm::write_guest_phys(vmcb->Cr3(), (u64)cmd.write.pTarget, (u64)cmd.write.pInBuf, cmd.read.length);

		break;
	}
	case VMCALL_READ_VIRT: {
		auto cmd = GetCommand(vmcb, context->rdx);
		DWORD64 cr3 = context->r8;
		if (!cr3) {
			cr3 = storageData[VMX_ROOT_STORAGE::NTOSKRNL_CR3];
		}

		if (!cmd.read.pOutBuf) {
			vmcb->Rax() = VMX_ROOT_ERROR::VMXROOT_TRANSLATE_FAILURE;
			break;
		}

		vmcb->Rax() = mm::copy_guest_virt(cr3, (u64)cmd.read.pTarget, vmcb->Cr3(), (u64)cmd.read.pOutBuf, cmd.read.length);

		break;
	}
	case VMCALL_WRITE_VIRT: {
		auto cmd = GetCommand(vmcb, context->rdx);
		DWORD64 cr3 = context->r8;
		if (!cr3) {
			cr3 = storageData[VMX_ROOT_STORAGE::NTOSKRNL_CR3];
		}

		if (!cmd.write.pInBuf) {
			vmcb->Rax() = VMX_ROOT_ERROR::VMXROOT_TRANSLATE_FAILURE;
			break;
		}

		vmcb->Rax() = mm::copy_guest_virt(vmcb->Cr3(), (u64)cmd.write.pInBuf, cr3, (u64)cmd.write.pTarget, cmd.write.length);

		break;
	}
	case VMCALL_SET_COMM_KEY: {
		vmcall::SetKey(context->r8);
		vmcb->Rax() = VMX_ROOT_ERROR::SUCCESS;
		break;
	}
	case VMCALL_VIRT_TO_PHY: {
		auto cmd = GetCommand(vmcb, context->rdx);
		if (!cmd.translation.va) {
			vmcb->Rax() = VMX_ROOT_ERROR::VMXROOT_TRANSLATE_FAILURE;
			break;
		}
		UINT64 dirBase = context->r8 ? context->r8 : vmcb->Cr3();
		cmd.translation.pa = mm::translate_guest_virtual(dirBase, (u64)cmd.translation.va);

		vmcb->Rax() = mm::copy_guest_virt(__readcr3(), (u64)&cmd, vmcb->Cr3(), (u64)context->rdx, sizeof(cmd));

		break;
	}
	case VMCALL_STORAGE_QUERY: {
		auto cmd = GetCommand(vmcb, context->rdx);
		if (cmd.storage.id > VMX_ROOT_STORAGE::MAX_STORAGE) {
			vmcb->Rax() = VMX_ROOT_ERROR::INVALID_GUEST_PARAM;
			break;
		}

		if (cmd.storage.bWrite) {
			storageData[cmd.storage.id] = cmd.storage.uint64;
		vmcb->Rax() = VMX_ROOT_ERROR::SUCCESS;
		}
		else {
			cmd.storage.uint64 = storageData[cmd.storage.id];
			vmcb->Rax() = mm::copy_guest_virt(__readcr3(), (u64)&cmd, vmcb->Cr3(), (u64)context->rdx, sizeof(cmd));
		}

		break;
	}
	case VMCALL_DISABLE_EPT: {
		vmcb->ControlArea.NpEnable = false;
		vmcb->Rax() = VMX_ROOT_ERROR::SUCCESS;
		break;
	}
	case VMCALL_ENABLE_EPT: {
		vmcb->ControlArea.NpEnable = true;
		vmcb->Rax() = VMX_ROOT_ERROR::SUCCESS;
		break;
	}
	case VMCALL_GET_VMCB: {
		auto cmd = GetCommand(vmcb, context->rdx);

		cmd.pa = mm::translate((host_virt_t)vmcb);

		vmcb->Rax() = mm::copy_guest_virt(__readcr3(), (u64)&cmd, vmcb->Cr3(), (u64)context->rdx, sizeof(cmd));
		break;
	}
	default: {
		return false;
	}
	}
	return true;
}

void RootSetup() {
	if (!bSetupDone) {
		bSetupDone = true;
		exception::HostIdt.setup(generic_interrupt_handler_vm, generic_interrupt_handler_ecode_vm);
		exception::IdtReg.BaseAddress = (uintptr_t)exception::HostIdt.get_address();
		exception::IdtReg.Limit = exception::HostIdt.get_limit();

		svm::sputnik_context.record_base = (u64)pe::FindPE();

		auto mmInit = mm::init();
		CPU::Init();
	}
}

UINT64 GetGPRNumberForCrExit(svm::Vmcb* vmcb) {
	//DbgMsg("[SVM] ExitInfo1: 0x%x", (state->GuestVmcb->ControlArea.ExitInfo1));
	//DbgMsg("[SVM] GPR number: 0x%x", (state->GuestVmcb->ControlArea.ExitInfo1 & 15));
	return (vmcb->ControlArea.ExitInfo1 & 15);
}

UINT64* GetRegisterForCrExit(svm::Vmcb* vmcb, svm::pguest_context context) {
	switch (GetGPRNumberForCrExit(vmcb)) {
	case 0:
		return &vmcb->Rax();
	case 1:
		return &context->rcx;
	case 2:
		return &context->rdx;
	case 3:
		return &context->rbx;
	case 4:
		return &vmcb->Rsp();
	case 5:
		return &context->rbp;
	case 6:
		return &context->rsi;
	case 7:
		return &context->rdi;
	case 8:
		return &context->r8;
	case 9:
		return &context->r9;
	case 10:
		return &context->r10;
	case 11:
		return &context->r11;
	case 12:
		return &context->r12;
	case 13:
		return &context->r13;
	case 14:
		return &context->r14;
	case 15:
		return &context->r15;
	default:
		return 0;
	}
}

bool HandleCr4Write(svm::Vmcb* vmcb, svm::pguest_context context) {
	UINT64* reg = GetRegisterForCrExit(vmcb, context);
	CR4 cr4;
	cr4.Flags = *reg;

	/*GP: */
	/*If an attempt is made to change CR4.PCIDE from 0 to 1 while CR3[11:0] ≠ 000H.*/
	/*If an attempt is made to write a 1 to any reserved bit in CR4.*/
	/*If an attempt is made to leave IA-32e mode by clearing CR4.PAE[bit 5].*/
	if (cr4.PcidEnable == 1)
	{
		CR3 cr3;
		cr3.Flags = vmcb->Cr3();
		if (cr3.Flags & 0xFFF) {
			return false;
		}
	}

	if (cr4.Reserved1 || cr4.Reserved2 || cr4.Reserved3 || cr4.Reserved4) {
		return false;
	}

	vmcb->StateSaveArea.Cr4 = cr4.Flags;
	return true;
}

bool HandleCr0Write(svm::Vmcb* vmcb, svm::pguest_context context) {
	UINT64* reg = GetRegisterForCrExit(vmcb, context);
	CR0 cr0;
	cr0.Flags = *reg;
	CR4 cr4;
	cr4.Flags = vmcb->StateSaveArea.Cr4;

	if (cr0.Reserved1 || cr0.Reserved2 || cr0.Reserved3 || cr0.Reserved4) {
		return false;
	}

	if (cr4.CETEnabled == 1)
	{
		cr4.CETEnabled = false;
		vmcb->StateSaveArea.Cr4 = cr4.Flags;
	}

	vmcb->StateSaveArea.Cr0 = cr0.Flags;
	return true;
}

auto vmexit_handler(void* unknown, void* unknown2, svm::pguest_context context) -> svm::pgs_base_struct
{
	RootSetup();

	Seg::DescriptorTableRegister<Seg::Mode::longMode> origIdt = { 0 };
	__sidt(&origIdt);

	exception::SaveOrigParams(unknown, unknown2, context, origIdt, _AddressOfReturnAddress());
	__lidt(&exception::IdtReg);

	const auto vmcb = svm::get_vmcb();
	bool bIncRip = false;
	bool bHandledExit = false;
	vmcb->ControlArea.TlbControl.layout.TlbControl = 0;
	if (bCpuidVmcallCalled) {
		vmcb->ControlArea.InterceptCr.rw.write.layout.WriteCr4 = false;
		vmcb->ControlArea.InterceptCr.rw.write.layout.WriteCr0 = false;
		vmcb->ControlArea.InterceptCr0WritesOther = false;
	}

	switch (vmcb->ControlArea.ExitCode) {
	case svm::SvmExitCode::VMEXIT_CPUID: {
		bHandledExit = HandleCpuid(vmcb, context);
		bIncRip = true;
		break;
	}
	case svm::SvmExitCode::VMEXIT_NPF: {
		if (storageData[EPT_HANDLER_ADDRESS]
			&& bitmap::GetBit(&storageData[EPT_OS_INIT_BITMAP], CPU::ApicId())
			) {
			auto pEptHandler = (fnEptHandler)storageData[EPT_HANDLER_ADDRESS];
			pEptHandler(vmcb->ControlArea.ExitInfo2);
			bHandledExit = true;
		}
		break;
	}
	default: {
		break;
	}
	}

	if (!bHandledExit) {
		__lidt(&origIdt);
		return reinterpret_cast<svm::vcpu_run_t>(
			reinterpret_cast<u64>(&vmexit_handler) -
			svm::sputnik_context.vcpu_run_rva)(unknown, unknown2, context);
	}

	if(bIncRip)
		vmcb->StateSaveArea.Rip = vmcb->ControlArea.NextRip;

	__lidt(&origIdt);
	return reinterpret_cast<svm::pgs_base_struct>(__readgsqword(0));
}