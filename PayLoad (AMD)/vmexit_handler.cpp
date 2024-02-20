#include "types.h"
#include "mm.h"
#include "debug.h"
#include "exception.h"

#include <communication.hpp>
#include <SELib/Vmcall.h>
#include <SELib/ia32.h>
#include <SELib/Ept.h>
#include <SELib/hvgdk.h>

bool bSetupDone = false;
bool bFirstExitSetupDone = false;

UINT64 storageData[128] = { 0 };

typedef BOOLEAN (*fnEptHandler) (UINT64 GuestPhysicalAddr);
fnEptHandler pEptHandler = 0;

COMMAND_DATA GetCommand(svm::Vmcb* vmcb, UINT64 pCmd) {
	COMMAND_DATA cmd = { 0 };
	mm::copy_guest_virt(vmcb->Cr3(), (u64)pCmd, __readcr3(), (u64)&cmd, sizeof(cmd));
	return cmd;
}

bool HandleCpuid(svm::Vmcb* vmcb, svm::pguest_context context) {
	if(!vmcall::IsVmcall(context->r9))
		return false;

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
		if (!cr3)
			cr3 = vmcb->Cr3();

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
		if (!cr3)
			cr3 = vmcb->Cr3();

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
	case VMCALL_REGISTER_EPT_HANDLER: {
		auto cmd = GetCommand(vmcb, context->rdx);
		if (!cmd.handler) {
			vmcb->Rax() = VMX_ROOT_ERROR::INVALID_GUEST_PARAM;
			break;
		}

		pEptHandler = (fnEptHandler)cmd.handler;
		vmcb->Rax() = VMX_ROOT_ERROR::SUCCESS;

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

	switch (vmcb->ControlArea.ExitCode) {
	case svm::SvmExitCode::VMEXIT_CPUID: {
		bHandledExit = HandleCpuid(vmcb, context);
		bIncRip = true;
		break;
	}
	case svm::SvmExitCode::VMEXIT_NPF: {
		break;
	}
	default: {
		if (pEptHandler) {
			bHandledExit = pEptHandler(vmcb->ControlArea.ExitInfo2);
		}
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