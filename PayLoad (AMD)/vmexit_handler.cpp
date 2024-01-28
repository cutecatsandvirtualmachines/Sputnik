#include "types.h"
#include "mm.h"
#include "debug.h"

#include <communication.hpp>
#include <SELib/Vmcall.h>
#include <SELib/ia32.h>


COMMAND_DATA& GetCommand(svm::Vmcb* vmcb, UINT64 pCmd) {
	CR3 cr3 = { 0 };
	cr3.Flags = vmcb->Cr3();

	COMMAND_DATA* p = (COMMAND_DATA*)mm::map_guest_virt(cr3.AddressOfPageDirectory * 0x1000, pCmd, mm::map_type_t::map_src);
	return *p;
}

bool HandleCpuid(svm::Vmcb* vmcb, svm::pguest_context context) {
	if(
		!vmcall::IsVmcall(context->r9) 
		//|| !vmcall::IsValidKey(vmcb->Rax())
		)
		return false;

	switch (context->rcx) {
	case VMCALL_GET_CR3: {
		auto& cmd = GetCommand(vmcb, context->rdx);
		cmd.cr3.value = vmcb->Cr3();
		vmcb->Rax() = VMX_ROOT_ERROR::SUCCESS;

		break;
	}
	case VMCALL_READ_PHY: {
		auto& cmd = GetCommand(vmcb, context->rdx);
		if (!cmd.read.pOutBuf) {
			vmcb->Rax() = VMX_ROOT_ERROR::VMXROOT_TRANSLATE_FAILURE;
			break;
		}

		vmcb->Rax() = mm::read_guest_phys(vmcb->Cr3(), (u64)cmd.read.pTarget, (u64)cmd.read.pOutBuf, cmd.read.length);

		break;
	}
	case VMCALL_WRITE_PHY: {
		auto& cmd = GetCommand(vmcb, context->rdx);
		if (!cmd.write.pInBuf) {
			vmcb->Rax() = VMX_ROOT_ERROR::VMXROOT_TRANSLATE_FAILURE;
			break;
		}

		vmcb->Rax() = mm::write_guest_phys(vmcb->Cr3(), (u64)cmd.write.pTarget, (u64)cmd.write.pInBuf, cmd.read.length);

		break;
	}
	case VMCALL_READ_VIRT: {
		auto& cmd = GetCommand(vmcb, context->rdx);
		if (!cmd.read.pOutBuf || !context->r8) {
			vmcb->Rax() = VMX_ROOT_ERROR::VMXROOT_TRANSLATE_FAILURE;
			break;
		}

		vmcb->Rax() = mm::copy_guest_virt(context->r8, (u64)cmd.read.pTarget, vmcb->Cr3(), (u64)cmd.read.pOutBuf, cmd.read.length);

		break;
	}
	case VMCALL_WRITE_VIRT: {
		auto& cmd = GetCommand(vmcb, context->rdx);
		if (!cmd.write.pInBuf || !context->r8) {
			vmcb->Rax() = VMX_ROOT_ERROR::VMXROOT_TRANSLATE_FAILURE;
			break;
		}

		vmcb->Rax() = mm::copy_guest_virt(vmcb->Cr3(), (u64)cmd.write.pInBuf, context->r8, (u64)cmd.write.pTarget, cmd.write.length);

		break;
	}
	default: {
		return false;
	}
	}
	return true;
}

auto vmexit_handler(void* unknown, void* unknown2, svm::pguest_context context) -> svm::pgs_base_struct
{
	const auto vmcb = svm::get_vmcb();
	bool bIncRip = false;
	bool bHandledExit = false;

	auto mmInit = mm::init();

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
		break;
	}
	}

	if (!bHandledExit) {
		return reinterpret_cast<svm::vcpu_run_t>(
			reinterpret_cast<u64>(&vmexit_handler) -
			svm::sputnik_context.vcpu_run_rva)(unknown, unknown2, context);
	}

	if(bIncRip) 
		vmcb->StateSaveArea.Rip = vmcb->ControlArea.NextRip;

	return reinterpret_cast<svm::pgs_base_struct>(__readgsqword(0));
}