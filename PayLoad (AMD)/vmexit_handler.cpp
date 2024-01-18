#include "types.h"
#include "mm.h"
#include "debug.h"

#include <communication.hpp>
#include <SELib/Vmcall.h>

bool HandleCpuid(svm::Vmcb* vmcb, svm::pguest_context context) {
	if(
		!vmcall::IsVmcall(context->r9) 
		|| !vmcall::IsValidKey(vmcb->Rax())
		)
		return false;

	switch (context->rcx) {
	case VMCALL_GET_CR3: {
		vmcb->Rax() = vmcb->Cr3();
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