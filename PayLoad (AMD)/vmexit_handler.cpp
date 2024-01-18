#include "types.h"
#include "mm.h"
#include "vmexit.h"
#include "debug.h"

auto vmexit_handler(void* unknown, void* unknown2, svm::pguest_context context) -> svm::pgs_base_struct
{
	const auto vmcb = svm::get_vmcb();
	bool bIncRip = false;
	bool bHandledExit = false;

	switch (vmcb->ControlArea.ExitCode) {
	case svm::SvmExitCode::VMEXIT_CPUID: {
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