#include "eventhandler.h"

bool bEventHandleInit = false;
vector<EVENT_INFO>* vEvents = nullptr;

NTSTATUS InsertEventHandler(ULONG64& ulOpt1, ULONG64& ulOpt2, ULONG64& ulOpt3) {
	if (!bEventHandleInit)
		return STATUS_NOT_IMPLEMENTED;

	SKLIB_EVENT_TYPE evt = (SKLIB_EVENT_TYPE)ulOpt1;
	switch (evt) {
	case EVT_DETECTION:
	{
		EVENT_INFO evtInfo;
		evtInfo.guestAddr = (PVOID)ulOpt2;
		evtInfo.guestCr3 = vmm::GetGuestCR3().Flags;
		evtInfo.type = evt;
		SKLibEvent* pEvt = (SKLibEvent*)paging::vmmhost::MapGuestToHost(vmm::GetGuestCR3().Flags, (PVOID)ulOpt2);
		if (!pEvt || vEvents->size() == vEvents->length())
			return STATUS_UNSUCCESSFUL;

		vEvents->Append(evtInfo);

		break;
	}
	default:
	{
		return STATUS_NOT_SUPPORTED;
	}
	}

	return STATUS_SUCCESS;
}

void eventhandler::Init()
{
	if (bEventHandleInit)
		return;

	if (!vEvents)
	{
		vEvents = (vector<EVENT_INFO>*)cpp::kMalloc(sizeof(*vEvents));
		RtlZeroMemory(vEvents, sizeof(*vEvents));
		vEvents->Init();
		vEvents->reserve(64);
	}

	bEventHandleInit = true;
}

void eventhandler::OnDetection()
{
	if (!bEventHandleInit)
		return;

	for (auto& evt : *vEvents) {
		if (evt.type != EVT_DETECTION)
			continue;
	
		SKLibEvent* pEvt = (SKLibEvent*)paging::vmmhost::MapGuestToHost(evt.guestCr3, evt.guestAddr);
		pEvt->Trigger();
	}
}
