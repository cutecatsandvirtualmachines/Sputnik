#include "comms.h"
#include "winternlex.h"
#include "Vmoperations.h"
#include "VTxException.h"
#include "eac.h"
#include "file.h"
#include "xor.h"
#include "threading.h"
#include <defender.h>
#include <spoof.h>
#include <timing.h>
#include <libsputnik.hpp>

#pragma warning (disable:4302)

typedef struct _RANGE_INFO {
	PVOID pBase;
	SIZE_T sz;
	PEPROCESS pEprocess;

	_RANGE_INFO() {
		RtlZeroMemory(this, sizeof(*this));
	}
	_RANGE_INFO(PVOID base, SIZE_T size, PEPROCESS process) {
		pBase = base;
		sz = size;
		pEprocess = process;
	}

	__forceinline bool operator==(_RANGE_INFO& rhs) {
		return !memcmp(&rhs, this, sizeof(rhs));
	}
	__forceinline bool operator!=(_RANGE_INFO& rhs) {
		return !(*this == rhs);
	}
} RANGE_INFO, * PRANGE_INFO;

typedef struct _CR3_TRACKING_DATA {
	PVOID imageBase;
	ULONG64* pCr3;

	__forceinline bool operator==(_CR3_TRACKING_DATA& rhs) {
		return !memcmp(&rhs, this, sizeof(rhs));
	}
	__forceinline bool operator!=(_CR3_TRACKING_DATA& rhs) {
		return !(*this == rhs);
	}
} CR3_TRACKING_DATA, * PCR3_TRACKING_DATA;

typedef struct _MOD_BACKUP_DATA {
	DWORD64 cr3;
	DWORD64 pEprocess;
	DWORD64 szMod;
	PVOID pModule;
	PVOID pBuffer;

	__forceinline bool operator==(_MOD_BACKUP_DATA& rhs) {
		return !memcmp(&rhs, this, sizeof(rhs));
	}
	__forceinline bool operator!=(_MOD_BACKUP_DATA& rhs) {
		return !(*this == rhs);
	}
} MOD_BACKUP_DATA, * PMOD_BACKUP_DATA;

vector<PROC_INFO>* vTrackedProcesses = nullptr;
vector<RANGE_INFO>* vTrackedHiddenRanges = nullptr;
#ifdef INTERNAL_FACILITY
vector<MOD_BACKUP_DATA>* vModBackups = nullptr;
#endif
bool bCommsInit = false;

winternl::fnPspInsertProcess pPspInsertProcessOrig = 0;
winternl::fnPspInsertThread pPspInsertThreadOrig = 0;
winternl::fnPspRundownSingleProcess pPspRundownSingleProcessOrig = 0;
winternl::fnNtLockVirtualMemory pNtLockVirtualMemoryOrig = 0;

HANDLE hWndDefault = 0;

#ifndef MINIMAL_BUILD
vector<BLOCKED_PROCESS_INFO>* vBlockedProcesses = nullptr;
vector<PROC_INFO>* vRestrictedProcesses = nullptr;
vector<PEPROCESS>* vProtectedProcesses = nullptr;

DWORD64 currScore = 0;
DWORD64 maxScore = 0;
DWORD64 warnScore = 0;
DWORD64 untrustedScore = 0;
DWORD64 untrustedHalfLife = 0;
DWORD64 totalUntrustScore = 0;
PBOOLEAN pDetected = 0;
PBOOLEAN pWarning = 0;
BOOLEAN bDetectNotified = false;
BOOLEAN bWarnNotified = false;
PEPROCESS callbackProcess = 0;
timing::StopWatch stopWatch;
#endif


NTSTATUS HideWndThread(PETHREAD pEthread, PROC_INFO* pProcInfo) {
	PCHAR teb = (PCHAR)winternl::PsGetThreadTeb(pEthread);
	if (!teb)
	{
		DbgMsg("[DRIVER] TEB was null: %p", pEthread);
		return STATUS_SUCCESS;
	}

	ULONG64 hwndCache[2] = { 0 };
	hwndCache[0] = (DWORD64)pProcInfo->hWnd;
	PEPROCESS Process = PsGetThreadProcess(pEthread);

	PVOID pBase = (PVOID)(teb + offsets.ClientInfo + (0x8 * offsets.HwndCache));
	if (MmIsAddressValid(teb)) {
		if (MmIsAddressValid(pBase)) {
			RtlCopyMemory(pBase, &hwndCache, sizeof(hwndCache));
			DbgMsg("[DRIVER] Hidden window: %s - %p", winternl::GetProcessImageFileName(Process), pBase);
		}
		else {
			DbgMsg("Failed hiding window for: %s - %p", winternl::GetProcessImageFileName(Process), pBase);
		}
		return STATUS_UNSUCCESSFUL;
	}
	else {
		DbgMsg("TEB invalid for: %s - %p", winternl::GetProcessImageFileName(Process), teb);
	}

	//Make sure the buffer is not crossing a page boundary
	PWRITE_DATA writeData = nullptr;
	char buffer[sizeof(WRITE_DATA) * 2] = { 0 };
	if (PAGE_ALIGN(buffer) != PAGE_ALIGN(buffer + sizeof(WRITE_DATA))) {
		writeData = (PWRITE_DATA)PAGE_ALIGN(buffer + sizeof(WRITE_DATA));
	}
	else {
		writeData = (PWRITE_DATA)buffer;
	}
	writeData->length = sizeof(hwndCache);
	writeData->pInBuf = &hwndCache;
	writeData->pTarget = pBase;

	ULONG64 cr3 = PsProcessDirBase(Process);
	NTSTATUS ntStatus = CPU::CPUIDVmCall(VMCALL_WRITE_VIRT, (ULONG64)writeData, cr3, vmcall::GetCommunicationKey());
	if (ntStatus != STATUS_SUCCESS) {
		DbgMsg("[DRIVER] Could not hide window: 0x%x - 0x%x", pProcInfo->hWnd, ntStatus);
	}
	else {
		DbgMsg("[DRIVER] Hidden window: 0x%x - %s", pProcInfo->hWnd, winternl::GetProcessImageFileName(Process));
	}
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS ThreadCallback(PEPROCESS pEprocess, PETHREAD pEthread, PVOID pContext) {
	return HideWndThread(pEthread, (PROC_INFO*)pContext);
}

NTSTATUS CountThreadCallback(PEPROCESS pEprocess, PETHREAD pEthread, PVOID pContext) {
	if (MmIsAddressValid(pContext))
		*(DWORD64*)pContext += 1;
	return STATUS_SUCCESS;
}

NTSTATUS ThreadCallbackAll(PEPROCESS pEprocess, PETHREAD pEthread, PVOID pContext) {
	HideWndThread(pEthread, (PROC_INFO*)pContext);
	return STATUS_SUCCESS;
}

VOID TriggerDetection() {
#ifndef MINIMAL_BUILD
	if (!pDetected
		|| !callbackProcess
		|| bDetectNotified)
		return;

	ULONG64 time1 = 0;
	ULONG64 time2 = 0;

	PsQueryTotalCycleTimeProcess(callbackProcess, &time1);
	threading::Sleep(200);
	PsQueryTotalCycleTimeProcess(callbackProcess, &time2);

	if (time1 == time2) {
		DbgMsg("[DETECTION] Cannot invoke callback as the process is dead!");
		return;
	}

	KAPC_STATE apc = { 0 };
	KeStackAttachProcess(callbackProcess, &apc);
	if (MmIsAddressValid(pDetected))
		*pDetected = true;
	KeUnstackDetachProcess(&apc);
	bDetectNotified = true;
	DbgMsg("[DETECTION] Notified detection successfully at: %p", pDetected);
#endif
}

VOID TriggerWarning() {
#ifndef MINIMAL_BUILD
	if (!pWarning
		|| !callbackProcess
		|| bWarnNotified)
		return;

	ULONG64 time1 = 0;
	ULONG64 time2 = 0;

	PsQueryTotalCycleTimeProcess(callbackProcess, &time1);
	threading::Sleep(200);
	PsQueryTotalCycleTimeProcess(callbackProcess, &time2);

	if (time1 == time2) {
		DbgMsg("[DETECTION] Cannot invoke callback as the process is dead!");
		return;
	}

	KAPC_STATE apc = { 0 };
	KeStackAttachProcess(callbackProcess, &apc);
	if (MmIsAddressValid(pWarning))
		*pWarning = true;
	KeUnstackDetachProcess(&apc);
	bWarnNotified = true;
	DbgMsg("[DETECTION] Notified warning successfully at: %p", pWarning);
#endif
}

NTSTATUS RestrickAndBlockProcess(PEPROCESS pEprocess, PVOID pCtx) {
#ifndef MINIMAL_BUILD
	if (pEprocess == CurrentProcess()
		|| pEprocess == PsInitialSystemProcess
		|| vBlockedProcesses->length() == 0
		)
		return STATUS_SUCCESS;

	BOOLEAN bStopBlock = (BOOLEAN)pCtx;

	KAPC_STATE apc = { 0 };
	KeStackAttachProcess(pEprocess, &apc);
	PVOID pBase = winternl::PsGetProcessSectionBaseAddress(pEprocess);
	if (!MmIsAddressValid(pBase)) {
		DbgMsg("[HOOK] Process base is invalid: %p", pBase);
		PROC_INFO info;
		info.pEprocess = (DWORD64)pEprocess;
		info.imageBase = (DWORD64)pBase;
		vRestrictedProcesses->Append(info);
		KeUnstackDetachProcess(&apc);
		return STATUS_SUCCESS;
	}

	PE pe(pBase);

	string pdbPath(pe.pdbPath());
	if (!pdbPath.Length()) {
		DbgMsg("[HOOK] Process created without PDB path in PE: %s", winternl::GetProcessImageFileName(pEprocess));

		string shortName(winternl::GetProcessImageFileName(pEprocess));
		for (auto& blocked : *vBlockedProcesses) {
			if (strstr(blocked.name.c_str(), shortName.to_lower())) {
				KeUnstackDetachProcess(&apc);

				currScore += blocked.score;

				if (!blocked.bRan
					&& maxScore
					) {
					if (currScore >= warnScore)
						TriggerWarning();
					if (currScore >= maxScore)
						TriggerDetection();
					blocked.bRan = true;
				}
				if (!bStopBlock) {
					DbgMsg("[HOOK] Blocked process creation: %s", blocked.name.c_str());
					return STATUS_ACCESS_DENIED;
				}
				HANDLE hProc = 0;
				ObOpenObjectByPointer(pEprocess, OBJ_KERNEL_HANDLE, NULL, GENERIC_ALL, *PsProcessType, KernelMode, &hProc);
				ZwTerminateProcess(hProc, STATUS_ACCESS_DENIED);
				ObCloseHandle(hProc, KernelMode);
				DbgMsg("[HOOK] Stopped process: %s", blocked.name.c_str());
				return STATUS_SUCCESS;
			}
		}
		KeUnstackDetachProcess(&apc);
		return STATUS_SUCCESS;
	}
	pdbPath.to_lower();
	if (pdbPath.last_of('\\'))
		pdbPath = pdbPath.substring(pdbPath.last_of('\\'));

	for (auto& blocked : *vBlockedProcesses) {
		if (strstr(pdbPath.c_str(), blocked.name.c_str())) {
			KeUnstackDetachProcess(&apc);

			currScore += blocked.score;

			if (!blocked.bRan
				&& maxScore
				) {
				if ((currScore + totalUntrustScore) >= warnScore)
					TriggerWarning();
				if ((currScore + totalUntrustScore) >= maxScore)
					TriggerDetection();
				blocked.bRan = true;
			}
			if (!bStopBlock) {
				DbgMsg("[HOOK] Blocked process creation: %s", blocked.name.c_str());
				return STATUS_ACCESS_DENIED;
			}
			HANDLE hProc = 0;
			ObOpenObjectByPointer(pEprocess, OBJ_KERNEL_HANDLE, NULL, GENERIC_ALL, *PsProcessType, KernelMode, &hProc);
			ZwTerminateProcess(hProc, STATUS_ACCESS_DENIED);
			ObCloseHandle(hProc, KernelMode);
			DbgMsg("[HOOK] Stopped process: %s", blocked.name.c_str());
			return STATUS_SUCCESS;
		}
	}
	if (pe.DataDir(IMAGE_DIRECTORY_ENTRY_SECURITY) == pBase) {
		DbgMsg("[HOOK] Process created without signature in PE: %s", pdbPath.c_str());
		PROC_INFO info;
		info.pEprocess = (DWORD64)pEprocess;
		info.imageBase = (DWORD64)pBase;
		vRestrictedProcesses->Append(info);
	}
	KeUnstackDetachProcess(&apc);
	DbgMsg("[HOOK] Process clean: %s", pdbPath.c_str());

#endif
	return STATUS_SUCCESS;
}

PEPROCESS currProcess = nullptr;

NTSTATUS
PspRundownSingleProcess(
	IN PEPROCESS Process,
	IN DWORD64 Flags
) {
	if (Process == (PEPROCESS)identity::LastMappedEprocess()) {
		identity::ResetCache();
		DbgMsg("[DRIVER] Cheat process is exiting!");
	}
	int i = 0;
#ifdef INTERNAL_FACILITY
	int len = vModBackups->length();
	for (; i < len; i++) {
		MOD_BACKUP_DATA& backup = vModBackups->at(i);
		if (backup.pEprocess == (DWORD64)Process) {
			if (Process == CurrentProcess() && MmIsAddressValid(backup.pModule)) {
				Memory::WriteProtected(backup.pModule, backup.pBuffer, backup.szMod);
			}
			else {
				vmcall::RW rw(backup.cr3);
				bool bSuccess = rw.Write(backup.pModule, backup.pBuffer, backup.szMod);
				if (!bSuccess) {
					DbgMsg("[HOOK] Failed restoring backup: %p - 0x%llx", backup.pModule, backup.szMod);
				}
			}

			backup.pEprocess = 0;
			cpp::kFree(backup.pBuffer);
			PVOID oldPml4 = (PVOID)Memory::PhyToVirt(backup.cr3);
			cpp::kFree(oldPml4);
			vModBackups->RemoveAt(i);
			len--;
		}
		else
			i++;
	}
#endif
	for (auto& rangeInfo : *vTrackedHiddenRanges) {
		if (rangeInfo.pEprocess
			&& rangeInfo.pEprocess == Process) {
			DbgMsg("[DRIVER] Unhooking EPT range at %p for 0x%llx bytes: %s", rangeInfo.pBase, rangeInfo.sz, winternl::GetProcessImageFileName(rangeInfo.pEprocess));
			rangeInfo.pEprocess = (PEPROCESS)MAXULONG32;
			if (rangeInfo.sz == PAGE_SIZE) {
				if (EPT::Unhook(rangeInfo.pBase) != STATUS_SUCCESS) {
					DbgMsg("[DRIVER] Failed unhooking page %p at process termination! Might cause unexpected issues...", rangeInfo.pBase);
				}
			}
			else {
				if (EPT::UnhookRange(rangeInfo.pBase, rangeInfo.sz) != STATUS_SUCCESS) {
					DbgMsg("[DRIVER] Failed unhooking pages at process termination! Might cause unexpected issues...");
				}
			}
		}
	}
	for (auto& procInfo : *vTrackedProcesses) {
		if (procInfo.pEprocess == (ULONG64)Process) {
			eac::UntrackCr3(procInfo.cr3);

			procInfo.bDead = true;
			procInfo.lock = false;
			procInfo.bMainThreadHidden = false;
			procInfo.pEprocess = 0;
			procInfo.pPeb = 0;
			procInfo.cr3 = 0;
			procInfo.imageBase = 0;
			procInfo.lastTrackedCr3 = 0;
#ifdef INTERNAL_FACILITY
			procInfo.bDllInjected = procInfo.mapInfo.pBuffer ? false : true;

			int dlls = 0;
			int strOffset = 0;
			while (procInfo.dllsToShadow && procInfo.dllsToShadow[strOffset] != 0) {
				i = 0;
				while ((&procInfo.dllsToShadow[strOffset])[i] != 0) {
					if ((&procInfo.dllsToShadow[strOffset])[i] == ',') {
						(&procInfo.dllsToShadow[strOffset])[i] = '.';
						DbgMsg("[DRIVER] Restored dll name: %s", &procInfo.dllsToShadow[strOffset]);
						break;
					}
					i++;
				}

				strOffset += strlen(&procInfo.dllsToShadow[strOffset]) + 1;
				dlls++;
			}
			procInfo.dllsQueueShadow = dlls;
			procInfo.lastDllBase = 0;
#endif
			procInfo.threadsStarted = 0;
		}
		else if (procInfo.pRequestor == (ULONG64)Process) {
			cpp::kFree(procInfo.mapInfo.pBuffer);
			procInfo.mapInfo.pBuffer = nullptr;
			procInfo.bDllInjected = true;
			procInfo.pRequestor = 0;
			break;
		}
	}
#ifndef MINIMAL_BUILD
	i = 0;
	for (auto& protect : *vProtectedProcesses) {
		if (protect == Process) {
			DbgMsg("[HOOK] Protected process is exiting!");
			vProtectedProcesses->RemoveAt(i);
			break;
		}
		i++;
	}

	i = 0;
	for (auto& restricted : *vRestrictedProcesses) {
		if (restricted.pEprocess == (DWORD64)Process) {
			DbgMsg("[HOOK] Restricted process is exiting!");
			vRestrictedProcesses->RemoveAt(i);
			break;
		}
		i++;
	}
	if (Process == currProcess) {
		currProcess = nullptr;
	}
#endif
	return pPspRundownSingleProcessOrig(Process, Flags);
}

NTSTATUS
PspInsertThread(
	PETHREAD pEthread,
	PEPROCESS Process,
	DWORD64 a3,
	DWORD64 a4,
	DWORD32 a5,
	DWORD64 a6,
	DWORD64 a7,
	DWORD64 a8,
	DWORD64 a9,
	DWORD64 a10,
	DWORD64 pStartRoutine
) {
	NTSTATUS ntStatus = pPspInsertThreadOrig(pEthread, Process, a3, a4, a5, a6, a7, a8, a9, a10, pStartRoutine);
	if (NT_SUCCESS(ntStatus)) {
		PEPROCESS currentProcess = CurrentProcess();
		PPROC_INFO pProcInfo = nullptr;

		if (hWndDefault
			&& (Process == currentProcess)
			) {
			PROC_INFO fakeProcInfo;
			fakeProcInfo.hWnd = hWndDefault;
			winternl::PsEnumProcessThreads((PEPROCESS)Process, ThreadCallbackAll, &fakeProcInfo);
		}

		if (vTrackedProcesses->length() == 0) {
			return ntStatus;
		}
		for (auto& procInfo : *vTrackedProcesses) {
			if ((ULONG64)Process == procInfo.pEprocess
				&& !procInfo.bDead) {
				DbgMsg("[DRIVER] Game process created thread: %s", procInfo.pImageName);

				if (procInfo.hWnd
					&& (Process == currentProcess)
					)
					winternl::PsEnumProcessThreads(Process, ThreadCallback, &procInfo);

				pProcInfo = &procInfo;

				break;
			}
		}

#ifndef MINIMAL_BUILD
		if (!pProcInfo && vBlockedProcesses->length()) {
			DWORD64 threadCount = 0;
			winternl::PsEnumProcessThreads(Process, CountThreadCallback, &threadCount);

			if (threadCount <= 1) {
				NTSTATUS blockStatus = RestrickAndBlockProcess(Process, 0);
				if (!NT_SUCCESS(blockStatus))
					return blockStatus;
			}
		}
#endif

		if (Process != currentProcess
			|| !pProcInfo) {
			return ntStatus;
		}

		pProcInfo->lastTrackedCr3 = __readcr3();
		if (pProcInfo->pRequestor && MmIsAddressValid((PVOID)pProcInfo->pRequestor)) {
			CR3 gCr3 = { 0 };
			gCr3.Flags = PsProcessDirBase(pProcInfo->pRequestor);
			vmcall::RW rw(gCr3.AddressOfPageDirectory * PAGE_SIZE);
			rw.Write(pProcInfo->cr3, &pProcInfo->lastTrackedCr3, 8);
		}

		//if(!MmIsAddressValid((PVOID)pProcInfo->pPeb))
		//	pProcInfo->pPeb = (ULONG64)PsGetProcessPeb(Process);
		PEPROCESS pEprocess = Process;

		PPEB_SKLIB CurrentPEB = (PPEB_SKLIB)PsGetProcessPeb(pEprocess);
		PLIST_ENTRY pListEntry = CurrentPEB->Ldr->MemoryOrder.Flink;

		pProcInfo->threadsStarted++;
		if (pProcInfo->bMapping
			|| (!pProcInfo->dllsToShadow && !pProcInfo->bDllInjected)
			)
			return ntStatus;

		pProcInfo->bMapping = true;

#ifdef INTERNAL_FACILITY
		if (!pProcInfo->bDllInjected && MmIsAddressValid(pProcInfo->mapInfo.pBuffer)) {
			SIZE_T szBuffer = (DWORD64)PAGE_ALIGN(pProcInfo->mapInfo.szOut + (PAGE_SIZE * 0x10));
			char* pBuffer = 0;
			PVOID pBufferShadow = cpp::kMalloc(PAGE_SIZE, PAGE_READWRITE);
			NTSTATUS allocStatus = ZwAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&pBuffer, 0, &szBuffer, MEM_COMMIT, PAGE_READWRITE);
			if (!NT_SUCCESS(allocStatus)) {
				DbgMsg("[DRIVER] Failed allocating memory!");
				pProcInfo->bMapping = false;
				return ntStatus;
			}
			DbgMsg("[DRIVER] Allocated 0x%llx bytes at: %p", szBuffer, pBuffer);

			RtlZeroMemory(pBuffer, pProcInfo->mapInfo.szOut);

			encryption::xorBytes(pProcInfo->mapInfo.pBuffer, pProcInfo->mapInfo.szOut, vmcall::GetCommunicationKey() << 1);
			RtlCopyMemory(pBuffer, pProcInfo->mapInfo.pBuffer, PAGE_SIZE);
			PE pePreAllocated(pProcInfo->mapInfo.pBuffer);
			for (auto& section : pePreAllocated.sections()) {
				PVOID pCurrSectionBase = (PVOID)(pBuffer + section.VirtualAddress);
				SIZE_T szSection = section.SizeOfRawData;
				RtlCopyMemory(pBuffer + section.VirtualAddress, (char*)pProcInfo->mapInfo.pBuffer + section.PointerToRawData, szSection);

				ULONG oldProtect = 0;
				ULONG protect = (IMAGE_SCN_MEM_EXECUTE & section.Characteristics) ? PAGE_EXECUTE_READ : PAGE_READWRITE;
				allocStatus = ZwProtectVirtualMemory(NtCurrentProcess(), &pCurrSectionBase, &szSection, protect, &oldProtect);
				if (!NT_SUCCESS(allocStatus)) {
					DbgMsg("[DRIVER] Failed protecting memory: %p - 0x%x", pCurrSectionBase, protect);
					encryption::xorBytes(pProcInfo->mapInfo.pBuffer, pProcInfo->mapInfo.szOut, vmcall::GetCommunicationKey() << 1);
					pProcInfo->bMapping = false;
					return ntStatus;
				}
			}

			winternl::QUOTA_LIMITS quotaLimits = { 0 };
			quotaLimits.Reserved0 = 33;
			quotaLimits.Reserved1 = 14;
			quotaLimits.MaximumWorkingSetSize = SIZE_1_GB;
			quotaLimits.MinimumWorkingSetSize = SIZE_1_GB;

			NTSTATUS adjustStatus = winternl::PspSetQuotaLimits(NtCurrentProcess(), &quotaLimits, sizeof(quotaLimits), KernelMode);
			if (!NT_SUCCESS(adjustStatus)) {
				DbgMsg("[DRIVER] Failed adjusting working set size for current process: 0x%x", adjustStatus);
				pProcInfo->bMapping = false;
				RtlZeroMemory(pBuffer, pProcInfo->mapInfo.szOut);
				ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&pBuffer, &szBuffer, MEM_RELEASE);
				encryption::xorBytes(pProcInfo->mapInfo.pBuffer, pProcInfo->mapInfo.szOut, vmcall::GetCommunicationKey() << 1);
				return ntStatus;
			}

			adjustStatus = winternl::NtLockVirtualMemory(NtCurrentProcess(), (PVOID*)&pBuffer, (SIZE_T*)&szBuffer, 1);
			if (!NT_SUCCESS(adjustStatus)) {
				DbgMsg("[DRIVER] Failed locking injected module at %p for current process: 0x%x", pBuffer, adjustStatus);
				pProcInfo->bMapping = false;
				RtlZeroMemory(pBuffer, pProcInfo->mapInfo.szOut);
				ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&pBuffer, &szBuffer, MEM_RELEASE);
				encryption::xorBytes(pProcInfo->mapInfo.pBuffer, pProcInfo->mapInfo.szOut, vmcall::GetCommunicationKey() << 1);
				return ntStatus;
			}

			RtlZeroMemory(pBufferShadow, PAGE_SIZE);

			if (pProcInfo->mapInfo.bEPTHide) {
				HOOK_SECONDARY_INFO hkSecondaryInfo = { 0 };
				PAGE_PERMISSIONS pgPermission = { 0 };
				hkSecondaryInfo.pSubstitutePage = pBufferShadow;
				pgPermission.Exec = true;

				//szBuffer = PAGE_SIZE + pePreAllocated.sizeOfCode();
				if (!EPT::HookRange(pBuffer, szBuffer, pBufferShadow, hkSecondaryInfo, pgPermission)) {
					DbgMsg("[DRIVER] Failed EPT shadowing injected module: %p - 0x%llx", pBuffer, szBuffer);
					RtlZeroMemory(pBuffer, pProcInfo->mapInfo.szOut);
					ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&pBuffer, &szBuffer, MEM_RELEASE);
					cpp::kFree(pBufferShadow);
					encryption::xorBytes(pProcInfo->mapInfo.pBuffer, pProcInfo->mapInfo.szOut, vmcall::GetCommunicationKey() << 1);
					pProcInfo->bMapping = false;
					return ntStatus;
				}
				vTrackedHiddenRanges->emplace_back(pBuffer, szBuffer, pEprocess);
			}

			PE pe(pBuffer);

			if (!pProcInfo->mapInfo.bMapped) {
				DbgMsg("[DRIVER] Image requires relocations and import fixing!");
				pe.relocate();
				pe.fixImports(pProcInfo->pPeb);
			}

			pProcInfo->mapInfo.pOutBuffer = pBuffer;
			pProcInfo->bDllInjected = true;
			encryption::xorBytes(pProcInfo->mapInfo.pBuffer, pProcInfo->mapInfo.szOut, vmcall::GetCommunicationKey() << 1);

			DbgMsg("[DRIVER] Injected module into %s", pProcInfo->pImageName);
		}

		if (!pProcInfo->dllsToShadow
			|| !pProcInfo->dllsToShadow[0]
			|| !pProcInfo->dllsQueueShadow
			) {
			pProcInfo->bMapping = false;
			return ntStatus;
		}

		pListEntry = CurrentPEB->Ldr->MemoryOrder.Flink;
		for (; pListEntry != &CurrentPEB->Ldr->MemoryOrder;) {
			if (!pListEntry) {
				DbgMsg("[DRIVER] List entry is null!");
				break;
			}

			auto moduleEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, LoadOrder);
			string modName(&moduleEntry->ModuleName);

			bool bModFound = false;
			int strOffset = 0;
			while (pProcInfo->dllsToShadow[strOffset] != 0) {
				char* dll = &pProcInfo->dllsToShadow[strOffset];
				strOffset += strlen(dll) + 1;
				if (modName != dll) {
					continue;
				}
				dll[modName.last_of('.')] = ',';

				bModFound = true;
				DbgMsg("[DRIVER] Found module to shadow: %s", modName.c_str());

				PE pe(moduleEntry->ModuleBaseAddress);

				ULONG oldPrt = 0;
				PVOID pCodeBase = (PVOID)((DWORD64)moduleEntry->ModuleBaseAddress + PAGE_SIZE);
				SIZE_T szCode = pe.sizeOfCode();

				CR3 currCr3 = { 0 };
				currCr3.Flags = __readcr3();
				PVOID pml4t = cpp::kMalloc(PAGE_SIZE);
				RtlCopyMemory(pml4t, paging::MapPML4Base(currCr3), PAGE_SIZE);
				MOD_BACKUP_DATA backup = { 0 };
				backup.cr3 = Memory::VirtToPhy(pml4t);
				backup.pEprocess = (DWORD64)currentProcess;
				backup.szMod = szCode;
				backup.pBuffer = cpp::kMalloc(backup.szMod);
				backup.pModule = (PVOID)pCodeBase;
				RtlCopyMemory(backup.pBuffer, backup.pModule, backup.szMod);
				vModBackups->Append(backup);

				winternl::QUOTA_LIMITS quotaLimits = { 0 };
				quotaLimits.Reserved0 = 33;
				quotaLimits.Reserved1 = 14;
				quotaLimits.MaximumWorkingSetSize = SIZE_1_GB;
				quotaLimits.MinimumWorkingSetSize = SIZE_1_GB;

				NTSTATUS adjustStatus = winternl::PspSetQuotaLimits(NtCurrentProcess(), &quotaLimits, sizeof(quotaLimits), KernelMode);
				if (!NT_SUCCESS(adjustStatus)) {
					DbgMsg("[DRIVER] Failed adjusting working set size for current process: 0x%x", adjustStatus);
					KeBugCheckEx(0x12345555, adjustStatus, (ULONG_PTR)moduleEntry->ModuleBaseAddress, 0, 0);
					break;
				}

				adjustStatus = winternl::NtLockVirtualMemory(NtCurrentProcess(), &moduleEntry->ModuleBaseAddress, (SIZE_T*)&moduleEntry->ModuleSize, 1);
				if (!NT_SUCCESS(adjustStatus)) {
					DbgMsg("[DRIVER] Failed locking module at %p for current process: 0x%x", moduleEntry->ModuleBaseAddress, adjustStatus);
					KeBugCheckEx(0x12345556, adjustStatus, (ULONG_PTR)moduleEntry->ModuleBaseAddress, 0, 0);
					break;
				}

				DbgMsg("[DRIVER] Locked module: %wZ - %p - 0x%x", moduleEntry->ModuleName, moduleEntry->ModuleBaseAddress, moduleEntry->ModuleSize);
				pProcInfo->lastDllBase = (DWORD64)moduleEntry->ModuleBaseAddress;
				pProcInfo->dllsQueueShadow--;
				break;
			}

			if (bModFound)
				break;
			pListEntry = pListEntry->Flink;
		}
#endif
		pProcInfo->bMapping = false;
	}
	return ntStatus;
}

NTSTATUS
PspInsertProcess(
	PEPROCESS pEprocess,
	PEPROCESS pEprocessOwner,
	DWORD64 unknown,
	DWORD64 unknown1,
	DWORD64 exceptionPort,
	DWORD64 someFlags,
	DWORD64 isZero,
	DWORD64 someParamPtr
) {
	NTSTATUS ntStatus = pPspInsertProcessOrig(pEprocess, pEprocessOwner, unknown, unknown1, exceptionPort, someFlags, isZero, someParamPtr);
	if (NT_SUCCESS(ntStatus)) {
		if (!MmIsAddressValid(pEprocess))
			return ntStatus;

		bool bFound = false;
		for (auto& procInfo : *vTrackedProcesses) {
			if (!procInfo.bDead)
				continue;

			UNICODE_STRING imgName = { 0 };
			unsigned int nameLen = PAGE_SIZE;
			PVOID pName = cpp::kMalloc(nameLen);
			NTSTATUS status = winternl::PsQueryFullProcessImageName(pEprocess, &imgName, pName, &nameLen);
			if (!NT_SUCCESS(status)) {
				DbgMsg("[DRIVER] Failed getting full process image name: 0x%x", status);
				cpp::kFree(pName);
				return ntStatus;
			}

			string fullName(&imgName);
			cpp::kFree(pName);
			int splitIdx = fullName.last_of('\\');
			if (splitIdx != 0) {
				fullName = fullName.substring(splitIdx + 1);
			}
			if (fullName == procInfo.pImageName) {
				DbgMsg("[DRIVER] Found registered image: %s", fullName.c_str());
				procInfo.pEprocess = (ULONG64)pEprocess;
				procInfo.imageBase = (DWORD64)winternl::PsGetProcessSectionBaseAddress((PEPROCESS)procInfo.pEprocess);
				procInfo.pPeb = (ULONG64)PsGetProcessPeb((PEPROCESS)procInfo.pEprocess);
				procInfo.dwPid = (HANDLE)PsGetProcessId(pEprocess);
				CR3 gameCr3 = { 0 };
				gameCr3.Flags = PsProcessDirBase(pEprocess);
				if (!gameCr3.Reserved3 && !gameCr3.Reserved2 && !gameCr3.Reserved1) {
					procInfo.lastTrackedCr3 = gameCr3.Flags;
				}

				if (MmIsAddressValid((PVOID)procInfo.pRequestor)) {
					eac::TrackCr3(procInfo.cr3, (PVOID)procInfo.imageBase, PsProcessDirBase(procInfo.pRequestor));
				}

				procInfo.bDead = false;

				bFound = true;

				if (procInfo.bPause)
					procInfo.lock = true;
			}

			if (bFound)
				break;
		}
	}

	return ntStatus;
}

NTSTATUS
NtLockVirtualMemory (
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG MapType
	) {
	auto kReq = (KERNEL_REQUEST*)ProcessHandle;
	if (CurrentProcess() == sputnik::storage_get<PEPROCESS>(VMX_ROOT_STORAGE::CURRENT_CONTROLLER_PROCESS) && kReq->IsValid()) {
		return comms::Entry((KERNEL_REQUEST*)ProcessHandle);
	}

	NTSTATUS ntStatus = pNtLockVirtualMemoryOrig(ProcessHandle, BaseAddress, RegionSize, MapType);

	return ntStatus;
}

NTSTATUS CommsVmcallHandler(ULONG64& ulOpt1, ULONG64& ulOpt2, ULONG64& ulOpt3) {
	PULONG64 pMem = (PULONG64)paging::vmmhost::MapGuestToHost(vmm::GetGuestCR3().Flags, (PVOID)ulOpt1);
	if (pMem)
		*pMem = (ULONG64)comms::Entry;
	return STATUS_SUCCESS;
}

NTSTATUS CommsHvFlagsVmcallHandler(ULONG64& ulOpt1, ULONG64& ulOpt2, ULONG64& ulOpt3) {
	PULONG64 pMem = (PULONG64)paging::vmmhost::MapGuestToHost(vmm::GetGuestCR3().Flags, (PVOID)ulOpt1);
	if (pMem)
		*pMem = (ULONG64)BUILD_FLAGS;
	return STATUS_SUCCESS;
}

NTSTATUS CommsGetInfoVmcallHandler(ULONG64& ulOpt1, ULONG64& ulOpt2, ULONG64& ulOpt3) {
	for (auto& procInfo : *vTrackedProcesses) {
		if (ulOpt2 == (DWORD64)procInfo.cr3) {
			PROC_INFO* pMem = (PROC_INFO*)paging::vmmhost::MapGuestToHost(vmm::GetGuestCR3().Flags, (PVOID)ulOpt1);
			if (!pMem)
				break;

			*pMem = procInfo;
			break;
		}
	}

	return STATUS_SUCCESS;
}

BOOLEAN comms::Init()
{
	if (bCommsInit)
		return TRUE;

	if (!vTrackedProcesses)
	{
		vTrackedProcesses = (vector<PROC_INFO>*)cpp::kMallocTryAll(sizeof(*vTrackedProcesses));
		RtlZeroMemory(vTrackedProcesses, sizeof(*vTrackedProcesses));
		vTrackedProcesses->Init();
		vTrackedProcesses->reserve(64);
	}

#ifndef MINIMAL_BUILD
	if (!vRestrictedProcesses)
	{
		vRestrictedProcesses = (vector<PROC_INFO>*)cpp::kMallocTryAll(sizeof(*vRestrictedProcesses));
		RtlZeroMemory(vRestrictedProcesses, sizeof(*vRestrictedProcesses));
		vRestrictedProcesses->Init();
		vRestrictedProcesses->reserve(64);
	}

	if (!vProtectedProcesses)
	{
		vProtectedProcesses = (vector<PEPROCESS>*)cpp::kMallocTryAll(sizeof(*vProtectedProcesses));
		RtlZeroMemory(vProtectedProcesses, sizeof(*vProtectedProcesses));
		vProtectedProcesses->Init();
		vProtectedProcesses->reserve(64);
		//vProtectedProcesses->Append(CurrentProcess());
	}

	if (!vBlockedProcesses)
	{
		vBlockedProcesses = (vector<BLOCKED_PROCESS_INFO>*)cpp::kMallocTryAll(sizeof(*vBlockedProcesses));
		RtlZeroMemory(vBlockedProcesses, sizeof(*vBlockedProcesses));
		vBlockedProcesses->Init();
		vBlockedProcesses->reserve(64);

#ifndef DEBUG_BUILD
		DWORD64 score = 50;
		vBlockedProcesses->emplace_back("x64dbg", score);
		vBlockedProcesses->emplace_back("windbg", score);
		vBlockedProcesses->emplace_back("ghidra", score);
		vBlockedProcesses->emplace_back("ida64", score);
		vBlockedProcesses->emplace_back("wireshark", score);
		vBlockedProcesses->emplace_back("procmon", score);
		vBlockedProcesses->emplace_back("apimonitor", score);
		vBlockedProcesses->emplace_back("ollydbg", score);
		vBlockedProcesses->emplace_back("fiddler", score);
		vBlockedProcesses->emplace_back("scylla", score);
		score = 30;
		vBlockedProcesses->emplace_back("processhacker", score);
		vBlockedProcesses->emplace_back("systeminformer", score);
		vBlockedProcesses->emplace_back("pe-bear", score);
		vBlockedProcesses->emplace_back("dbgview", score);
#endif
		winternl::PsEnumProcesses(RestrickAndBlockProcess, (PVOID)1);
	}
#endif

	if (!vTrackedHiddenRanges)
	{
		vTrackedHiddenRanges = (vector<RANGE_INFO>*)cpp::kMallocTryAll(sizeof(*vTrackedHiddenRanges));
		RtlZeroMemory(vTrackedHiddenRanges, sizeof(*vTrackedHiddenRanges));
		vTrackedHiddenRanges->Init();
		vTrackedHiddenRanges->reserve(64);
	}

#ifdef INTERNAL_FACILITY
	if (!vModBackups) {
		vModBackups = (vector<MOD_BACKUP_DATA>*)cpp::kMallocTryAll(sizeof(*vModBackups));
		RtlZeroMemory(vModBackups, sizeof(*vModBackups));
		vModBackups->Init();
		vModBackups->reserve(64);
		vModBackups->DisableLock();
	}
#endif

	vmcall::InsertHandler(CommsVmcallHandler, VMCALL_GET_CALLBACK);
	vmcall::InsertHandler(CommsHvFlagsVmcallHandler, VMCALL_GET_HV_BUILD_FLAGS);
	vmcall::InsertHandler(CommsGetInfoVmcallHandler, VMCALL_GET_INFO);

	HOOK_SECONDARY_INFO hkSecondaryInfo = { 0 };
	PAGE_PERMISSIONS pgPermissions = { 0 };

	hkSecondaryInfo.pOrigFn = (PVOID*)&pPspInsertThreadOrig;
	if (!EPT::Hook((PVOID)winternl::PspInsertThread, PspInsertThread, hkSecondaryInfo, pgPermissions)) {
		DbgMsg("[DRIVER] Failed hooking PspInsertThread");
		return false;
	}
	else {
		DbgMsg("[DRIVER] Hooked PspInsertThread");
	}

	hkSecondaryInfo.pOrigFn = (PVOID*)&pPspInsertProcessOrig;
	if (!EPT::Hook((PVOID)winternl::PspInsertProcess, PspInsertProcess, hkSecondaryInfo, pgPermissions)) {
		DbgMsg("[DRIVER] Failed hooking PspInsertProcess");
		return false;
	}
	else {
		DbgMsg("[DRIVER] Hooked PspInsertProcess");
	}

	hkSecondaryInfo.pOrigFn = (PVOID*)&pPspRundownSingleProcessOrig;
	if (!EPT::Hook((PVOID)winternl::PspRundownSingleProcess, PspRundownSingleProcess, hkSecondaryInfo, pgPermissions)) {
		DbgMsg("[DRIVER] Failed hooking PspRundownSingleProcess");
		return false;
	}
	else {
		DbgMsg("[DRIVER] Hooked PspRundownSingleProcess");
	}

	hkSecondaryInfo.pOrigFn = (PVOID*)&pNtLockVirtualMemoryOrig;
	if (!EPT::Hook((PVOID)winternl::NtLockVirtualMemory, NtLockVirtualMemory, hkSecondaryInfo, pgPermissions)) {
		DbgMsg("[DRIVER] Failed hooking NtLockVirtualMemory");
		return false;
	}
	else {
		DbgMsg("[DRIVER] Hooked NtLockVirtualMemory");
	}

	bCommsInit = true;
	return true;
}

NTSTATUS comms::Entry(KERNEL_REQUEST* pKernelRequest)
{
	if (!bCommsInit)
		return STATUS_NOT_IMPLEMENTED;

	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

	if (SKLib::pUserInfo->cleanupData.pDriverName[0]) {
		if (!defender::CleanFilterList(SKLib::pUserInfo->cleanupData.pDriverName)) {
			DbgMsg("[CLEANUP] Defender FilterList could not be cleared!");
		}
		SKLib::pUserInfo->cleanupData.pDriverName[0] = 0;
	}

	if (!MmIsAddressValid(pKernelRequest))
		return ntStatus;

	currProcess = CurrentProcess();
	KERNEL_REQUEST kernelRequest = *pKernelRequest;

	switch (kernelRequest.instructionID) {
	case INST_RESET_INFO:
	{
		for (auto& procInfo : *vTrackedProcesses) {
			RtlZeroMemory(&procInfo, sizeof(procInfo));
		}
		ntStatus = STATUS_SUCCESS;
		break;
	}
	case INST_MAP:
	{
		if (!MmIsAddressValid(kernelRequest.procInfo.mapInfo.pBuffer)
			|| !kernelRequest.procInfo.mapInfo.sz) {
			return STATUS_INVALID_PARAMETER;
		}

		PEPROCESS targetProc = 0;
		ntStatus = winternl::PsLookupProcessByProcessId(kernelRequest.procInfo.dwPid, &targetProc);
		if (!NT_SUCCESS(ntStatus))
			break;

		KAPC_STATE apc = { 0 };

		PPROC_INFO pProcInfo = nullptr;
		for (auto& proc : *vTrackedProcesses) {
			if (kernelRequest.procInfo.cr3 == proc.cr3) {
				pProcInfo = &proc;
				break;
			}
		}
		if (!pProcInfo)
			return STATUS_NOT_FOUND;

		PVOID pBuffer = cpp::kMalloc(kernelRequest.procInfo.mapInfo.sz);
		RtlCopyMemory(pBuffer, kernelRequest.procInfo.mapInfo.pBuffer, kernelRequest.procInfo.mapInfo.sz);
		PE pe(pBuffer);
		char* pBufferMapped = (char*)0;
		SIZE_T szBuffer = pe.imageSize();
		KeStackAttachProcess(targetProc, &apc);
		ZwFreeVirtualMemory(NtCurrentProcess(), &kernelRequest.procInfo.mapInfo.pOutBuffer, &kernelRequest.procInfo.mapInfo.szOut, MEM_DECOMMIT);
		NTSTATUS allocStatus = ZwAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&pBufferMapped, 0, &szBuffer, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(allocStatus)) {
			DbgMsg("[DRIVER] Failed allocating memory!");
			KeUnstackDetachProcess(&apc);
			cpp::kFree(pBuffer);
			return ntStatus;
		}
		RtlZeroMemory(pBufferMapped, szBuffer);
		RtlCopyMemory(pBufferMapped, pBuffer, PAGE_SIZE);
		PE peMapped(pBufferMapped);

		winternl::QUOTA_LIMITS quotaLimits = { 0 };
		quotaLimits.Reserved0 = 33;
		quotaLimits.Reserved1 = 14;
		quotaLimits.MaximumWorkingSetSize = SIZE_1_GB;
		quotaLimits.MinimumWorkingSetSize = SIZE_1_GB;

		NTSTATUS adjustStatus = winternl::PspSetQuotaLimits(NtCurrentProcess(), &quotaLimits, sizeof(quotaLimits), KernelMode);
		if (!NT_SUCCESS(adjustStatus)) {
			DbgMsg("[DRIVER] Failed adjusting working set size for current process: 0x%x", adjustStatus);
			KeUnstackDetachProcess(&apc);
			return ntStatus;
		}

		adjustStatus = winternl::NtLockVirtualMemory(NtCurrentProcess(), (PVOID*)&pBufferMapped, (SIZE_T*)&szBuffer, 1);
		if (!NT_SUCCESS(adjustStatus)) {
			DbgMsg("[DRIVER] Failed locking injected module at %p for current process: 0x%x", pBufferMapped, adjustStatus);
			KeUnstackDetachProcess(&apc);
			return ntStatus;
		}

		for (auto& section : peMapped.sections()) {
			SIZE_T szSection = section.SizeOfRawData;
			RtlCopyMemory(pBufferMapped + section.VirtualAddress, (char*)pBuffer + section.PointerToRawData, szSection);
		}

		peMapped.relocate();
		peMapped.fixImports((DWORD64)PsGetProcessPeb(targetProc));

		KeUnstackDetachProcess(&apc);
		cpp::kFree(pBuffer);
		kernelRequest.procInfo.mapInfo.pOutBuffer = pBufferMapped;
		kernelRequest.procInfo.mapInfo.szOut = szBuffer;
		pProcInfo->mapInfo.pOutBuffer = pBufferMapped;
		pProcInfo->mapInfo.szOut = szBuffer;
		ntStatus = STATUS_SUCCESS;
		break;
	}
	case INST_ADD_SHADOW:
	{
#ifdef INTERNAL_FACILITY
		//if (!kernelRequest.memoryInfo.opSize) {
		//	return STATUS_INVALID_PARAMETER_1;
		//}
		//if (!kernelRequest.memoryInfo.opDstAddr) {
		//	return STATUS_INVALID_PARAMETER_2;
		//}
		//DWORD64 start = kernelRequest.memoryInfo.opDstAddr;
		//DWORD64 end = start + kernelRequest.memoryInfo.opSize;
		//
		//kernelRequest.memoryInfo.opSize = (DWORD64)PAGE_ALIGN(end + PAGE_SIZE - 1);
		//kernelRequest.memoryInfo.opSize -= (DWORD64)PAGE_ALIGN(start + PAGE_SIZE - 1);
		//kernelRequest.memoryInfo.opSize += PAGE_SIZE;
		//kernelRequest.memoryInfo.opDstAddr = (DWORD64)PAGE_ALIGN(kernelRequest.memoryInfo.opDstAddr);
		//
		//PEPROCESS pTargetProcess = CurrentProcess();
		//
		//PVOID Base = (PVOID)kernelRequest.memoryInfo.opDstAddr;
		//SIZE_T size = kernelRequest.memoryInfo.opSize;
		//
		//winternl::NtLockVirtualMemory(NtCurrentProcess(), &Base, &size, 1);
		//
		//vTrackedHiddenRanges->reserve(kernelRequest.memoryInfo.opSize / PAGE_SIZE);
		//vmm::vHooks->reserve(kernelRequest.memoryInfo.opSize / PAGE_SIZE);
		//for (DWORD64 pageOffset = 0; pageOffset < kernelRequest.memoryInfo.opSize; pageOffset += PAGE_SIZE) {
		//	PVOID pBase = (PVOID)(kernelRequest.memoryInfo.opDstAddr + pageOffset);
		//	for (auto i = 0; i < PAGE_SIZE / 8; i++) {
		//		volatile DWORD64 test = ((DWORD64*)pBase)[i];
		//	}
		//
		//	bool bRangeAlreadyHidden = false;
		//	for (auto& range : *vTrackedHiddenRanges) {
		//		if (range.pEprocess == pTargetProcess
		//			&& PAGE_ALIGN(range.pBase) == PAGE_ALIGN(pBase)
		//			) {
		//			bRangeAlreadyHidden = true;
		//			break;
		//		}
		//	}
		//	if (bRangeAlreadyHidden)
		//		continue;
		//
		//	PHYSICAL_ADDRESS pa = { 0 };
		//	CR3 cr3 = { 0 };
		//	cr3.Flags = __readcr3();
		//	pa.QuadPart = (DWORD64)paging::GuestVirtToPhy(pBase, (PVOID)(cr3.AddressOfPageDirectory * PAGE_SIZE));
		//	if (!pa.QuadPart) {
		//		DbgMsg("[DRIVER] Failed getting page pa for shadowing: %p", pBase);
		//		ntStatus = STATUS_FAIL_CHECK;
		//		return ntStatus;
		//	}
		//	PVOID pTarget = MmMapIoSpace(pa, PAGE_SIZE, MmNonCached);
		//	if (!EPT::AddToShadow(pTarget)) {
		//		DbgMsg("[DRIVER] Failed adding to shadow memory region!");
		//		ntStatus = STATUS_ABANDONED;
		//		MmUnmapIoSpace(pTarget, PAGE_SIZE);
		//		return ntStatus;
		//	}
		//	SIZE_T sz = PAGE_SIZE;
		//	vTrackedHiddenRanges->emplace_back(pTarget, sz, pTargetProcess);
		//	MmUnmapIoSpace(pTarget, PAGE_SIZE);
		//}
		//
		//DbgMsg("[DRIVER] Added to shadow module: 0x%llx - 0x%llx", kernelRequest.memoryInfo.opDstAddr, kernelRequest.memoryInfo.opSize);
#endif

		ntStatus = STATUS_SUCCESS;
		break;
	}
	case INST_SHADOW:
	{
#ifdef INTERNAL_FACILITY
		PPROC_INFO pProcInfo = nullptr;
		for (auto& proc : *vTrackedProcesses) {
			if (kernelRequest.procInfo.cr3 == proc.cr3) {
				pProcInfo = &proc;
				break;
			}
		}
		if (!pProcInfo)
			return STATUS_NOT_FOUND;

		CR3 cr3 = { 0 };
		cr3.Flags = *kernelRequest.procInfo.cr3;

		if (!kernelRequest.memoryInfo.opSize) {
			return STATUS_INVALID_PARAMETER_1;
		}
		if (!kernelRequest.memoryInfo.opDstAddr) {
			return STATUS_INVALID_PARAMETER_2;
		}
		DWORD64 start = kernelRequest.memoryInfo.opDstAddr;
		DWORD64 end = start + kernelRequest.memoryInfo.opSize;

		kernelRequest.memoryInfo.opSize = (DWORD64)PAGE_ALIGN(end + PAGE_SIZE - 1);
		kernelRequest.memoryInfo.opSize -= (DWORD64)PAGE_ALIGN(start + PAGE_SIZE - 1);
		kernelRequest.memoryInfo.opSize += PAGE_SIZE;
		kernelRequest.memoryInfo.opDstAddr = (DWORD64)PAGE_ALIGN(kernelRequest.memoryInfo.opDstAddr);

		char* pSubstitute = (char*)cpp::kMalloc(kernelRequest.memoryInfo.opSize, PAGE_READWRITE);
		RtlZeroMemory(pSubstitute, kernelRequest.memoryInfo.opSize);

		vmcall::RW rw(*kernelRequest.procInfo.cr3);
		rw.Read(PAGE_ALIGN(kernelRequest.memoryInfo.opDstAddr), pSubstitute, kernelRequest.memoryInfo.opSize);

		PEPROCESS pTargetProcess = (PEPROCESS)pProcInfo->pEprocess;

		vTrackedHiddenRanges->reserve(kernelRequest.memoryInfo.opSize / PAGE_SIZE);
		vmm::vHooks->reserve(kernelRequest.memoryInfo.opSize / PAGE_SIZE);
		for (DWORD64 pageOffset = 0; pageOffset < kernelRequest.memoryInfo.opSize; pageOffset += PAGE_SIZE) {
			PVOID pBase = (PVOID)(kernelRequest.memoryInfo.opDstAddr + pageOffset);
			bool bRangeAlreadyHidden = false;
			for (auto& range : *vTrackedHiddenRanges) {
				if (range.pEprocess == pTargetProcess
					&& PAGE_ALIGN(range.pBase) == PAGE_ALIGN(pBase)
					) {
					bRangeAlreadyHidden = true;
					break;
				}
			}
			if (bRangeAlreadyHidden)
				continue;

			PHYSICAL_ADDRESS pa = { 0 };
			cr3.Flags = *kernelRequest.procInfo.cr3;
			pa.QuadPart = (DWORD64)paging::GuestVirtToPhy(pBase, (PVOID)(cr3.AddressOfPageDirectory * PAGE_SIZE));
			if (!pa.QuadPart) {
				DbgMsg("[DRIVER] Failed getting page pa for shadowing: %p", pBase);
				ntStatus = STATUS_FAIL_CHECK;
				return ntStatus;
			}
			PVOID pTarget = MmMapIoSpace(pa, PAGE_SIZE, MmNonCached);
			HOOK_SECONDARY_INFO hkSecondaryInfo = { 0 };
			PAGE_PERMISSIONS pgPermissions = { 0 };
			pgPermissions.Exec = true;
			hkSecondaryInfo.pSubstitutePage = pSubstitute + pageOffset;
			if (!EPT::Hook(pTarget, (PVOID)pa.QuadPart, hkSecondaryInfo, pgPermissions)) {
				DbgMsg("[DRIVER] Failed shadowing memory region!");
				ntStatus = STATUS_ABANDONED;
				MmUnmapIoSpace(pTarget, PAGE_SIZE);
				return ntStatus;
			}
			SIZE_T sz = PAGE_SIZE;
			vTrackedHiddenRanges->emplace_back(pTarget, sz, pTargetProcess);
			MmUnmapIoSpace(pTarget, PAGE_SIZE);
		}

		DbgMsg("[DRIVER] Shadowed module: 0x%llx - 0x%llx", kernelRequest.memoryInfo.opDstAddr, kernelRequest.memoryInfo.opSize);
#endif

		ntStatus = STATUS_SUCCESS;
		break;
	}
	case INST_LOCK_MODULE:
	{
#ifdef INTERNAL_FACILITY
		PPROC_INFO pProcInfo = nullptr;
		for (auto& proc : *vTrackedProcesses) {
			if (kernelRequest.procInfo.cr3 == proc.cr3) {
				pProcInfo = &proc;
				break;
			}
		}
		if (!pProcInfo)
			return STATUS_NOT_FOUND;

		int strOffset = 0;
		while (pProcInfo->dllsToShadow[strOffset] != 0) {
			if (strcmp(&pProcInfo->dllsToShadow[strOffset], kernelRequest.procInfo.pImageName) == 0) {
				return STATUS_ALREADY_COMMITTED;
			}
			strOffset += strlen(&pProcInfo->dllsToShadow[strOffset]) + 1;
		}

		if (strcmp("GimmeDaKeyYouBastard:)", kernelRequest.procInfo.pImageName) == 0) {
			volatile char flag[] = "FLAG{W0rWe4k}";
			Memory::WriteProtected(kernelRequest.procInfo.pImageName, (char*)flag, sizeof(flag));
			ntStatus = STATUS_SUCCESS;
			break;
		}
		strcpy(&pProcInfo->dllsToShadow[strOffset], kernelRequest.procInfo.pImageName);
		pProcInfo->dllsQueueShadow++;

		DbgMsg("[DRIVER] Requested shadowing of module %s for process %s", kernelRequest.procInfo.pImageName, pProcInfo->pImageName);
#endif
		ntStatus = STATUS_SUCCESS;
		break;
	}
	case INST_HIDE:
	{
		CLIENT_ID cid = { 0 };
		PEPROCESS targetProc = CurrentProcess();

		PVOID Base = (PVOID)kernelRequest.memoryInfo.opDstAddr;
		SIZE_T size = kernelRequest.memoryInfo.opSize;

		winternl::QUOTA_LIMITS quotaLimits = { 0 };
		quotaLimits.Reserved0 = 33;
		quotaLimits.Reserved1 = 14;
		quotaLimits.MaximumWorkingSetSize = SIZE_1_GB;
		quotaLimits.MinimumWorkingSetSize = SIZE_1_GB;

		NTSTATUS adjustStatus = winternl::PspSetQuotaLimits(NtCurrentProcess(), &quotaLimits, sizeof(quotaLimits), KernelMode);
		if (!NT_SUCCESS(adjustStatus)) {
			DbgMsg("[DRIVER] Failed adjusting working set size for current process: 0x%x", adjustStatus);
			return ntStatus;
		}

		ntStatus = winternl::NtLockVirtualMemory(NtCurrentProcess(), &Base, &size, 1);
		if (!NT_SUCCESS(ntStatus)) {
			DbgMsg("[DRIVER] Failed NtLockVirtualMemory: 0x%x - 0x%x", ntStatus, cid.UniqueProcess);
			break;
		}
		ntStatus = STATUS_SUCCESS;

		DWORD64 start = kernelRequest.memoryInfo.opDstAddr;
		DWORD64 end = start + kernelRequest.memoryInfo.opSize;

		kernelRequest.memoryInfo.opSize = (DWORD64)PAGE_ALIGN(end + PAGE_SIZE - 1);
		kernelRequest.memoryInfo.opSize -= (DWORD64)PAGE_ALIGN(start + PAGE_SIZE - 1);
		//kernelRequest.memoryInfo.opSize += PAGE_SIZE;
		kernelRequest.memoryInfo.opDstAddr = (DWORD64)PAGE_ALIGN(kernelRequest.memoryInfo.opDstAddr);

		DbgMsg("[DRIVER] EPT hiding 0x%llx bytes at: 0x%llx", kernelRequest.memoryInfo.opSize, kernelRequest.memoryInfo.opDstAddr);

		char* pSubstitute = (char*)cpp::kMalloc(kernelRequest.memoryInfo.opSize, PAGE_READWRITE);
		RtlZeroMemory(pSubstitute, kernelRequest.memoryInfo.opSize);

		//vmcall::RW rw(__readcr3());
		//rw.Read(PAGE_ALIGN(kernelRequest.memoryInfo.opDstAddr), pSubstitute, kernelRequest.memoryInfo.opSize);

		vTrackedHiddenRanges->reserve(kernelRequest.memoryInfo.opSize / PAGE_SIZE);
		vmm::vHooks->reserve(kernelRequest.memoryInfo.opSize / PAGE_SIZE);
		for (DWORD64 pageOffset = 0; pageOffset < kernelRequest.memoryInfo.opSize; pageOffset += PAGE_SIZE) {
			PVOID pBase = (PVOID)(kernelRequest.memoryInfo.opDstAddr + pageOffset);
			bool bRangeAlreadyHidden = false;
			for (auto& range : *vTrackedHiddenRanges) {
				if (range.pEprocess == targetProc
					&& PAGE_ALIGN(range.pBase) == PAGE_ALIGN(pBase)
					) {
					bRangeAlreadyHidden = true;
					break;
				}
			}
			if (bRangeAlreadyHidden) {
				DbgMsg("[DRIVER] Page already hidden: %p", pBase);
				continue;
			}

			HOOK_SECONDARY_INFO hkSecondaryInfo = { 0 };
			PAGE_PERMISSIONS pgPermissions = { 0 };
			pgPermissions.Exec = true;
			hkSecondaryInfo.pSubstitutePage = pSubstitute + pageOffset;
			if (!EPT::Hook(pBase, (PVOID)hkSecondaryInfo.pSubstitutePage, hkSecondaryInfo, pgPermissions)) {
				DbgMsg("[DRIVER] Failed shadowing memory region!");
				ntStatus = STATUS_ABANDONED;
				break;
			}
			SIZE_T sz = PAGE_SIZE;
			vTrackedHiddenRanges->emplace_back(pBase, sz, targetProc);
		}

		ntStatus = STATUS_SUCCESS;
		break;
	}
	case INST_UNHIDE:
	{
		PEPROCESS targetProc = CurrentProcess();

		if (!EPT::UnhookRange((PVOID)kernelRequest.memoryInfo.opDstAddr, kernelRequest.memoryInfo.opSize)) {
			DbgMsg("[DRIVER] Failed unhooking 0x%llx pages at %p", kernelRequest.memoryInfo.opSize, (PVOID)kernelRequest.memoryInfo.opDstAddr);
		}
		else {
			ntStatus = STATUS_SUCCESS;
			DbgMsg("[DRIVER] Unhooked 0x%llx pages at %p", kernelRequest.memoryInfo.opSize, (PVOID)kernelRequest.memoryInfo.opDstAddr);
		}
		break;
	}
	case INST_SET_OVERLAY_HANDLE:
	{
		for (auto& procInfo : *vTrackedProcesses) {
			if (strcmp(procInfo.pImageName, kernelRequest.procInfo.pImageName) == 0) {
				DbgMsg("[DRIVER] Set overlay game process: %s - 0x%x", procInfo.pImageName, kernelRequest.procInfo.hWnd);
				procInfo.hWnd = kernelRequest.procInfo.hWnd;
				//if(MmIsAddressValid((PVOID)procInfo.pEprocess))
				//	winternl::PsEnumProcessThreads((PEPROCESS)procInfo.pEprocess, ThreadCallbackAll, &procInfo);
				ntStatus = STATUS_SUCCESS;
				break;
			}
		}
		break;
	}
	case INST_SET_DEFAULT_OVERLAY_HANDLE:
	{
		DbgMsg("[DRIVER] Set overlay default: 0x%x", kernelRequest.procInfo.hWnd);
		hWndDefault = (HANDLE)kernelRequest.procInfo.hWnd;
		ntStatus = STATUS_SUCCESS;
		break;
	}
	case INST_GET_OVERLAY_HANDLE:
	{
		for (auto& procInfo : *vTrackedProcesses) {
			if (strcmp(procInfo.pImageName, kernelRequest.procInfo.pImageName) == 0) {
				kernelRequest.procInfo.hWnd = procInfo.hWnd;
				ntStatus = STATUS_SUCCESS;
				break;
			}
		}
		break;
	}
	case INST_UNLOCK:
	{
		for (auto& procInfo : *vTrackedProcesses) {
			if (strcmp(procInfo.pImageName, kernelRequest.procInfo.pImageName) == 0) {
				DbgMsg("[DRIVER] Request unlock: %s", procInfo.pImageName);
				procInfo.lock = false;
				ntStatus = STATUS_SUCCESS;
				break;
			}
		}
		break;
	}
	case INST_UNLOCK_ALL:
	{
		DbgMsg("[DRIVER] Request unlock all");
		for (auto& procInfo : *vTrackedProcesses) {
			procInfo.lock = false;
		}
		ntStatus = STATUS_SUCCESS;
		break;
	}
	case INST_GET_INFO:
	{
		char* pProcName = (char*)kernelRequest.procInfo.pImageName;
		if (!pProcName)
			break;

		bool bFound = false;
		for (auto& procInfo : *vTrackedProcesses) {
			if (strcmp(procInfo.pImageName, pProcName) == 0) {
				DbgMsg("[DRIVER] Request info for game process: %s", procInfo.pImageName);
				DWORD64* pCr3 = kernelRequest.procInfo.cr3;
				kernelRequest.procInfo = procInfo;
				if (MmIsAddressValid(pCr3))
					*pCr3 = kernelRequest.procInfo.lastTrackedCr3;
				bFound = true;
				break;
			}
		}

		ntStatus = bFound ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
		break;
	}
	case INST_SUBSCRIBE_GAME:
	{
		char* pProcName = (char*)kernelRequest.procInfo.pImageName;
		if (!pProcName)
			break;
		int strLen = strlen(pProcName);
		char* pProcNameCopy = (char*)cpp::kMalloc(strLen + 1, PAGE_READWRITE);
		strcpy(pProcNameCopy, pProcName);
		pProcNameCopy[strLen] = 0;

		if (!kernelRequest.procInfo.cr3) {
			return STATUS_INVALID_ADDRESS;
		}
		*kernelRequest.procInfo.cr3 = 0;

		PROC_INFO procInfo;
		procInfo.pImageName = pProcNameCopy;
		procInfo.bPause = kernelRequest.procInfo.bPause;
		procInfo.mapInfo = kernelRequest.procInfo.mapInfo;
		procInfo.cr3 = kernelRequest.procInfo.cr3;
		procInfo.pRequestor = (ULONG64)CurrentProcess();

		bool bFound = false;
		for (auto& proc : *vTrackedProcesses) {
			if (strcmp(procInfo.pImageName, proc.pImageName) == 0) {
				bFound = true;
				eac::UntrackCr3(proc.cr3);
				proc.cr3 = procInfo.cr3;
				if (MmIsAddressValid(proc.cr3))
					*proc.cr3 = proc.lastTrackedCr3;
				proc.pRequestor = procInfo.pRequestor;
				eac::TrackCr3(proc.cr3, (PVOID)proc.imageBase, PsProcessDirBase(CurrentProcess()));

#ifdef INTERNAL_FACILITY
				if (MmIsAddressValid(procInfo.mapInfo.pBuffer) && procInfo.mapInfo.sz) {
					PE pe(procInfo.mapInfo.pBuffer);

					char* pBuffer = (char*)cpp::kMalloc(procInfo.mapInfo.sz);
					RtlCopyMemory(pBuffer, procInfo.mapInfo.pBuffer, procInfo.mapInfo.sz);

					char* pBufferMapped = (char*)cpp::kMalloc(pe.imageSize());
					RtlCopyMemory(pBufferMapped, pBuffer, procInfo.mapInfo.sz);

					cpp::kFree(proc.mapInfo.pBuffer);
					proc.mapInfo.pBuffer = pBufferMapped;
					proc.mapInfo.szOut = pe.imageSize();
					proc.mapInfo.bEPTHide = procInfo.mapInfo.bEPTHide;
					proc.bDllInjected = false;
					cpp::kFree(pBuffer);

					encryption::xorBytes(proc.mapInfo.pBuffer, proc.mapInfo.szOut, vmcall::GetCommunicationKey() << 1);
					DbgMsg("[DRIVER] Queried injection of 0x%llx bytes", proc.mapInfo.szOut);
				}
				else {
					proc.bDllInjected = true;
					proc.mapInfo.pBuffer = nullptr;
				}
#endif

				break;
			}
		}
		if (!bFound) {
			DbgMsg("[DRIVER] Subscribed game process: %s", procInfo.pImageName);
			procInfo.bDead = true;

#ifdef INTERNAL_FACILITY
			if (MmIsAddressValid(procInfo.mapInfo.pBuffer) && procInfo.mapInfo.sz) {
				PE pe(procInfo.mapInfo.pBuffer);

				char* pBuffer = (char*)cpp::kMalloc(procInfo.mapInfo.sz);
				RtlCopyMemory(pBuffer, procInfo.mapInfo.pBuffer, procInfo.mapInfo.sz);

				char* pBufferMapped = (char*)cpp::kMalloc(pe.imageSize());
				RtlCopyMemory(pBufferMapped, pBuffer, procInfo.mapInfo.sz);

				procInfo.mapInfo.pBuffer = pBufferMapped;
				procInfo.mapInfo.szOut = pe.imageSize();
				cpp::kFree(pBuffer);

				encryption::xorBytes(procInfo.mapInfo.pBuffer, procInfo.mapInfo.szOut, vmcall::GetCommunicationKey() << 1);
				DbgMsg("[DRIVER] Queried injection of 0x%llx bytes", proc.mapInfo.szOut);
				procInfo.bDllInjected = false;
			}
			else {
				procInfo.bDllInjected = true;
				procInfo.mapInfo.pBuffer = nullptr;
			}
#endif
			int procIdx = vTrackedProcesses->Append(procInfo);
			PROC_INFO& proc = vTrackedProcesses->at(procIdx);

			ntStatus = STATUS_SUCCESS;
		}
		else {
			ntStatus = STATUS_DUPLICATE_NAME;
		}

		break;
	}
	case INST_UNSUBSCRIBE_GAME:
	{
		int i = 0;
		bool bFound = false;
		for (auto& procInfo : *vTrackedProcesses) {
			if (procInfo.pEprocess == kernelRequest.procInfo.pEprocess) {
				DbgMsg("[DRIVER] Unsubscribed game process: %s", procInfo.pImageName);
				if (MmIsAddressValid(procInfo.mapInfo.pBuffer))
					cpp::kFree(procInfo.mapInfo.pBuffer);
				ntStatus = STATUS_SUCCESS;
				bFound = true;
				break;
			}
			i++;
		}
		if (bFound)
			vTrackedProcesses->RemoveAt(i);

		break;
	}
	case INST_CRASH_SETUP:
	{
		bugcheck::Update((PBUGCHECK_INFO)&kernelRequest.bugCheckInfo);
		ntStatus = STATUS_SUCCESS;
		break;
	}
	case INST_IDENTITY_MAP:
	{
		CR3 cr3 = { 0 };
		cr3.Flags = PsProcessDirBase(CurrentProcess());

		DbgMsg("[DRIVER] Request identity mapping from %s", winternl::GetProcessImageFileName(CurrentProcess()));

		kernelRequest.pIdentityMapping = (DWORD64)identity::MapIdentity(cr3);

		if (kernelRequest.pIdentityMapping != MAXULONG64)
			ntStatus = STATUS_SUCCESS;
		break;
	}
	case INST_IDENTITY_UNMAP:
	{
		DbgMsg("[DRIVER] Request identity unmapping from %s", winternl::GetProcessImageFileName(CurrentProcess()));
		identity::ResetCache();
		ntStatus = STATUS_SUCCESS;
		break;
	}
	case INST_BLOCK_IMAGE:
	{
#ifndef MINIMAL_BUILD
		if (!MmIsAddressValid(kernelRequest.blockInfo.pName)) {
			ntStatus = STATUS_COULD_NOT_INTERPRET;
			break;
		}
		string nameLower(kernelRequest.blockInfo.pName);
		nameLower.to_lower();

		bool bFound = false;
		for (auto& blocked : *vBlockedProcesses) {
			if (blocked.name == nameLower) {
				bFound = true;
				break;
			}
		}
		if (!bFound) {
			const char* pName = (const char*)nameLower.c_str();
			vBlockedProcesses->emplace_back(pName, kernelRequest.blockInfo.score);
		}
#endif
		ntStatus = STATUS_SUCCESS;
		break;
	}
	case INST_UNBLOCK_IMAGE:
	{
#ifndef MINIMAL_BUILD
		string nameLower(kernelRequest.blockInfo.pName);
		nameLower.to_lower();

		bool bFound = false;
		int i = 0;
		for (auto& blocked : *vBlockedProcesses) {
			if (blocked.name == nameLower) {
				vBlockedProcesses->RemoveAt(i);
				bFound = true;
				break;
			}
			i++;
		}
		if (bFound)
			ntStatus = STATUS_SUCCESS;
#endif
		break;
	}
	case INST_PROTECT:
	{
#ifndef MINIMAL_BUILD
		bool bFound = false;
		for (auto& proc : *vProtectedProcesses) {
			if (proc == CurrentProcess()) {
				bFound = true;
				break;
			}
		}
		if (!bFound) {
			vProtectedProcesses->Append(CurrentProcess());
			ntStatus = STATUS_SUCCESS;
		}
		else {
			ntStatus = STATUS_DUPLICATE_NAME;
		}
#endif
		break;
	}
	case INST_UNPROTECT:
	{
#ifndef MINIMAL_BUILD
		bool bFound = false;
		int i = 0;
		for (auto& proc : *vProtectedProcesses) {
			if (proc == CurrentProcess()) {
				vProtectedProcesses->RemoveAt(i);
				bFound = true;
				break;
			}
			i++;
		}
		if (bFound)
			ntStatus = STATUS_SUCCESS;
#endif
		break;
	}
	case INST_REGISTER_SCORE_NOTIFY:
	{
#ifndef MINIMAL_BUILD
		maxScore = kernelRequest.scoreInfo.score;
		warnScore = kernelRequest.scoreInfo.warningScore;
		untrustedScore = kernelRequest.scoreInfo.untrustedScore;
		untrustedHalfLife = kernelRequest.scoreInfo.halfLife;
		pDetected = kernelRequest.scoreInfo.pDetected;
		pWarning = kernelRequest.scoreInfo.pWarned;
		callbackProcess = CurrentProcess();
#endif
		ntStatus = STATUS_SUCCESS;
		break;
	}
	case INST_GET_SCORE:
	{
#ifndef MINIMAL_BUILD
		kernelRequest.scoreInfo.score = currScore;
#else 
		kernelRequest.scoreInfo.score = 0;
#endif
		ntStatus = STATUS_SUCCESS;
		break;
	}
	case INST_GET_MOD_TRACKING:
	{
		break;
	}
	case INST_SET_MOD_TRACKING:
	{
		break;
	}
	case INST_SET_MOD_BACKUP:
	{
		ntStatus = STATUS_SUCCESS;
		break;
	}
	case INST_SPOOF:
	{
		spoofer::SpoofAll(kernelRequest.seed);
		ntStatus = STATUS_SUCCESS;
		break;
	}
	default:
	{
		break;
	}
	}

	if (!MmIsAddressValid(pKernelRequest)) {
		DbgMsg("[DRIVER] Kernel request pointer is suddenly invalid: %p", pKernelRequest);
		return STATUS_UNSUCCESSFUL;
	}
	*pKernelRequest = kernelRequest;

	CR3 cr3 = { 0 };
	cr3.Flags = PsProcessDirBase(CurrentProcess());
	identity::MapIdentity(cr3);

	DbgMsg("[DRIVER] Kernel request completed with: 0x%x", ntStatus);
	return ntStatus;
}
