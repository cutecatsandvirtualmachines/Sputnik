#pragma once

#include "cpp.h"
#include "MemoryEx.h"
#include "VectorEx.h"
#include "Vmcall.h"
#include "Vmexit.h"
#include "event.h"
#include "identity.h"
#include "StringArray.h"

#include <SharedCheatLibrary\communication.hpp>

/*
* When enabled it will disable handle stripping and score mechanism
*/
#define MINIMAL_BUILD

/*
* When disabled it will not use internal injection modules
*/
//#define INTERNAL_FACILITY

#ifdef _KERNEL_MODE

typedef struct _PROCESS_MODULE_INFO {
	char* pImageName;
	PDLL_TRACK_INFO pDllTrackInfo;

	__forceinline bool operator==(_PROCESS_MODULE_INFO& rhs) {
		return !memcmp(&rhs, this, sizeof(rhs));
	}
	__forceinline bool operator!=(_PROCESS_MODULE_INFO& rhs) {
		return !(*this == rhs);
	}
} PROCESS_MODULE_INFO, *PPROCESS_MODULE_INFO;

typedef struct _BLOCKED_PROCESS_INFO {
	string name;
	BOOLEAN bRan;
	DWORD score;

	_BLOCKED_PROCESS_INFO(const char* _name, DWORD _score) : name(_name), bRan(false), score(_score) {};
	_BLOCKED_PROCESS_INFO() : name(""), bRan(false), score(0) {};

	__forceinline bool operator==(_BLOCKED_PROCESS_INFO& rhs) {
		return rhs.name == name;
	}
	__forceinline bool operator!=(_BLOCKED_PROCESS_INFO& rhs) {
		return !(*this == rhs);
	}
} BLOCKED_PROCESS_INFO, *PBLOCKED_PROCESS_INFO;

namespace comms {
	BOOLEAN Init();
	NTSTATUS Entry(KERNEL_REQUEST* pKernelRequest);
}

#endif