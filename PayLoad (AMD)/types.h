#pragma once
#include <intrin.h>
#include <xmmintrin.h>
#include <cstddef>
#include <ntstatus.h>
#include <basetsd.h>

#include <Windows.h>
#include <ntstatus.h>
#include "ia32.hpp"
#include <SELib/Svm.h>

#define VMEXIT_KEY 0xDEADBEEFDEADBEEF
#define PAGE_4KB 0x1000
#define PAGE_2MB PAGE_4KB * 512
#define PAGE_1GB PAGE_2MB * 512

#define PORT_NUM_3 0x3E8
#define DBG_PRINT(arg) \
	__outbytestring(PORT_NUM_3, (unsigned char*)arg, sizeof arg);

using u8 = unsigned char;
using u16 = unsigned short;
using u32 = unsigned int;
using u64 = unsigned long long;
using u128 = __m128;

using guest_virt_t = u64;
using guest_phys_t = u64;
using host_virt_t = u64;
using host_phys_t = u64;

namespace svm
{
	typedef struct __declspec(align(16)) _guest_context
	{
		u8  gap0[8];
		u64 rcx;
		u64 rdx;
		u64 rbx;
		u8  gap20[8];
		u64 rbp;
		u64 rsi;
		u64 rdi;
		u64 r8;
		u64 r9;
		u64 r10;
		u64 r11;
		u64 r12;
		u64 r13;
		u64 r14;
		u64 r15;
		u128 xmm0;
		u128 xmm1;
		u128 xmm2;
		u128 xmm3;
		u128 xmm4;
		u128 xmm5;
		u128 xmm6;
		u128 xmm7;
		u128 xmm8;
		u128 xmm9;
		u128 xmm10;
		u128 xmm11;
		u128 xmm12;
		u128 xmm13;
		u128 xmm14;
		u128 xmm15;
		u8  gap180[8];
		u64 vmcb_physical_address;
	} guest_context, *pguest_context;

	typedef struct __declspec(align(16)) _vcpu_context
	{
		u8 gap0[977];
		u8 byte3D1;
		u8 byte3D2;
		u8 gap3D3[1645];
		guest_context context;
		u8 gapBD0[1];
		u8 byteBD1;
		__declspec(align(16)) u64 dr0;
		u64 dr1;
		u64 dr2;
		u64 dr3;
	} vcpu_context, *pvcpu_context;

	typedef struct __declspec(align(8)) _gs_base_struct
	{
		u8 gap0[64];
		u64* pqword40;
		u8 gap48[66392];
		vcpu_context* pvcpu_context_2;
		u8 gap103A8[8];
		vcpu_context* pvcpu_context;
	} gs_base_struct, *pgs_base_struct;

#pragma pack(push, 1)
	typedef struct _SPUTNIK_T
	{
		u64 vcpu_run_rva;
		u64 hyperv_module_base;
		u64 hyperv_module_size;
		u64 record_base;
		u64 record_size;
		u32 vmcb_base;
		u32 vmcb_link;
		u32 vmcb_off;
	} SPUTNIK_T, * PSPUTNIK_T;
#pragma pack(pop)

	__declspec(dllexport) inline SPUTNIK_T sputnik_context;

	__forceinline auto get_vmcb() -> svm::Vmcb*
	{
		return *reinterpret_cast<svm::Vmcb**>(
			*reinterpret_cast<u64*>(
				*reinterpret_cast<u64*>(
					__readgsqword(0) + sputnik_context.vmcb_base)
				+ sputnik_context.vmcb_link) + sputnik_context.vmcb_off);
	}

	using vcpu_run_t = pgs_base_struct (__fastcall*)(void*, void*, guest_context*);
}