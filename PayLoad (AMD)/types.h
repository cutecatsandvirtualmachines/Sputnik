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

	typedef struct _vmcb
	{
		u16 interceptcrread;             // +0x000
		u16 interceptcrwrite;            // +0x002
		u16 interceptdrread;             // +0x004
		u16 interceptdrwrite;            // +0x006
		u32 interceptexception;          // +0x008
		u32 interceptmisc1;              // +0x00c
		u32 interceptmisc2;              // +0x010
		u8  reserved1[0x03c - 0x014];    // +0x014
		u16 pausefilterthreshold;        // +0x03c
		u16 pausefiltercount;            // +0x03e
		u64 iopmbasepa;                  // +0x040
		u64 msrpmbasepa;                 // +0x048
		u64 tscoffset;                   // +0x050
		u32 guestasid;                   // +0x058
		u32 tlbcontrol;                  // +0x05c
		u64 vintr;                       // +0x060
		u64 interruptshadow;             // +0x068
		u64 exitcode;                    // +0x070
		u64 exitinfo1;                   // +0x078
		u64 exitinfo2;                   // +0x080
		u64 exitintinfo;                 // +0x088
		u64 npenable;                    // +0x090
		u64 avicapicbar;                 // +0x098
		u64 guestpaofghcb;               // +0x0a0
		u64 eventinj;                    // +0x0a8
		u64 ncr3;                        // +0x0b0
		u64 lbrvirtualizationenable;     // +0x0b8
		u64 vmcbclean;                   // +0x0c0
		u64 nrip;                        // +0x0c8
		u8  numofbytesfetched;           // +0x0d0
		u8  guestinstructionbytes[15];   // +0x0d1
		u64 avicapicbackingpagepointer;  // +0x0e0
		u64 reserved2;                   // +0x0e8
		u64 aviclogicaltablepointer;     // +0x0f0
		u64 avicphysicaltablepointer;    // +0x0f8
		u64 reserved3;                   // +0x100
		u64 vmcbsavestatepointer;        // +0x108
		u8  reserved4[0x400 - 0x110];    // +0x110
		u16 esselector;                  // +0x000
		u16 esattrib;                    // +0x002
		u32 eslimit;                     // +0x004
		u64 esbase;                      // +0x008
		u16 csselector;                  // +0x010
		u16 csattrib;                    // +0x012
		u32 cslimit;                     // +0x014
		u64 csbase;                      // +0x018
		u16 ssselector;                  // +0x020
		u16 ssattrib;                    // +0x022
		u32 sslimit;                     // +0x024
		u64 ssbase;                      // +0x028
		u16 dsselector;                  // +0x030
		u16 dsattrib;                    // +0x032
		u32 dslimit;                     // +0x034
		u64 dsbase;                      // +0x038
		u16 fsselector;                  // +0x040
		u16 fsattrib;                    // +0x042
		u32 fslimit;                     // +0x044
		u64 fsbase;                      // +0x048
		u16 gsselector;                  // +0x050
		u16 gsattrib;                    // +0x052
		u32 gslimit;                     // +0x054
		u64 gsbase;                      // +0x058
		u16 gdtrselector;                // +0x060
		u16 gdtrattrib;                  // +0x062
		u32 gdtrlimit;                   // +0x064
		u64 gdtrbase;                    // +0x068
		u16 ldtrselector;                // +0x070
		u16 ldtrattrib;                  // +0x072
		u32 ldtrlimit;                   // +0x074
		u64 ldtrbase;                    // +0x078
		u16 idtrselector;                // +0x080
		u16 idtrattrib;                  // +0x082
		u32 idtrlimit;                   // +0x084
		u64 idtrbase;                    // +0x088
		u16 trselector;                  // +0x090
		u16 trattrib;                    // +0x092
		u32 trlimit;                     // +0x094
		u64 trbase;                      // +0x098
		u8  reserved_1[0x0cb - 0x0a0];   // +0x0a0
		u8  cpl;                         // +0x0cb
		u32 reserved_2;                  // +0x0cc
		u64 efer;                        // +0x0d0
		u8  reserved_3[0x148 - 0x0d8];   // +0x0d8
		u64 cr4;                         // +0x148
		u64 cr3;                         // +0x150
		u64 cr0;                         // +0x158
		u64 dr7;                         // +0x160
		u64 dr6;                         // +0x168
		u64 rflags;                      // +0x170
		u64 rip;                         // +0x178
		u8  reserved_4[0x1d8 - 0x180];   // +0x180
		u64 rsp;                         // +0x1d8
		u8  reserved5[0x1f8 - 0x1e0];    // +0x1e0
		u64 rax;                         // +0x1f8
		u64 star;                        // +0x200
		u64 lstar;                       // +0x208
		u64 cstar;                       // +0x210
		u64 sfmask;                      // +0x218
		u64 kernelgsbase;                // +0x220
		u64 sysentercs;                  // +0x228
		u64 sysenteresp;                 // +0x230
		u64 sysentereip;                 // +0x238
		u64 cr2;                         // +0x240
		u8  reserved6[0x268 - 0x248];    // +0x248
		u64 gpat;                        // +0x268
		u64 dbgctl;                      // +0x270
		u64 brfrom;                      // +0x278
		u64 brto;                        // +0x280
		u64 lastexcepfrom;               // +0x288
		u64 lastexcepto;                 // +0x290
	} vmcb, *pvmcb;

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
	} SPUTNIK_T, * pSPUTNIK_T;
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


	enum class vmexit_command_t
	{
		init_page_tables,
		read_guest_phys,
		write_guest_phys,
		copy_guest_virt,
		get_dirbase,
		translate
	};

	enum class vmxroot_error_t
	{
		error_success,
		pml4e_not_present,
		pdpte_not_present,
		pde_not_present,
		pte_not_present,
		vmxroot_translate_failure,
		invalid_self_ref_pml4e,
		invalid_mapping_pml4e,
		invalid_host_virtual,
		invalid_guest_physical,
		invalid_guest_virtual,
		page_table_init_failed
	};

	typedef union _command_t
	{
		struct _copy_phys
		{
			host_phys_t  phys_addr;
			guest_virt_t buffer;
			u64 size;
		} copy_phys;

		struct _copy_virt
		{
			guest_phys_t dirbase_src;
			guest_virt_t virt_src;
			guest_phys_t dirbase_dest;
			guest_virt_t virt_dest;
			u64 size;
		} copy_virt;

		struct _translate_virt
		{
			guest_virt_t virt_src;
			guest_phys_t phys_addr;
		} translate_virt;

		guest_phys_t dirbase;

	} command_t, * pcommand_t;

	using vcpu_run_t = pgs_base_struct (__fastcall*)(void*, void*, guest_context*);
}