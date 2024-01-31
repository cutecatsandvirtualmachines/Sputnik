#pragma once

#include <SELib/IDT.h>
#include <Arch/Segmentation.h>
#include <SELib/pe.h>
#include "types.h"

typedef union _UNWIND_CODE {
    UINT8 CodeOffset;
    UINT8 UnwindOp : 4;
    UINT8 OpInfo : 4;
    UINT16 FrameOffset;
} UNWIND_CODE;

typedef struct _UNWIND_INFO {
    UINT8 Version : 3;
    UINT8 Flags : 5;
    UINT8 SizeOfProlog;
    UINT8 CountOfCodes;
    UINT8 FrameRegister : 4;
    UINT8 FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];

    union {
        UINT32 ExceptionHandler;
        UINT32 FunctionEntry;
    };

    UINT32 ExceptionData[1];
} UNWIND_INFO;

namespace exception {
    extern IDT HostIdt;
    extern Seg::DescriptorTableRegister<Seg::Mode::longMode> IdtReg;

    extern "C" void seh_handler_ecode_vm(PIDT_REGS_ECODE regs);
    extern "C" void seh_handler_vm(PIDT_REGS regs);

    //When an unhandled exception occurs it will use these params to call the original hyper-v handler
    void SaveOrigParams(void* unknown, void* unknown2, svm::pguest_context context, Seg::DescriptorTableRegister<Seg::Mode::longMode> idt, void* rsp);
}