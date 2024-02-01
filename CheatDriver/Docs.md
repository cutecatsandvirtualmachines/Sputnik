# It's baller time 

## Driver communication interface

You can communicate to the kernel mode driver via Kernel Calls.
During setup a callback address will be given, or one can be retrieved by doing a VMCALL
with the correct communication key:

```
#include "comms.h"

PVOID GetCallback() {
	PVOID Callback = 0;
	CPU::CPUIdVmcall(VMCALL_GET_CALLBACK, (ULONG64)&Callback, 0, _sklibKey);
	return Callback;
}
```

Then, using a VDM-like interface (you should use SKLibVdm inside vdm.h) you can hijack a syscall to communicate with the driver using 
instruction(or communication) codes.

```
typedef enum : ULONG
{
	INST_GET_INFO = 1,
	INST_RESET_INFO,
	INST_MAP,
	INST_HIDE,
	INST_UNHIDE,
	INST_GET_OVERLAY_HANDLE,
	INST_SET_OVERLAY_HANDLE,
	INST_UNLOCK,
	INST_SUBSCRIBE_GAME,
	INST_UNSUBSCRIBE_GAME
} COMM_CODE, *PCOMM_CODE;
```
_NOTE: Codes might change in the future_

Such interface gives the application access to a number of features, like process creation stalling (freezing),
selective window and memory hiding, and process information gathering.

### Step 1

Before being able to actually use any of said features you must register the application you want to control via its name.

_NOTE: App name is case sensitive by design_

Assuming all next functions to be inside a class caching the callback address and sklib key:

```
BOOLEAN RegisterApp(char* pAppName) {
	KERNEL_REQUEST kernelRequest = { 0 };
	kernelRequest.instructionID = INST_SUBSCRIBE_GAME;
	kernelRequest.procInfo.pImageName = pAppName;
	kernelRequest.procInfo.bFreeze = false;
	if (!vdm.CallbackInvoke(&kernelRequest)) {
		Log("Failed registering process: %s", pAppName);
		return FALSE;
	}
	return TRUE;
}
```

If one wants to use the process creation stalling on this process, set bFreeze to true.

By activating process stalling, everytime the target process is created, execution will stall until a 
release call is invoked by the user mode application, to give back control to the process original creator.

This proves to be very useful in defeating protections based on internal injections of code by the anti-cheat,
since by stalling execution the creator will think the process is still creating, while in fact its already running.

You can then gather whatever protected info you need and release the lock via the given call:

_NOTE: This will release all process instances at once_
```
BOOLEAN ReleaseProcess(char* pAppName) {
	KERNEL_REQUEST kernelRequest = { 0 };
	kernelRequest.instructionID = INST_UNLOCK;
	kernelRequest.procInfo.pImageName = pAppName;
	if (!vdm.CallbackInvoke(&kernelRequest)) {
		Log("Failed unlocking process: %s", pAppName);
		return FALSE;
	}
	return TRUE;
}
```

### Step 2

Now every time a process with said name is started, some of the process info will be cached by the driver.
Such info can be retrieved with a single operation:

```
PROC_INFO GetProcInfo(char* pAppName) {
	KERNEL_REQUEST kernelRequest = { 0 };
	kernelRequest.instructionID = INST_GET_INFO;
	kernelRequest.procInfo.pImageName = pAppName;
	if (!vdm.CallbackInvoke(&kernelRequest)) {
		Log("Failed getting info for process: %s", pAppName);
	}
	return kernelRequest.procInfo;
}
```

Also, thread and process creation for monitored processes may invoke callbacks for predefined operations, such as window hiding.
Each process can only have a single hidden window, but you can specify different windows for each of them.

_NOTE: A process is identified by its name, therefore copies of the same process can't be assigned different windows to hidee_

```
BOOLEAN SetWindowToHide(char* pAppName, HWND hWnd) {
	KERNEL_REQUEST kernelRequest = { 0 };
	kernelRequest.instructionID = INST_SET_OVERLAY_HANDLE;
	kernelRequest.procInfo.pImageName = pAppName;
	kernelRequest.procInfo.hWnd = hWnd;
	if (!vdm.CallbackInvoke(&kernelRequest)) {
		Log("Failed hiding window 0x%x for process: %s", hWnd, pAppName);
		return FALSE;
	}
	return TRUE;
}
```

After being set once, every time this process creates a new thread the callback will be notified to hide
your window from it.
This refresh can be forced by setting the overlay handle via the showed code.

### Step 3

After you're done mapping your code and started your threads, you may also want to hide your process memory
from external threads.

To do so a memory hiding interface using EPT is available.

#### IMPORTANT: to hide memory with EPT such memory must be locked in RAM. The locking might fail if the size of the memory block is too big. This can be extended by calling SetProcessWorkingSetSize.

```
BOOLEAN HideMemory(char* pAppName, PVOID pMemoryBase, SIZE_T szMemory) {
	KERNEL_REQUEST kernelRequest = { 0 };
	kernelRequest.instructionID = INST_HIDE;
	kernelRequest.procInfo.pImageName = pAppName;
	kernelRequest.memoryInfo.opDstAddr = pMemoryBase;
	kernelRequest.memoryInfo.opSize = szMemory;
	if (!vdm.CallbackInvoke(&kernelRequest)) {
		Log("Failed hiding memory at %p for process: %s", pMemoryBase, pAppName);
		return FALSE;
	}
	return TRUE;
}
```

It is recommended for an implementation to hide only specific sections of the binary, as any hidden memory will be visible only to EPT hidden code.

### Step 4 (optional)

It is recommended to let the kernel component handle memory unhiding. All hidden memory in a process will be automatically unhidden once said process dies.

If you still want to unhide said memory you can use the following request.

```
BOOLEAN UnhideMemory(char* pAppName, PVOID pMemoryBase, SIZE_T szMemory) {
	KERNEL_REQUEST kernelRequest = { 0 };
	kernelRequest.instructionID = INST_UNHIDE;
	kernelRequest.procInfo.pImageName = pAppName;
	kernelRequest.memoryInfo.opDstAddr = pMemoryBase;
	kernelRequest.memoryInfo.opSize = szMemory;
	if (!vdm.CallbackInvoke(&kernelRequest)) {
		Log("Failed unhiding memory at %p for process: %s", pMemoryBase, pAppName);
		return FALSE;
	}
	return TRUE;
}
```

### Important note on EPT hidden memory
If a code region is hidden with EPT from r/w, said code will be able to access a "shadow EPT" where there are no r/w restrictions.  
This means that if an identity mapping was requested by the program, then accessing physical memory using said identity mapping  
from EPT protected code, will result in the program being able to r/w into EPT protected memory regions, bypassing said protection.

## Steps before running the hypervisor

Please make sure to check all of these before running the hv, and in case of BSOD

### Enable virtualization and IOMMU(AMD)/VT-d(Intel) from BIOS
IOMMU/VT-d could also be called I/O virtualization or DMA protection in BIOS settings depending
on your motherboard

### Disable kernel CET
https://www.elevenforum.com/t/enable-or-disable-kernel-mode-hardware-enforced-stack-protection-in-windows-11.14966/

### Disable vulnerable driver blocklist
Defender settings -> Device security -> Microsoft Vulnerable Driver Blocklist

**Or via registry**

reg add Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CI\Config /v "VulnerableDriverBlocklistEnable" /t REG_DWORD /d 0 /f

### Disable Hyper-v
Go to Services and check for any service called Hyper-v, if one of them is enabled then you need to disable Hyper-v
https://www.makeuseof.com/windows-11-disable-hyper-v/

### Disable WSL
https://pureinfotech.com/uninstall-wsl-windows-11/

## Internal related features

The kernel interface offers the possibility to automatically map and hide an arbitrary DLL inside a subscribed process as soon as said process is starting.

The DLL has to be a buffer in memory, and should be passed as it would be from disk (no pre-mapping done).

Additionally the kernel mapped does not have API set resolution capabilities, which means any dependencies to API set dlls won't be resolved.
Only already loaded DLLs at the time of mapping will be considered for import resolution. If an import references a not loaded DLL, the import won't be resolved.

**Important: the mapped DLL will be automatically EPT shadowed, which means it will be visible as 0 filled pages from any non-shadowed code**

```
	std::ifstream File("TestDll.dll", std::ios::binary | std::ios::ate);
	if (File.fail()) {
		File.close();
		return false;
	}
	//Tellg takes the current cursor position, therefore getting the file length
	auto FileSize = File.tellg();
	auto pSrcData = new BYTE[static_cast<UINT_PTR>(FileSize)];
	//Seeks to the beginning after reading file length
	File.seekg(0, std::ios::beg);
	//Put file in memory to the memory pointed to by pSrcData
	File.read(reinterpret_cast<char*>(pSrcData), FileSize);
	//Close file stream
	File.close();

	kernelRequest.instructionID = INST_SUBSCRIBE_GAME;
	kernelRequest.procInfo.pImageName = (char*)"RustClient.exe";
	kernelRequest.procInfo.mapInfo.pBuffer = pSrcData;
	kernelRequest.procInfo.mapInfo.sz = FileSize;
	if (!vdm.CallbackInvoke(&kernelRequest)) {
		Log("Failed subscribing game");
	}
	else {
		kernelRequest.instructionID = INST_LOCK_MODULE;
		kernelRequest.procInfo.pImageName = (char*)"GameAssembly.dll";
		if (!vdm.CallbackInvoke(&kernelRequest)) {
			Log("Failed requesting module shadowing");
		}
	}
```

As shown from the code snippet, it's also possible, using INST_LOCK_MODULE, to lock an arbitrary module in place for a specific subscribed process.

Said locking is extremely important if one wants to use the usermode memory shadowing interface, extremely useful for hooking and patching code.

```
	kernelRequest.instructionID = INST_SHADOW;
	kernelRequest.memoryInfo.opSize = PAGE_SIZE;
	kernelRequest.memoryInfo.opDstAddr = (ULONG64)kernelRequest.procInfo.lastDllBase + 0x1470;
	if (!vdm.CallbackInvoke(&kernelRequest)) {
		Log("Failed requesting module shadowing: 0x%llx", (ULONG64)kernelRequest.procInfo.imageBase + 0x1470);
	}
```

Both interfaces INST_SHADOW and INST_LOCK_MODULE use the kernelRequest.procInfo.cr3 as reference to which subscribed process to select.

The shown snippet applies a shadowing onto the selected page (the entire page will be shadowed), which means that as long as you use **vmcalls**
or **EPT protected code** to write into said memory (using identity mapping for instance), the write will go "through" the shadowing, allowing you to
make completely _invisible_ inline patches.
