# This document describes the parameters required for each kernel call

### INST_GET_INFO
- KERNEL_REQUEST.procInfo.pImageName:  
finding subscribed process
- KERNEL_REQUEST.procInfo.cr3:  
getting the last saved cr3
- [OUT] KERNEL_REQUEST.procInfo.pPeb:  
process PEB as seen by the target (not a local copy)
- [OUT] KERNEL_REQUEST.procInfo.pEprocess:  
process EPROCESS pointer as seen by the target (not a local copy)
- [OUT] KERNEL_REQUEST.procInfo.imageBase:  
process main module base
- [OUT] KERNEL_REQUEST.procInfo.bDead:  
true if the process has died
- [OUT] KERNEL_REQUEST.procInfo.dwPid:  
PID of the last caught subscribed process.
- [OUT] KERNEL_REQUEST.procInfo.mapInfo.pBufferOut:  
if a buffer was passed on process subscription, this holds the base address of the mapped module
- [OUT] KERNEL_REQUEST.procInfo.mapInfo.szOut:  
holds the size of the mapped module, if any
- [OUT] KERNEL_REQUEST.procInfo.dllQueueShadow:  
is not 0 when one or more modules are waiting to be locked in memory after a call to INST_LOCK_MODULE.
- [OUT] KERNEL_REQUEST.procInfo.lastDllBase:  
holds the base address of the last locked module. Useful when only 1 module is registered to avoid parsing the MemoryOrder module list in PEB.
- [OUT] KERNEL_REQUEST.procInfo.bDllInjected:  
true if the registered DLL has been injected

### INST_RESET_INFO
- KERNEL_REQUEST.procInfo.pImageName:  
finding subscribed process

### INST_MAP
- KERNEL_REQUEST.procInfo.mapInfo.pBuffer:  
pointer to usermode buffer containing the image to map (should be as it would be taken from disk)
- KERNEL_REQUEST.procInfo.mapInfo.sz:  
size of the buffer
- KERNEL_REQUEST.procInfo.dwPid:  
pid of the process to inject into
- [OUT] KERNEL_REQUEST.procInfo.mapInfo.pBufferOut:  
returns the pointer to the allocated buffer inside the selected process
- [OUT] KERNEL_REQUEST.procInfo.mapInfo.szOut:  
size of the returned buffer

#### Remarks
INST_MAP will overwrite the saved kernel copy of KERNEL_REQUEST.procInfo.mapInfo.pBufferOut, therefore should only be used for debugging.  

INST_MAP will attach to the target process, do not use with EAC protected processes.  

INST_MAP will lock the allocated buffer in RAM.  

### INST_HIDE
- KERNEL_REQUEST.procInfo.pEprocess / KERNEL_REQUEST.procInfo.dwPid:  
used to select the correct process to attach to for hiding memory
- kernelRequest.memoryInfo.opDstAddr:  
destination of the required shadowing
- kernelRequest.memoryInfo.opSize:  
size of the required shadowing

#### Remarks
INST_HIDE will attach to the target process, do not use with EAC protected processes.  

INST_HIDE locks the memory in RAM, then performs EPT shadowing. As such it can cause crashes if spammed, do not use for testing.  

INST_HIDE targeted memory is automatically tracked and "unprotected" when the target process dies.  

### INST_UNHIDE
#### Deprecated

### INST_SET_DEFAULT_OVERLAY_HANDLE
- KERNEL_REQUEST.procInfo.hWnd:  
HWND to be registered for hiding for all processes

#### Remarks
INST_SET_DEFAULT_OVERLAY_HANDLE will only hide the window for processes/threads started after this call.

### INST_GET_OVERLAY_HANDLE
- KERNEL_REQUEST.procInfo.pImageName:  
finding subscribed process
- [OUT] KERNEL_REQUEST.procInfo.hWnd:  
HWND registered for hiding for the specified process

### INST_SET_OVERLAY_HANDLE
- KERNEL_REQUEST.procInfo.pImageName:  
finding subscribed process
- KERNEL_REQUEST.procInfo.hWnd:  
HWND to be registered for hiding for the specified process

#### Remarks
INST_SET_OVERLAY_HANDLE will override any set default HWND to hide for all processes.

### INST_UNLOCK
- KERNEL_REQUEST.procInfo.pImageName:  
finding subscribed process

### INST_UNLOCK_ALL
[NOPARAMS]

### INST_CRASH_SETUP
#### Deprecated

### INST_SUBSCRIBE_GAME
- KERNEL_REQUEST.procInfo.pImageName:  
subscribed process name
- KERNEL_REQUEST.procInfo.cr3:  
pointer to a cr3 that will be updated at each writecr3
- KERNEL_REQUEST.procInfo.bPause:  
[DEPRECATED]
- [OPTIONAL] KERNEL_REQUEST.procInfo.mapInfo.pBuffer:  
usermode buffer holding an optional image to map into the subscribed process as soon as it's first thread is started
- [OPTIONAL] KERNEL_REQUEST.procInfo.mapInfo.sz:  
size of the buffer
- [OPTIONAL] KERNEL_REQUEST.procInfo.mapInfo.bEPTHide:  
if to automatically shadow the entire module with EPT on map

#### Remarks
KERNEL_REQUEST.procInfo.cr3 should not be a shared value between different subscribed processes, as it's used as an identifier.  

INST_SUBSCRIBE_GAME will always lock onto the first process matching the given name. If multiple instances of the process are started
only the first one will be caught.

PROC_INFO will be reset every time the subscribed process dies.  

INST_SUBSCRIBE_GAME will keep a copy of the given module in kernel, encrypted, and will keep on mapping the image every time the game is restarted.  

Subsequent calls to INST_SUBSCRIBE_GAME will update these parameters:
- KERNEL_REQUEST.procInfo.cr3
- KERNEL_REQUEST.procInfo.mapInfo.pBuffer
- KERNEL_REQUEST.procInfo.mapInfo.sz

Once a subscribed process has an associated module registered for mapping, it can only be substituted, but never manually removed.

The registered DLL for mapping will automatically be unregistered as soon as the requestor process dies, requiring a new call to INST_SUBSCRIBE_GAME
for a new DLL to be mapped the next time the subscribed process starts.

### INST_UNSUBSCRIBE_GAME
- KERNEL_REQUEST.procInfo.pImageName:  
subscribed process name

### INST_IDENTITY_MAP
- [OUT] KERNEL_REQUEST.pIdentityMapping:  
Base address of the 512GB identity mapping.

#### Remarks
The mapping will automatically be deleted on process death as to avoid PG BSODs.  

Only one process at a time can get the identity mapping. If another process is holding it, the call will fail.  

Subsequent calls will return the same base address until the process is restarted.

### INST_IDENTITY_UNMAP
[NOPARAMS]

### INST_LOCK_MODULE
- KERNEL_REQUEST.procInfo.cr3:  
used to identify the subscribed process. Should be the same passed into INST_SUBSCRIBE_GAME.
- KERNEL_REQUEST.procInfo.pImageName: 
NULL terminated C string containing the name of the module to lock in memory.

#### Remarks
Multiple modules can be registered for locking in memory.  

The entire module will be locked.  

A backup of the entire module is automatically made as to avoid a bug where modified read-only pages will persist across multiple process reboots,
causing the module to crash on next start if hooks or patches were applied beforehand.

### INST_SHADOW
- KERNEL_REQUEST.procInfo.cr3:  
used to identify the subscribed process. Should be the same passed into INST_SUBSCRIBE_GAME.
- KERNEL_REQUEST.procInfo.memoryInfo.opDstAddr:  
destination address inside the target process.
- KERNEL_REQUEST.procInfo.memoryInfo.opSize:  
size of the buffer to EPT shadow

#### Remarks
INST_SHADOW differs from INST_HIDE as it doesn't attach, therefore can be used on EAC protected games.  

INST_SHADOW differs from INST_HIDE as it will use a copy of the shadowed pages, instead of zeroed out pages, making the memory look untampered.  

INST_SHADOW **requires** the memory to be locked, therefore it is highly advised to only call it on memory coming from INST_LOCK_MODULE.  

### INST_BLOCK_IMAGE
- KERNEL_REQUEST.blockInfo.pName:  
name of the process to block
- KERNEL_REQUEST.blockInfo.score:  
score that will be added when this process is found

#### Remarks
The score is added only the first time the process is found.  

### INST_UNBLOCK_IMAGE
- KERNEL_REQUEST.blockInfo.pName:   
name of the process to unblock

### INST_PROTECT
[NOPARAMS]

#### Remarks
**All** processes besides for taskmgr will have any handle open requests on the requestor process be denied, until the process dies.

### INST_UNPROTECT
[NOPARAMS]

### INST_REGISTER_SCORE_NOTIFY
- KERNEL_REQUEST.scoreInfo.score:  
max score before a detection is triggered
- KERNEL_REQUEST.scoreInfo.warningScore:  
max score before a warning is triggered
- KERNEL_REQUEST.scoreInfo.untrustedScore:  
score added each time an unsigned process tries to open an handle to a protected process
- KERNEL_REQUEST.scoreInfo.halfLife:  
time in seconds after which the untrusted score is halved (useful to avoid false positive score buildups over time)
- KERNEL_REQUEST.scoreInfo.pDetected:  
pointer to a boolean that will be set to true when the score gets over the allowed detection max
- KERNEL_REQUEST.scoreInfo.pWarned:  
pointer to a boolean that will be set to true when the score gets over the allowed warning max

#### Remarks
Internally the block score and untrusted score are different, as one is given from the processes blocked from starting,
while the other is given by unsigned/untrusted processes interacting with protected processes.

### INST_GET_SCORE
- [OUT] KERNEL_REQUEST.scoreInfo.score:  
total score so far

### INST_GET_MOD_TRACKING
#### Deprecated

### INST_SET_MOD_TRACKING
#### Deprecated

### INST_SET_MOD_BACKUP
- KERNEL_REQUEST.procInfo.pEprocess:  
target process for the backup
- KERNEL_REQUEST.procInfo.cr3:  
cr3 pointer, not used for identification, but must lead to a valid cr3 for the target process
- KERNEL_REQUEST.procInfo.imageBase:  
base of the memory buffer that needs to be later restored
- KERNEL_REQUEST.procInfo.mapInfo.pBuffer:  
base of the local buffer holding the value to restore into imageBase
- KERNEL_REQUEST.procInfo.mapInfo.sz:  
size of the local buffer

#### Remarks
Backups restore the memory on process exit, and are one shot.  

After the backup has been triggered it will need to be re-registered to have effect again.

