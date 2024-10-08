#include <Windows.h>
#include <string>
#include <intrin.h>
#include <filesystem>
#include <fstream>

#include "debug.h"

#include <mapper/map_driver.h>
#include <vdm.hpp>
#include <Arch/Pte.h>
#include <identity.hpp>
#include <mapper/kernel_ctx.h>
#include <data.h>
#include <Setup.hpp>

SELibVdm vdm;

std::wstring FindEFIPartition(void)
{
	TCHAR volumeName[260];
	HANDLE firstVolume = FindFirstVolume(volumeName, 260);
	if (firstVolume == INVALID_HANDLE_VALUE)
		return L"";

	HANDLE next = firstVolume;
	GUID efiPart;
	efiPart.Data1 = 0xc12a7328;
	efiPart.Data2 = 0xf81f;
	efiPart.Data3 = 0x11d2;
	efiPart.Data4[0] = 0xba;
	efiPart.Data4[1] = 0x4b;
	efiPart.Data4[2] = 0x00;
	efiPart.Data4[3] = 0xa0;
	efiPart.Data4[4] = 0xc9;
	efiPart.Data4[5] = 0x3e;
	efiPart.Data4[6] = 0xc9;
	efiPart.Data4[7] = 0x3b;
	//c12a7328-f81f-11d2-ba4b-00a0c93ec93b
	while (FindNextVolume(next, volumeName, 260)) {
		PARTITION_INFORMATION_EX partinfo;
		DWORD fuck;

		int len = wcslen(volumeName);
		volumeName[len - 1] = L'\0';

		HANDLE file = CreateFileW(volumeName, GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
			OPEN_EXISTING, 0, NULL);

		volumeName[len - 1] = L'\\';

		DeviceIoControl(file, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, &partinfo, sizeof(partinfo), &fuck, NULL);
		CloseHandle(file);

		if (partinfo.PartitionStyle == PARTITION_STYLE_GPT) {
			if (partinfo.Gpt.PartitionType == efiPart) {
				FindVolumeClose(next);
				return volumeName;
			}
		}
	}
	FindVolumeClose(next);
	return L"";
}

bool DoesEditionSupportHyperV() {

	DWORD dwPInfo = NULL;
	DWORD dwVersion = NULL;
	DWORD dwMajorVersion = NULL;
	DWORD dwMinorVersion = NULL;
	GetProductInfo(6, 2, 0, 0, &dwPInfo);
	switch (dwPInfo) {
	case PRODUCT_ULTIMATE:
	case PRODUCT_HYPERV:
	case PRODUCT_PRO_WORKSTATION:
	case PRODUCT_PROFESSIONAL:
	case PRODUCT_ENTERPRISE:
	case PRODUCT_EDUCATION:
	case PRODUCT_STANDARD_SERVER:
	case PRODUCT_STANDARD_SERVER_CORE:
		return true;
	default:
		return false;
	}
}

bool IsIntel() // returns true on an Intel processor, false on anything else
{
	int id_str[4] = { 0 }; // The first four characters of the vendor ID string

	__cpuid(id_str, 0);

	if (id_str[3] == 0x6c65746e) // letn. little endian clobbering of GenuineI[ntel]
		return true;
	else
		return false;
}

int Main() {
	const std::wstring efiPart = FindEFIPartition();
	if (efiPart.empty())
	{
		DbgLog("Could not find EFI partition!");
		return -1;
	}

	const std::wstring bootmgfwBackupPath = efiPart + L"EFI\\Microsoft\\Boot\\bootmgfw.efi.backup";
	const std::wstring payloadPath = efiPart + L"EFI\\Microsoft\\Boot\\payload.dll";
	const std::wstring bootmgfwPath = efiPart + L"EFI\\Microsoft\\Boot\\bootmgfw.efi";
	const std::wstring bootmgrPath = efiPart + L"EFI\\Microsoft\\Boot\\bootmgr.efi";
	WIN32_FILE_ATTRIBUTE_DATA fileAttributes;
	GetFileAttributesExW(bootmgrPath.c_str(), GetFileExInfoStandard, &fileAttributes);
	HANDLE file = CreateFileW(bootmgfwPath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	SetFileTime(file, &fileAttributes.ftCreationTime, &fileAttributes.ftLastAccessTime, &fileAttributes.ftLastWriteTime);
	CloseHandle(file);

	bool IsSecureBootEnabled = FALSE;
	bool IsUEFI = true;
	bool IsCorrectEdition = DoesEditionSupportHyperV();
	bool IsVirtualisationEnabled = false;
	bool IsHyperVEnabled = false;
	if (GetFirmwareEnvironmentVariable(L"", L"{00000000-0000-0000-0000-000000000000}", NULL, 0) == 0) {
		if (GetLastError() == ERROR_INVALID_FUNCTION) {
			IsUEFI = false;
		}
	}
	if (efiPart.empty())
		IsUEFI = false;
	int returnLength = GetFirmwareEnvironmentVariable(L"SecureBoot",
		L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}", &IsSecureBootEnabled, sizeof(IsSecureBootEnabled));

	if (returnLength != sizeof(IsSecureBootEnabled)) {
		//HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\State
		int secureBoot = 0;
		DWORD sizeOfVar = sizeof(secureBoot);
		bool success = ERROR_SUCCESS == RegGetValueA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", "UEFISecureBootEnabled", REG_DWORD, nullptr /*type not required*/, &secureBoot, &sizeOfVar);

		if (success)
			IsSecureBootEnabled = secureBoot != 0;
	}
	int info[4];
	__cpuid(info, 1);

	if (info[2] & (1 << 5 /*VMX*/))
		IsVirtualisationEnabled = true;
	if (info[2] & (1 << 31 /*VMX*/)) {
		IsVirtualisationEnabled = true;
		__cpuid(info, 0x40000000);
		if (info[1] == 0x7263694D)
			IsHyperVEnabled = true;
	}

	__cpuid(info, 0x40000000);
	if (info[1] == 0x7263694D) {
		IsVirtualisationEnabled = true;
		IsHyperVEnabled = true;
		DbgLog("Virtualization is enabled!");
	}
	else {
		DbgLog("Virtualization is not enabled!");
	}

	bool CanLoadHypervisor = !IsSecureBootEnabled && IsUEFI && IsCorrectEdition && IsVirtualisationEnabled && IsHyperVEnabled;

	if (!CanLoadHypervisor) {
		DbgLog("Cannot load hypervisor!");
		return -1;
	}

	std::ifstream File("Sputnik.efi", std::ios::binary | std::ios::ate);
	if (File.fail()) {
		File.close();
		DbgLog("Cannot open Sputnik.efi!");
		return -1;
	}
	auto FileSize = File.tellg();
	auto pSrcData = new BYTE[static_cast<UINT_PTR>(FileSize)];
	File.seekg(0, std::ios::beg);
	File.read(reinterpret_cast<char*>(pSrcData), FileSize);
	File.close();

	char* name = (char*)"PayLoad (AMD).dll";
	if (IsIntel()) {
		name = (char*)"PayLoad (Intel).dll";
		DbgLog("This is an Intel machine!");
	}
	else {
		DbgLog("This is an AMD machine!");
	}
	std::ifstream payload(name, std::ios::binary | std::ios::ate);
	if (payload.fail()) {
		payload.close();
		DbgLog("Cannot open %s!", name);
		return -1;
	}
	auto FileSizePayload = payload.tellg();
	auto pSrcDataPayload = new BYTE[static_cast<UINT_PTR>(FileSizePayload)];
	payload.seekg(0, std::ios::beg);
	payload.read(reinterpret_cast<char*>(pSrcDataPayload), FileSizePayload);
	payload.close();

	bool success = false;
	if (SetFileAttributesW(bootmgfwPath.c_str(), FILE_ATTRIBUTE_NORMAL)) {
		if (!std::filesystem::exists(bootmgfwBackupPath)) {
			DbgLog("Bootmgfw backup does not exist!");
			if (MoveFileW(bootmgfwPath.c_str(), bootmgfwBackupPath.c_str())) {
				HANDLE bootmgfw = CreateFileW(bootmgfwPath.c_str(), (GENERIC_READ | GENERIC_WRITE), 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

				if (bootmgfw != INVALID_HANDLE_VALUE) {
					DWORD written;
					WriteFile(bootmgfw, pSrcData, FileSize, &written, NULL);
					HANDLE payload = CreateFileW(payloadPath.c_str(), (GENERIC_READ | GENERIC_WRITE), 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
					if (payload != INVALID_HANDLE_VALUE) {
						DbgLog("Saved payload!");
						WriteFile(payload, pSrcDataPayload, FileSizePayload, &written, NULL);
						CloseHandle(payload);
						CloseHandle(bootmgfw);
						success = true;
					}
					else
					{
						DbgLog("Saved backup!");
						CloseHandle(bootmgfw);
						MoveFileW(bootmgfwBackupPath.c_str(), bootmgfwPath.c_str());
					}
				}
				else
				{
					DbgLog("Restored backup!");
					MoveFileW(bootmgfwBackupPath.c_str(), bootmgfwPath.c_str());
				}
			}
		}
		else {
			DbgLog("Bootmgfw backup exists!");
			success = true;
			HANDLE bootmgfw = CreateFileW(bootmgfwPath.c_str(), (GENERIC_READ | GENERIC_WRITE), 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

			if (bootmgfw != INVALID_HANDLE_VALUE) {
				DWORD written;
				WriteFile(bootmgfw, pSrcData, FileSize, &written, NULL);
				DbgLog("Bootmgfw backup overridden!");
			}
			else
			{
				DbgLog("Restored backup!");
				MoveFileW(bootmgfwBackupPath.c_str(), bootmgfwPath.c_str());
			}
		}

		if (!std::filesystem::exists(payloadPath)) {
			DbgLog("Payload does not exist!");
		}
		else {
			DbgLog("Payload exists!");
			HANDLE payload = CreateFileW(payloadPath.c_str(), (GENERIC_READ | GENERIC_WRITE), 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (payload != INVALID_HANDLE_VALUE) {
				DbgLog("Overridden payload!");
				DWORD written;
				WriteFile(payload, pSrcDataPayload, FileSizePayload, &written, NULL);
				CloseHandle(payload);
				success = true;
			}
		}
	}
	else {
		DbgLog("Restored backup!");
		MoveFileW(bootmgfwBackupPath.c_str(), bootmgfwPath.c_str());
	}

	sputnik::set_vmcall_key(0xbabababa);
	vdm.Init(0xbabababa, 0);

	DWORD64 cr3 = sputnik::current_dirbase();
	DbgLog("CR3: 0x%llx", cr3);
	DWORD64 ncr3 = sputnik::current_ept_base();
	DbgLog("nCR3: 0x%llx", ncr3);

	auto res = identity::Init(cr3);
	DbgLog("Identity setup: %d", res);

	DWORD64 callback = sputnik::storage_get<DWORD64>(VMX_ROOT_STORAGE::CALLBACK_ADDRESS);
	if (!callback) {
		ULONG64 driverBase = 0;

		USERMODE_INFO uInfo = { 0 };
		if (!setup::InitOffsets(uInfo.offsets)) {
			DbgLog("Could not initialise offsets");
			return false;
		}
		uInfo.loaderProcId = GetCurrentProcessId();
		uInfo.spooferSeed = 0x4712abb3892;
		uInfo.vmcallKey = sputnik::VMEXIT_KEY;

		auto status = mapper::map_driver(
			"CheatDriver.sys",
			0,
			(ULONG64)&uInfo,
			true,
			false,
			&driverBase
		);
		DbgLog("Driver status: 0x%x", status);

		if (!NT_SUCCESS(status)) {
			mapper::kernel_ctx ctx;
			ctx.free_pool((void*)driverBase);
			return -1;
		}
	}
	
	callback = sputnik::storage_get<DWORD64>(VMX_ROOT_STORAGE::CALLBACK_ADDRESS);
	DbgLog("Callback: 0x%llx", callback);

	DWORD64 driverPa = sputnik::storage_get<DWORD64>(VMX_ROOT_STORAGE::DRIVER_BASE_PA);
	DbgLog("Driver pa: 0x%llx", driverPa);
	
	mapper::kernel_ctx ctx;
	sputnik::storage_set(VMX_ROOT_STORAGE::CURRENT_CONTROLLER_PROCESS, ctx.get_peprocess(GetCurrentProcessId()));

	DbgLog("Current Process: %p", sputnik::storage_get<PEPROCESS>(VMX_ROOT_STORAGE::CURRENT_CONTROLLER_PROCESS));
	vdm.Init(callback);
	
	KERNEL_REQUEST req;
	req.instructionID = INST_REGISTER_SCORE_NOTIFY;
	NTSTATUS ntStatus = -1;
	BOOLEAN bSuccess = vdm.CallKernelFunction(&ntStatus, callback, &req);
	DbgLog("Callback invoke test: 0x%x - 0x%x", bSuccess, ntStatus);
	//ctx.free_pool((void*)driverBase);
	
	DWORD64 value = 0xbeefbeef;
	DWORD64 valueWrite = 0xdeaddead;
	DbgLog("Write result: 0x%x", sputnik::write_virt((u64)&value, (u64)&valueWrite, sizeof(valueWrite), cr3));
	DbgLog("0x0: 0x%llx", value);
	DbgLog("0x0: 0x%llx", *(DWORD64*)identity::phyToVirt(0));
	DbgLog("Driver 0x0: 0x%llx", *(DWORD64*)identity::phyToVirt(driverPa));

	return 0;
}

int main() {
	Main();
	system("pause");
}