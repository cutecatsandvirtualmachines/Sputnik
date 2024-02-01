#pragma once

#include <SKLib.h>
#include <VTx.h>

#include <ntddk.h>

NTSTATUS DriverEntryInit(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);
VOID UnloadDriver(PDRIVER_OBJECT pDriverObject);