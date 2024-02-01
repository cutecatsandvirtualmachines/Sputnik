#pragma once

#include <vector>
#include <Windows.h>
#include <string>

namespace mapper {
	NTSTATUS map_driver(std::string driver_name, uintptr_t param1, uintptr_t param2, bool bAllocationPtrParam1 = false, bool bAllocationSizeParam2 = false, uintptr_t* allocBase = 0);
	NTSTATUS map_driver(const std::vector<std::uint8_t>& raw_driver, uintptr_t param1, uintptr_t param2, bool bAllocationPtrParam1 = false, bool bAllocationSizeParam2 = false, uintptr_t* allocBase = 0);
}