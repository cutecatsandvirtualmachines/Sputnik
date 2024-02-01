#include "map_driver.h"

#include "util.hpp"
#include "drv_image.h"
#include "kernel_ctx.h"

NTSTATUS mapper::map_driver(std::string driver_name, uintptr_t param1, uintptr_t param2, bool bAllocationPtrParam1, bool bAllocationSizeParam2, uintptr_t* allocBase)
{
	std::vector<std::uint8_t> drv_buffer;
	util::open_binary_file(driver_name.c_str(), drv_buffer);
	if (!drv_buffer.size())
	{
		std::perror("[-] invalid drv_buffer size\n");
		return -1;
	}
	return map_driver(drv_buffer, param1, param2, bAllocationPtrParam1, bAllocationSizeParam2, allocBase);
}

NTSTATUS mapper::map_driver(const std::vector<std::uint8_t>& driver, uintptr_t param1, uintptr_t param2, bool bAllocationPtrParam1, bool bAllocationSizeParam2, uintptr_t* allocBase)
{
	mapper::drv_image image(driver);
	mapper::kernel_ctx ctx;

	const auto _get_export_name = [&](const char* base, const char* name)
	{
		return reinterpret_cast<std::uintptr_t>(util::get_kernel_export(base, name));
	};

	image.fix_imports(_get_export_name);
	image.map();

	void* pool_base = 0;

	if (!*allocBase) {
		pool_base =
			ctx.allocate_pool(
				image.size(),
				NonPagedPool
			);
		*allocBase = (uintptr_t)pool_base;
	}
	else {
		pool_base = (void*)*allocBase;
	}

	image.relocate(pool_base);
	ctx.write_kernel(pool_base, image.data(), image.size());
	auto entry_point = reinterpret_cast<std::uintptr_t>(pool_base) + image.entry_point();

	auto result = ctx.syscall<DRIVER_INITIALIZE>
		(
			(PVOID)entry_point,
			bAllocationPtrParam1 ? (uintptr_t)(pool_base) : (uintptr_t)(param1),
			bAllocationSizeParam2 ? (uintptr_t)(image.size()) : (uintptr_t)(param2)
		);

	return result;
}
