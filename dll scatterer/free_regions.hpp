#pragma once
#include <cstdint>
#include <vector>
#include <Windows.h>
#include <algorithm>
#include "memory.hpp"

namespace free_regions {

	struct region {
		uint64_t address;
		uint32_t size;
	};

	inline std::vector<region> regios;

	// minimum size of free memory
	inline size_t threshold = 50;

	void get_free_regions() {
		
		size_t abs_size = 0;

		MEMORY_BASIC_INFORMATION mem_info;
		uint64_t current_address = 0x10000;
		while (memory::query_memory(current_address, &mem_info)) {

			if ((mem_info.Protect == PAGE_EXECUTE_READWRITE) && mem_info.State == MEM_COMMIT) {

				auto buffer = (uint8_t*)malloc(mem_info.RegionSize);
				if (!buffer)
					continue;

				memory::read_virtual_memory(buffer, mem_info.BaseAddress, mem_info.RegionSize);

				size_t current_region_size = 0;
				size_t region_offset = 0;

				for (auto i = 0u; i < mem_info.RegionSize; ++i) {

					if (buffer[i] == 0x00 || buffer[i] == 0xCC) {
						current_region_size++;
					}
					else {

						if (current_region_size > threshold) {
							//printf("[+] found free region at 0x%p size %d\n", (uint64_t)(mem_info.BaseAddress) + region_offset, (uint32_t)current_region_size);
							regios.push_back({ (uint64_t)(mem_info.BaseAddress) + region_offset,  (uint32_t)current_region_size });
							abs_size += current_region_size;
						}

						current_region_size = 0;
						region_offset = i+1;
					}

				}

				// is page free til the end
				if (current_region_size > threshold) {
					regios.push_back({ (uint64_t)(mem_info.BaseAddress) + region_offset,  (uint32_t)current_region_size });
					abs_size += current_region_size;
				}

				free(buffer);

			}


			current_address = (uint64_t)mem_info.BaseAddress + mem_info.RegionSize;
		}
		
		// sort vector so dll gets less scattered = better performance
		
		std::sort(regios.begin(), regios.end(), [](const region&  a, const region& b) -> bool {
			return a.size > b.size;
			});
			
		
		printf("[+] total free memory found %d\n", abs_size);
	}
}