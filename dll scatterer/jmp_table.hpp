#pragma once
#include <cstdint>
#include <vector>
#include "memory.hpp"

namespace jmp_table {
	struct jmp_entry
	{
		uint8_t shellcode[14];
		uint64_t base;
		uint32_t size;
	};

	std::vector<jmp_entry> table;

	void add_entry(uint64_t base, uint64_t address) {

		uint8_t jmp_abs[] = { 0xff, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		std::memcpy(jmp_abs + 6, &address, 0x8);
		jmp_entry entry;
		entry.base = base;
		entry.size = 14;
		std::memcpy(&entry, jmp_abs, 14);
		table.push_back(entry);

		//printf("[+] added jmp table at 0x%p jmp to 0x%p\n", base, address);
	}
	bool map_tables() {
		for (auto& entry : table) {
			//std::memcpy((void*)entry.base, entry.shellcode, entry.size);
			memory::write_virtual_memory((void*)entry.base, entry.shellcode, entry.size);

			//printf("[t] cpy jmptabl at:0x%p\n", entry.base);
		}

		return true;
	}

}
