#pragma once
#include <cstdint>
#include <vector>
#include "memory.hpp"

namespace jmp_table {

	uint8_t jmp_abs[] = { 0xff, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

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

	void add_small_jmp(uint64_t base, int8_t offset) {
		uint8_t jmp_rel[] = { 0xeb, 0x00 };
		std::memcpy(jmp_abs + 1, &offset, 1);
		jmp_entry entry;
		entry.base = base;
		entry.size = 2;
		std::memcpy(&entry, jmp_rel, 2);
		table.push_back(entry);

		//printf("[+] added small jmp to jmp table at 0x%p jmp to 0x%p\n", base, base + 2 + offset);
	}

	bool map_tables() {
		// todo
		for (auto& entry : table) {
			//std::memcpy((void*)entry.base, entry.shellcode, entry.size);
			memory::write_virtual_memory((void*)entry.base, entry.shellcode, entry.size);

			//printf("[t] cpy jmptabl at:0x%p\n", entry.base);
		}

		return true;
	}
	//uint64_t add_entry();

}