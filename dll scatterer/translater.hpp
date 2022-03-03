#pragma once
#include <cstdint>
#include <vector>

namespace translater {

	

	class transaction {
	private:
		
	public:
		uint64_t address;
		uint32_t instruction_size;
		bool relative;
		uint64_t new_address;
		uint8_t raw_opcodes[16];

		transaction() = default;

		transaction(uint64_t address, uint32_t instruction_size, bool relative, uint8_t* bytes) : address(address), instruction_size(instruction_size), relative(relative){
			new_address = 0;
			std::memcpy(raw_opcodes, bytes, 16);
		}
	};

	inline std::vector<transaction> transactions;

	bool get_transaction(uint64_t address, transaction& trans) {
		for (auto& el : transactions) {
			if (el.address == address) {
				trans = el;
				return true;
			}
			
		}

		return false;
	}

	uint64_t get_transaction_offset(uint64_t address) {
		for (auto& el : transactions) {

			if (address >= el.address && address <= el.address + el.instruction_size) {
			auto offset = address - el.address;
				
			return el.new_address + offset;
			}

		}

		return 0;
	}
}