#pragma once

#include "capstone/capstone.h"
#include "assembly_utils.hpp"
#include "translater.hpp"
#include "free_regions.hpp"
#include "jmp_table.hpp"
#include "memory.hpp"

namespace analize {

	size_t make_jmp(uint8_t** out_buffer, uint64_t from, uint64_t to) {
		uint8_t near_jmp[] = { 0xEB, 0x00 };
		uint64_t delta = to - from - sizeof(near_jmp);
		near_jmp[1] = (uint8_t)delta;
		*out_buffer = (uint8_t*)malloc(sizeof(near_jmp));
		std::memcpy(*out_buffer, near_jmp, sizeof(near_jmp));
		return sizeof(near_jmp);
	}

	bool add_transactions(uint8_t* shellcode, size_t size) {
		csh handle;
		cs_insn* inst;
		size_t count;

		if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
			return false;
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		count = cs_disasm(handle, shellcode, size, (size_t)shellcode, 0, &inst);

		for (int i = 0ul; i < count; i++) {

			cs_insn* cur_inst = (cs_insn*)&inst[i];
			cs_x86* x86 = &(cur_inst->detail->x86);

			//printf("[disasm] 0x%p: %s %s ", inst[i].address, inst[i].mnemonic, inst[i].op_str);

			bool relative_instruction = assembly_utils::is_instruction_relative(cur_inst, x86);

			translater::transactions.push_back({ inst[i].address, inst[i].size, relative_instruction, inst[i].bytes });
			if (relative_instruction) {
				//printf(" relative instruction");
			}

			//printf("\n");
		}

		cs_free(inst, count);
		cs_close(&handle);
		return true;
	}

	bool base_relocation() {
		size_t padding = 14;// jmp to next section

		size_t instruction_index = 0;
		size_t instructions_offset = 0;
		const auto transactions_size = translater::transactions.size();

		if (!transactions_size)
			return true;

		size_t relocations_count = 0;

		for (auto i = 0u; i < free_regions::regios.size(); ++i) {
			// skip invalid regions

			auto& region = free_regions::regios[i];

			if (region.size < padding)
				continue;

			// we are done 1
			if (instruction_index >= transactions_size)
				break;

			// make sure we can fit this instruction
			auto current_padding = padding + translater::transactions[instruction_index].instruction_size;

			while (instructions_offset < region.size - current_padding) {

				// we are done 2
				if (instruction_index >= transactions_size)
					break;

				// is next instruction relative
				if (instruction_index + 1 < transactions_size && translater::transactions[instruction_index + 1].relative) {
					// add jmp table size
					current_padding += 28;
				}

				translater::transactions[instruction_index].new_address = region.address + instructions_offset;
				//printf("[+] relocating instruction from 0x%p to 0x%p size %d\n", translater::transactions[instruction_index].address, translater::transactions[instruction_index].new_address, translater::transactions[instruction_index].instruction_size);

				if (translater::transactions[instruction_index].relative) {
					// make space for jmp table :>
					instructions_offset += 28;
					//printf("[+] made 28 bytes padding for jmp table\n");
					// reset padding
					current_padding -= 28;
				}

				

				instructions_offset += translater::transactions[instruction_index].instruction_size;
				instruction_index = instruction_index + 1;
			}

			// we are done 3
			if (instruction_index >= transactions_size)
				break;

			// make jmp if we cant fit more instructions
			if ((i+1) < free_regions::regios.size()) {
				relocations_count++;
				jmp_table::add_entry(region.address + instructions_offset, free_regions::regios[(i + 1)].address);
				//printf("[+] added jmp table for memory block\n");
			}


			instructions_offset= 0;
		}

		if (instruction_index < transactions_size) {
			printf("[-] not enought memory\n");
			return false;
		}

		printf("[+] made %d relocations\n", relocations_count);

		return true;
	}

	bool relocate_instructions() {

		csh handle;
		cs_insn* inst;
		size_t count;

		if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
			return false;
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

		auto transactions = translater::transactions;

		//const auto transactions_count = translater::transactions.size();

		for (auto i = 0u; i < translater::transactions.size(); ++i) {

			auto& trans = transactions[i];

			

			//printf("dis: %s %s\n", inst[0].mnemonic, inst[0].op_str);

			if (trans.relative) {

				count = cs_disasm(handle, (uint8_t*)trans.address, trans.instruction_size, (size_t)trans.address, 0, &inst);
				
				if (count != 1) {
					printf("[-] assembler error\n");
					return false;
				}

				cs_insn* cur_inst = &inst[0];
				cs_x86 x86 = cur_inst->detail->x86;
				cs_x86_encoding encoding = x86.encoding;
				
				

				if (assembly_utils::is_jmp_instruction(cur_inst)) {
					//printf("[+] resolving jmp instruction\n");

					uint64_t old_target = 0;

					if (encoding.disp_offset) {
						//printf("[+] displcement offset %d size %d\n", encoding.disp_offset, encoding.disp_size);
					}
					else if (encoding.imm_offset) {
						//printf("[+] displcement offset %d size %d\n", encoding.imm_offset, encoding.imm_size);
						switch (encoding.imm_size)
						{
						case 1: {
							uint64_t rel_jmp;// = cur_inst->bytes[encoding.imm_offset];
							std::memcpy(&rel_jmp, &cur_inst->bytes[encoding.imm_offset], encoding.imm_size);
							//printf("[+] rel jmp 0x%X\n", rel_jmp);

							// relative to new instruction
							old_target = inst->address + inst->size + (int8_t)rel_jmp;
							break;
						}
						case 2: {
							uint64_t rel_jmp;
							std::memcpy(&rel_jmp, &cur_inst->bytes[encoding.imm_offset], encoding.imm_size);
							//printf("[+] rel jmp 0x%X\n", rel_jmp);

							// relative to new instruction
							old_target = inst->address + inst->size + (int16_t)rel_jmp;

							break;
						}
						case 4: {
							uint64_t rel_jmp;
							std::memcpy(&rel_jmp, &cur_inst->bytes[encoding.imm_offset], encoding.imm_size);
							//printf("[+] rel jmp 0x%X\n", rel_jmp);

							// relative to new instruction
							old_target = inst->address + inst->size + (int32_t)rel_jmp;

							break;
						}
						case 8:

							// skip abbsolute addressing
							continue;
							break;
						default:
							printf("[-] abort: invalid imm size\n");
							return false;
							break;
						}


						translater::transaction target_instruction;
						translater::transaction current_instruction;
						if (!translater::get_transaction(old_target, target_instruction)) {
							// points to other module?
							printf("[-] error transaction not found\n");
							continue;
						}
						if (!translater::get_transaction(inst->address, current_instruction)) {
							printf("[-] error transaction not found\n");
							continue;
						}

						//printf("[+] old target 0x%p new target 0x%p\n", old_target, target_instruction.new_address);

						if (i + 1 >= translater::transactions.size()) {
							printf("[-] assembly error\n");
							return false;
						}
						// contine code flow
						jmp_table::add_entry(current_instruction.new_address + current_instruction.instruction_size, transactions[i + 1].new_address);

						// point jcc to this
						jmp_table::add_entry(current_instruction.new_address + current_instruction.instruction_size + 14, target_instruction.new_address);


						/*
						printf("old bytes: ");
						for (int k = 0u; k < encoding.imm_size; ++k) {
							printf("0x%X ", *(uint8_t*)(translater::transactions[i].raw_opcodes + encoding.imm_offset));
						}
						printf("\n");
						*/

						//change jcc
						// signed value
						int64_t rel_jmp = 14; // 14 is size of avs jmp to maintain code flow
						std::memcpy(translater::transactions[i].raw_opcodes + encoding.imm_offset, &rel_jmp, encoding.imm_size);
						/*
						printf("new bytes: ");
						for (int k = 0u; k < encoding.imm_size; ++k) {
							printf("0x%X ", *(uint8_t*)(translater::transactions[i].raw_opcodes + encoding.imm_offset));
						}
						printf("\n");
						*/
					}
					else {
						printf("[-] abort: invalid instruction\n");
						return false;
					}
				}
				else if (false) {

				}
				else {
					printf("[-] aborting: unknown relative instrucion %s %s\n", cur_inst->mnemonic, cur_inst->op_str);
					cs_free(inst, count);
					return false;
				}

				cs_free(inst, count);
			}

			
		}

		
		cs_close(&handle);

		return true;
	}

	bool map_code() {
		for (auto i = 0u; i < translater::transactions.size(); ++i) {

			auto& trans = translater::transactions[i];

			memory::write_virtual_memory((void*)trans.new_address, trans.raw_opcodes, trans.instruction_size);
			//std::memcpy((void*)trans.new_address, trans.raw_opcodes, trans.instruction_size);

			//printf("[i] cpy ins f:0x%p t:0x%p\n", trans.address, trans.new_address);
		}

		return true;
	}

	uint64_t get_entry_point(uint64_t old_entry) {

		translater::transaction trans;

		if (!translater::get_transaction(old_entry, trans))
			return 0;

		return trans.new_address;
	}

	bool scatter_shellcode(uint8_t* shellcode, size_t size, uint64_t* entry) {

		if (!add_transactions(shellcode, size)) {
			printf("[-] disassembler error\n");
			return false;
		}

		free_regions::get_free_regions();

		if (!base_relocation()) {
			printf("[-] failed to relocate\n");
			return false;
		}

		if (!relocate_instructions()) {
			printf("[-] failed to relocate instructions\n");
			return false;
		}

		if (!jmp_table::map_tables()) {
			printf("[-] failed to map tables\n");
			return false;
		}
		//printf("[+] mapped tables\n");
		if (!map_code()) {
			printf("[-] failed to map instructions\n");
			return false;
		}

		*entry = get_entry_point(*entry);
		return true;
	}

}
