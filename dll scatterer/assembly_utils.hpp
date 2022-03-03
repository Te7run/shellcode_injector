#pragma once
#include <cstdint>
#include <iostream>
#include "capstone/capstone.h"

namespace assembly_utils {

	enum displacement : uint8_t {
		d_int64 = 8,
		d_int32 = 4,
		d_int16 = 2,
		d_int8 = 1,
		d_invalid = 0
	};

	displacement get_displacement_type(uint8_t disp) {
		switch (disp)
		{
		case 1:
			return displacement::d_int8;
		case 2:
			return displacement::d_int16;
		case 4:
			return displacement::d_int32;
		case 8:
			return displacement::d_int64;
		default:
			return displacement::d_invalid;
		}
	}

	bool is_conditional_jmp(uint8_t* bytes, size_t size) {
		//http://unixwiz.net/techtips/x86-jumps.html
		if (size < 1)
			return false;

		if (bytes[0] == 0x0F && size > 1)
		{
			if (bytes[1] >= 0x80 && bytes[1] <= 0x8F)
				return true;
		}

		if (bytes[0] >= 0x70 && bytes[0] <= 0x7F)
			return true;

		if (bytes[0] == 0xE3)
			return true;

		return false;
	}

	template<class T>
	T get_displacement(uint8_t* instruction, uint32_t offset) {
		T disp;
		std::memset(&disp, 0x0, sizeof(T));
		std::memcpy(&disp, &instruction[offset], sizeof(T));
		return disp;
	}

	void relocate(cs_insn* cur_ins, uint64_t from, uint64_t to, uint8_t disp_size, uint8_t disp_offset) {
		printf("[+] relocating...");

		const auto disp_type = get_displacement_type(disp_size);
		if (disp_type == displacement::d_int8) {
			uint8_t disp = get_displacement<uint8_t>(cur_ins->bytes, disp_offset);
			disp -= (to - from);
			*(uint8_t*)(cur_ins->address + disp_offset) = disp;
		}
		else if (disp_type == displacement::d_int16) {
			uint16_t disp = get_displacement<uint16_t>(cur_ins->bytes, disp_offset);
			disp -= (to - from);
			*(uint16_t*)(cur_ins->address + disp_offset) = disp;
		}
		else if (disp_type == displacement::d_int32) {
			uint32_t disp = get_displacement<uint32_t>(cur_ins->bytes, disp_offset);
			disp -= (to - from);
			*(uint32_t*)(cur_ins->address + disp_offset) = disp;
		}
	}

	bool has_group(const cs_insn* inst, const x86_insn_group group) {
		const uint8_t grpSize = inst->detail->groups_count;

		for (int i = 0; i < grpSize; i++) {
			if (inst->detail->groups[i] == group)
				return true;
		}
		return false;
	}

	bool is_jmp_instruction(const cs_insn* inst) {
		//const bool isCalling = has_group(inst, x86_insn_group::X86_GRP_CALL);
		//const bool branches = isCalling || has_group(inst, x86_insn_group::X86_GRP_JUMP);

		return has_group(inst, X86_GRP_BRANCH_RELATIVE);// || has_group(inst, X86_GRP_JUMP);
	}

	size_t get_rel_jmp_address_size(long long diff) {
		if (abs(diff) <= 0x7F) {
			return 1;
		}

		if (abs(diff) <= 0x7FFFFFFF) {
			return 4;
		}

		return 8;
	}

	size_t get_jmp_size(long long diff) {
		if (abs(diff) <= 0x7F) {
			return 2;
		}

		if (abs(diff) <= 0x7FFFFFFF) {
			return 5;
		}

		return 14;
	}

	bool is_instruction_relative(cs_insn* cur_inst, cs_x86* x86) {
		for (auto j = 0u; j < x86->op_count; ++j) {
			cs_x86_op* op = &(x86->operands[j]);
			if (op->type == X86_OP_MEM)
			{
				// MEM are types like lea rcx,[rip+0xdead]
				if (op->mem.base == X86_REG_INVALID) {
					continue;
				}
				
				//Are we relative to instruction pointer?
				if (op->mem.base != X86_REG_EIP) {
					continue;
				}

				return true;
			}
			else if (op->type == X86_OP_IMM) {
				//IMM types are like call 0xdeadbeef
				if (x86->op_count > 1) //exclude types like sub rsp,0x20
					continue;

				char* mnemonic = cur_inst->mnemonic;
				if (is_conditional_jmp(cur_inst->bytes, cur_inst->size))
				{
					return true;
					//RelocateConditionalJMP(CurIns, CodeSize, From, To, x86->offsets.imm_size, x86->offsets.imm_offset);
					continue;
				}

				//types like push 0x20 slip through, check mnemonic
				if (strcmp(mnemonic, "call") != 0 && strcmp(mnemonic, "jmp") != 0) //probably more types than just these, update list as they're found
					continue;

				return true;
				//_Relocate(CurIns, From, To, x86->offsets.imm_size, x86->offsets.imm_offset);
			}
		}


		return false;
	}

	void relocate_instructions(uint8_t* code, size_t* code_size, uint64_t from, uint64_t to) {
		cs_insn* inst;
		csh capstone_handle;

		if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone_handle) != CS_ERR_OK)
			return;
		cs_option(capstone_handle, CS_OPT_DETAIL, CS_OPT_ON);
		size_t inst_count = cs_disasm(capstone_handle, code, *code_size, (uintptr_t)code, 0, &inst);

		for (auto i = 0u; i < inst_count; ++i) {
			cs_insn* cur_inst = (cs_insn*)&inst[i];
			cs_x86* x86 = &(cur_inst->detail->x86);
			
			for (auto j = 0u; j < x86->op_count; ++j) {
				cs_x86_op* op = &(x86->operands[j]);
				if (op->type == X86_OP_MEM)
				{
					// MEM are types like lea rcx,[rip+0xdead]
					if (op->mem.base == X86_REG_INVALID)
						continue;

					//Are we relative to instruction pointer?
					if (op->mem.base != X86_REG_EIP) {
						printf("[+] instruction related to rip\n");
						continue;
					}

					//relocate(inst, from, to, x86->, x86->offsets.displacement_offset);
				}
				else if (op->type == X86_OP_IMM) {
					//IMM types are like call 0xdeadbeef
					if (x86->op_count > 1) //exclude types like sub rsp,0x20
						continue;

					char* mnemonic = cur_inst->mnemonic;
					if (is_conditional_jmp(cur_inst->bytes, cur_inst->size))
					{
						//RelocateConditionalJMP(CurIns, CodeSize, From, To, x86->offsets.imm_size, x86->offsets.imm_offset);
						continue;
					}

					//types like push 0x20 slip through, check mnemonic
					if (strcmp(mnemonic, "call") != 0 && strcmp(mnemonic, "jmp") != 0) //probably more types than just these, update list as they're found
						continue;

					//_Relocate(CurIns, From, To, x86->offsets.imm_size, x86->offsets.imm_offset);
				}
			}
			
		}

		cs_free(inst, inst_count);
		cs_close(&capstone_handle);
	}
}