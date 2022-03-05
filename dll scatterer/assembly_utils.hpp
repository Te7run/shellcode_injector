#pragma once
#include <cstdint>
#include <iostream>
#include "capstone/capstone.h"

namespace assembly_utils {

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

	bool has_group(const cs_insn* inst, const x86_insn_group group) {
		const uint8_t grpSize = inst->detail->groups_count;

		for (int i = 0; i < grpSize; i++) {
			if (inst->detail->groups[i] == group)
				return true;
		}
		return false;
	}

	bool is_jmp_instruction(const cs_insn* inst) {
		return has_group(inst, X86_GRP_BRANCH_RELATIVE);
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
					continue;
				}

				//types like push 0x20 slip through, check mnemonic
				if (strcmp(mnemonic, "call") != 0 && strcmp(mnemonic, "jmp") != 0)
					continue;

				return true;
			}
		}


		return false;
	}
}
