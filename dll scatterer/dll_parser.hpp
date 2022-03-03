#pragma once
#include <cstdint>
#include <Windows.h>
#include <iostream>
#include <vector>
#include "memory.hpp"
#include "translater.hpp"

namespace dll_parser {

	inline uint8_t* image_buffer;
	inline PIMAGE_NT_HEADERS nt_headers;

	

	PVOID rva_va(uintptr_t rva, PIMAGE_NT_HEADERS nt_head, PVOID local_image)
	{
		PIMAGE_SECTION_HEADER p_first_sect = IMAGE_FIRST_SECTION(nt_head);
		for (PIMAGE_SECTION_HEADER p_section = p_first_sect; p_section < p_first_sect + nt_head->FileHeader.NumberOfSections; p_section++)
			if (rva >= p_section->VirtualAddress && rva < p_section->VirtualAddress + p_section->Misc.VirtualSize)
				return (PUCHAR)local_image + p_section->PointerToRawData + (rva - p_section->VirtualAddress);

		return NULL;
	}

	struct reloc
	{
		uint64_t address_offset;
		uint64_t virtual_offset;
		uint64_t old_value;
	};

	struct section {
		std::string name;
		uint64_t local_address;
		uint64_t virtual_offset;
		uint64_t mapped_address;
		uint32_t size;
	};

	inline std::vector<reloc> relocs;
	inline std::vector<section> sections;
	inline section instruction_section;

	// returns address in process
	uint64_t transalte_data_address(uint64_t old_address) {

		uint64_t virtual_relative = old_address - nt_headers->OptionalHeader.ImageBase;
		//printf("[+] virtual_relative 0x%p\n", virtual_relative);

		for (auto& section : sections) {
			if (virtual_relative >= section.virtual_offset && virtual_relative <= section.virtual_offset + section.size) {
				uint64_t offset = virtual_relative - section.virtual_offset;
				return section.mapped_address + offset;
			}
		}

		return 0;
	}

	// todo relocation table
	bool relocate() {
		struct reloc_entry
		{
			ULONG to_rva;
			ULONG size;
			struct
			{
				WORD offset : 12;
				WORD type : 4;
			} item[1];
		};

		//uintptr_t delta_offset = (uintptr_t)p_remote_img - nt_head->OptionalHeader.ImageBase;
		//if (!delta_offset) return true; else if (!(nt_head->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) return false;
		reloc_entry* reloc_ent = (reloc_entry*)rva_va(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, nt_headers, image_buffer);
		uintptr_t reloc_end = (uintptr_t)reloc_ent + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

		if (reloc_ent == nullptr)
			return true;

		while ((uintptr_t)reloc_ent < reloc_end && reloc_ent->size)
		{
			DWORD records_count = (reloc_ent->size - 8) >> 1;
			for (DWORD i = 0; i < records_count; i++)
			{
				WORD fix_type = (reloc_ent->item[i].type);
				WORD shift_delta = (reloc_ent->item[i].offset) % 4096;

				//printf("fix_up type %d\n", fix_type);
				
				//if(fix_type == IMAGE_REL)

				if (fix_type == IMAGE_REL_BASED_ABSOLUTE)
					continue;

				if (fix_type != IMAGE_REL_BASED_DIR64) {
					printf("[-] aborting invalid dll\n");
					return false;
				}
				uintptr_t fix_va = (uintptr_t)rva_va(reloc_ent->to_rva, nt_headers, image_buffer);

				if (!fix_va)
					fix_va = (uintptr_t)image_buffer;

				auto val = *(uintptr_t*)(fix_va + shift_delta);

				auto true_delta = fix_va + shift_delta - (uintptr_t)image_buffer;

				const auto iamge_base = nt_headers->OptionalHeader.ImageBase;
				//printf(" reloc value 0x%p virtual offset 0x%p offset address to write 0x%p\n", val, val- iamge_base, true_delta);

				relocs.push_back({ true_delta , val - iamge_base, val });
			}

			reloc_ent = (reloc_entry*)((LPBYTE)reloc_ent + reloc_ent->size);
		}
		
		for (auto& reloc : relocs) {


			uint64_t value = *(uint64_t*)(image_buffer + reloc.address_offset);
			//printf("[+] fixing reloc offset 0x%p old value 0x%p\n", reloc.address_offset, value);// reloc.old_value);

			
			//printf("cur value 0x%p", *(uint64_t*)(image_buffer + reloc.address_offset));


			//uint64_t address = 
			//translate

			auto new_adddress = translater::get_transaction_offset((uint64_t)image_buffer + reloc.address_offset);
			if (new_adddress) {
				//printf("found relocation new address 0x%p\n", new_adddress);


				// resolve to what points old address
				auto add = transalte_data_address(value);
				if (add) {
					
					memory::write_virtual_memory((void*)new_adddress, &add, 8);

					//printf("[+] fixed data reloc from 0x%p to 0x%p\n", value, add);
				}
				else {
					// convert virtual related value to local
					uint64_t value_converted = value - nt_headers->OptionalHeader.ImageBase;

					value_converted -= instruction_section.virtual_offset;
					value_converted += instruction_section.mapped_address;
					// end

					add = translater::get_transaction_offset(value_converted);
					if (!add) {
						printf("[-] unknown relocation 0x%p\n", value);
					}
					else {
						//printf("[+] fixed text reloc from 0x%p to 0x%p\n", value, add);
						memory::write_virtual_memory((void*)new_adddress, &add, 8);
					}
				}

			}
			else {

				new_adddress = transalte_data_address(nt_headers->OptionalHeader.ImageBase + reloc.virtual_offset);
				//auto add = transalte_data_address(new_adddress);
				// relocation for data
				if (new_adddress) {
					// resolve to what points old address
					auto add = transalte_data_address(value);
					if (add) {

						memory::write_virtual_memory((void*)new_adddress, &add, 8);

						//printf("[+] fixed data reloc from 0x%p to 0x%p\n", value, add);
					}
					else {
						// convert virtual related value to local
						uint64_t value_converted = value - nt_headers->OptionalHeader.ImageBase;

						value_converted -= instruction_section.virtual_offset;
						value_converted += instruction_section.mapped_address;
						// end

						add = translater::get_transaction_offset(value_converted);
						if (!add) {
							printf("[-] unknown relocation 0x%p\n", value);
						}
						else {
							//printf("[+] fixed text reloc from 0x%p to 0x%p\n", value, add);
							memory::write_virtual_memory((void*)new_adddress, &add, 8);
						}
					}
				}
				
				// ignore relocations for not mapped sections
				//printf("reloc not found for address 0x%p -> 0x%p\n", (uint64_t)image_buffer + reloc.virtual_offset, new_adddress);
			}
		}
		
		
		return true;
	}

	bool check_imports() {

		if (!nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size || !nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
			return true;
		}
		else {
			printf("[-] imports not supported\n");
			return false;
		}
		
	}

	bool parse(const char* dll_path, uint8_t** exe_section, size_t* out_size, uint64_t* out_entry_point_relative) {

		auto file_handle = CreateFileA(dll_path, GENERIC_READ, NULL, reinterpret_cast<LPSECURITY_ATTRIBUTES>(NULL), OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, reinterpret_cast<HANDLE>(NULL));
		if (file_handle == INVALID_HANDLE_VALUE) {
			printf("[-] invalid file last error 0x%X\n", GetLastError());
			return false;
		}
		const auto size = GetFileSize(file_handle, NULL);
		if (!size) {
			printf("[-] invalid file szie\n");
			return false;
		}
		// program exits immediately so no "free" needed
		image_buffer = (uint8_t*)malloc(size);

		DWORD written;
		if (!ReadFile(file_handle, image_buffer, size, &written, NULL)) {
			printf("[-] cannot read file\n");
			return false;
		}
		CloseHandle(file_handle);

		auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(image_buffer);
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
			printf("[-] invalid dos signature\n");
			return false;
		}

		nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(image_buffer + dos_header->e_lfanew);

		// map sections

		//auto dll_base = VirtualAllocEx(process_handle, NULL, nt_headers->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		//if (!dll_base) {
		//	printf("[-] failed to allocate memory for dll\n");
		//	return 0;
		//}
		//printf("[+] allocated memory at 0x%p\n", dll_base);

		uint64_t virtual_exe_section=0;

		for (size_t i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i)
		{

			auto m_section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>((uintptr_t)(&nt_headers->OptionalHeader) + nt_headers->FileHeader.SizeOfOptionalHeader);
			const auto& section = m_section_header[i];

			if (section.Characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
				printf("[+] skipping discardable section: %s\n", section.Name);
				//continue;
			}
			else if (section.Characteristics & IMAGE_SCN_LNK_REMOVE) {
				printf("[+] skipping unlinked section: %s\n", section.Name);
				//continue;
			}
			else if(section.SizeOfRawData == 0 || section.Misc.VirtualSize == 0)
			{
				printf("[+] skipping zero section: %s\n", section.Name);
				//continue;
			}
			else if(!strcmp((const char*)section.Name, ".pdata") || !strcmp((const char*)section.Name, ".xdata"))
			{
				printf("[+] skipping not used section: %s\n", section.Name);
				//continue;
			}else if (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) {
				if (virtual_exe_section != 0) {
					printf("[-] multiple executable sections not supported\n");
					return false;
				}

				printf("[+] executable section: %s found\n", section.Name);


				//printf("[+] local image 0x%p\n", image_buffer);
				const auto source = (uintptr_t)image_buffer + section.PointerToRawData;
				const auto size = min(section.SizeOfRawData, section.Misc.VirtualSize);

				//std::copy_n(m_image.begin() + section.PointerToRawData, section.SizeOfRawData, m_image_mapped.begin() + section.VirtualAddress);
				//WriteProcessMemory(process_handle, (void*)target, (void*)source, size, NULL);

				//printf("[+] copying section %s 0x%p -> 0x%p [0x%04X]\n", &section.Name[0], (void*)source, (void*)target, size);

				*exe_section = (uint8_t*)source;
				virtual_exe_section = (uintptr_t)section.VirtualAddress;
				*out_size = size;
				//std::string s_name((const char*)section.Name);
				//exe_section = { s_name, (uint64_t)source, (uint64_t)section.VirtualAddress, (uint64_t)0, size };
				std::string s_name((const char*)section.Name);
				instruction_section = { s_name, (uint64_t)source, (uint64_t)section.VirtualAddress, (uint64_t)source, size };
			}
			else {


				const auto source = (uintptr_t)image_buffer + section.PointerToRawData;
				const auto size = min(section.SizeOfRawData, section.Misc.VirtualSize);
				auto address = memory::alloc_memory(size, false);//VirtualAllocEx(process_handle, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

				memory::write_virtual_memory((void*)address, (void*)source, size);

				printf("[+] data section: %s allocated at 0x%p virtual offset 0x%p\n", section.Name, address, section.VirtualAddress);
				
				std::string s_name((const char*)section.Name);

				sections.push_back({ s_name, (uint64_t)source, (uint64_t)section.VirtualAddress, (uint64_t)address, size });
			}

		}

		*out_entry_point_relative = nt_headers->OptionalHeader.AddressOfEntryPoint - virtual_exe_section;

		/*
		uint64_t entry_rva = nt_headers->OptionalHeader.AddressOfEntryPoint;
		printf("[+] entry_rva 0x%p\n", entry_rva);

		uint64_t entry = (uint64_t)dll_base + entry_rva;
		printf("[+] entry 0x%p\n", entry);

		CreateRemoteThreadEx(process_handle, NULL, NULL, (LPTHREAD_START_ROUTINE)entry, NULL, NULL, NULL, NULL);

		*/
		//CloseHandle(process_handle);

		return true;
	}
}
