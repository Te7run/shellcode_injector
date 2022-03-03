// shellcode mutation.cpp : Ten plik zawiera funkcję „main”. W nim rozpoczyna się i kończy wykonywanie programu.
// 
//

#include <iostream>
#include <vector>
#include <Windows.h>
#include "analize_instructions.hpp"
#include "dll_parser.hpp"

const char* target_process = nullptr;
const char* dll_name = nullptr;

/*

    program deassembluje specjalny plik .dll potem odtwarza go w pamieciu wirtualnej danego procesu(w wybranych lukach* pamieci)
    *luki powsaja np przez apliacje .net lub programy do nagrywania. Sa to strony RWX (read write execute), ktore mozna naduzywac do wykanania malego programu

*/

int main(int argc,char** argv)
{
    // works only in x64
    static_assert(sizeof(void*) == 8);

    if (argc < 3) {

        printf("[-] invalid usage .exe dll_name target_process (optional) minimal_scatter_threshold");
        return 0;
    }
    else {
        if (argc == 4) {
            free_regions::threshold = max(atoi(argv[3]), 50);
            printf("[+] new minimal scatter threshold is %d\n", (int)free_regions::threshold);
        }
        else if(argc > 4){
            printf("[-] invalid usage .exe dll_name target_process (optional) minimal_scatter_threshold");
            return 0;
        }
    }

    dll_name = argv[1];
    target_process = argv[2];

    if (!memory::attach(target_process)) {
        printf("[-] failed to attach to target process");
        return -1;
    }

    // executable section
    uint8_t* new_section;
    size_t section_size;
    uint64_t entry_point_rel;
    if (!dll_parser::parse(dll_name, &new_section, &section_size, &entry_point_rel)) {
        printf("[-] failed to parse dll\n");
        return 0;
    }
    printf("[+] parsed dll\n");
    

    uint64_t new_entry_point = (uint64_t)new_section + entry_point_rel;
    if (!analize::scatter_shellcode((uint8_t*)new_section, section_size, &new_entry_point)) {
        printf("[-] failed to scatter instructions\n");
        return  0;
    }
    printf("[+] scattered shellcode\n");

    if (!new_entry_point) {
        printf("[-] failed to map whole section\n");
        return 0;
    }

    printf("[+] new dll entry: 0x%p\n", new_entry_point);

    if (!dll_parser::relocate()) {
        printf("[-] failed to relocate image\n");
        return 0;
    }
    printf("[+] changed relocations\n");
    
    if (!dll_parser::check_imports()) {
        //printf("[-] imports not supported\n");
        return 0;
    }

   // CreateRemoteThreadEx(memory::handle, NULL, NULL, (LPTHREAD_START_ROUTINE)new_shellcode, NULL, NULL, NULL, NULL);
    memory::execute_dll_entry(new_entry_point);
    return 0;
}