// dllmain.cpp : Definiuje punkt wejścia dla aplikacji DLL.
#include <Windows.h>
#include <stdio.h>
#include "depend/lazy_importer.hpp"


/*

	imports are not suported!
	clang is needed for mcmodel=large and -fno-jump-tables
	its easier to handle for the injector

*/

void msg_thread() {

	LI_FN(MessageBoxA)(nullptr, "hi", "hello", MB_OK);

	while (true) {
		LI_FN(OutputDebugStringA)("hi from scattered dll!");
		LI_FN(Sleep)(1000);
	}
}


// useful for hooking pressent in dx apps
template<class T>
__forceinline auto hook_vmt(uint64_t virtual_table, uint64_t hook, size_t index) -> T {
	uintptr_t dwVTable = *((uintptr_t*)virtual_table);
	uintptr_t dwEntry = dwVTable + (index * sizeof(void*));
	uintptr_t dwOrig = *((uintptr_t*)dwEntry);

	DWORD dwOldProtection;
	LI_FN(VirtualProtect)((LPVOID)dwEntry, sizeof(dwEntry),
		PAGE_READWRITE, &dwOldProtection);

	*((uintptr_t*)dwEntry) = (uintptr_t)hook;

	LI_FN(VirtualProtect)((LPVOID)dwEntry, sizeof(dwEntry),
		dwOldProtection, &dwOldProtection);

	return (T)dwOrig;
}


static bool loaded = false;
int dll_main() {


	// make sure to load only once
	if (!loaded) {
		loaded = true;
		LI_FN(CreateThread)((LPSECURITY_ATTRIBUTES)nullptr, NULL, (LPTHREAD_START_ROUTINE)msg_thread, nullptr, NULL, nullptr);
	}
	else {
	}

	return 1;
}

