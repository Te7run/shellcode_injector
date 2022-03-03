#pragma once
#include <Windows.h>
#include <cstdint>

namespace memory {
	inline HANDLE handle;
	inline DWORD pid;
	inline DWORD tid;

	uint32_t get_pid(const char* window_name, PDWORD out_thread_id = NULL) {
		auto handle = FindWindowA(reinterpret_cast<LPCSTR>(window_name), reinterpret_cast<LPCSTR>(NULL));
		if (handle == 0) {
			handle = FindWindowA(reinterpret_cast<LPCSTR>(NULL), reinterpret_cast<LPCSTR>(window_name));
			if (handle == 0)
				return 0;
		}
		DWORD pid = 0;
		DWORD tid = GetWindowThreadProcessId(handle, &pid);
		if (out_thread_id)
			*out_thread_id = tid;
		return pid;
	}

	bool attach(const char* window_name) {

		pid = get_pid(window_name, &tid);
		if (!pid) return false;
		handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

		return (handle != INVALID_HANDLE_VALUE);
	}

	void write_virtual_memory(void* target, void* source, size_t size) {
		WriteProcessMemory(handle, (void*)target, (void*)source, size, NULL);
	}

	void read_virtual_memory(void* local_buffer, void* target, size_t size) {
		ReadProcessMemory(handle, target, local_buffer, size, NULL);
	}

	uint64_t alloc_memory(size_t size, bool executable) {
		return (uint64_t)VirtualAllocEx(handle, NULL, size, MEM_RESERVE | MEM_COMMIT, executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE);
	}

	bool query_memory(uint64_t address, PMEMORY_BASIC_INFORMATION basic_info) {
		return (VirtualQueryEx(handle, (void*)address, basic_info, sizeof(MEMORY_BASIC_INFORMATION)) != NULL);
	}

	void execute_dll_entry(uint64_t address) {
		printf("[*] calling dll entry...\n");


		// not usual technique
		auto hook = SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)address, LoadLibraryA("User32.dll"), tid);
		if (!hook) {
			printf("[-] SetWindowsHookEx failed\n");
			return;
		}
		PostThreadMessage(tid, WM_NULL, 0, 0);
		Sleep(10);
		// make sure entry was called
		PostThreadMessage(tid, WM_NULL, 0, 0);
		UnhookWindowsHookEx(hook);

		printf("[+] done\n");
	}

	void secure_memory(uint64_t address, size_t size) {
		;//
	}
}