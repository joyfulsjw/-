// dllmain.cpp : DLL 응용 프로그램의 진입점을 정의합니다.
#include "stdafx.h"
#include <stdio.h>
#include "Settings.h"
#include "ntdll.h"
#include "kernel32.h"
#include "RemoteHook.h"
#include "HookedFunctions.h"
#include "Peb.h"
#include "NtApiShim.h"


#define HOOK_NATIVE(name) { hdd->d##name = (t_##name)DetourCreateRemoteNative(hProcess, "" STR(name) "", (void*)_##name, Hooked##name, true, &hdd->name##BackupSize);if (hdd->d##name == nullptr) { return false; } }
t_KiUserExceptionDispatcher _KiUserExceptionDispatcher = 0;

namespace scl
{
	HOOK_DLL_DATA hooked = { 0, };
}


void log(const WCHAR* msg)
{
	MessageBox(0, msg, L"log", 0);
}

#define DbgBreakPoint_FUNC_SIZE 2
#ifdef _WIN64
#define DbgUiRemoteBreakin_FUNC_SIZE 0x42
#define NtContinue_FUNC_SIZE 11
#else
#define DbgUiRemoteBreakin_FUNC_SIZE 0x54
#define NtContinue_FUNC_SIZE 0x18
#endif

typedef struct _PATCH_FUNC {
	const char * funcName;
	PVOID funcAddr;
	SIZE_T funcSize;
} PATCH_FUNC;

PATCH_FUNC patchFunctions[] = {
	{
		"DbgBreakPoint", 0, DbgBreakPoint_FUNC_SIZE
	},
	{
		"DbgUiRemoteBreakin", 0, DbgUiRemoteBreakin_FUNC_SIZE
	},
	{
		"NtContinue", 0, NtContinue_FUNC_SIZE
	}
};

bool ApplyAntiAntiAttach(HANDLE hProcess)
{
	bool result = false;
	if (!hProcess)
		return result;

	HMODULE hMod = GetModuleHandleW(L"ntdll.dll");

	for (ULONG i = 0; i < _countof(patchFunctions); i++)
	{
		patchFunctions[i].funcAddr = (PVOID)GetProcAddress(hMod, patchFunctions[i].funcName);
	}

	for (ULONG i = 0; i < _countof(patchFunctions); i++)
	{
		ULONG oldProtection;
		if (VirtualProtectEx(hProcess, patchFunctions[i].funcAddr, patchFunctions[i].funcSize, PAGE_EXECUTE_READWRITE, &oldProtection) &&
			WriteProcessMemory(hProcess, patchFunctions[i].funcAddr, patchFunctions[i].funcAddr, patchFunctions[i].funcSize, nullptr))
		{
			VirtualProtectEx(hProcess, patchFunctions[i].funcAddr, patchFunctions[i].funcSize, oldProtection, &oldProtection);
			result = true;
		}
		else
		{
			result = false;
			break;
		}
	}

	CloseHandle(hProcess);

	return result;
}

void patchPEB(scl::Settings g_settings, HANDLE hProcess)
{
	/*
	PROCESS_BASIC_INFORMATION pbi = { 0 };
	HMODULE hmod_ntdll = LoadLibrary(L"ntdll.dll");
	typedef NTSTATUS(*type_NtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
	type_NtQueryInformationProcess proc_NtQueryInformationProcess = (type_NtQueryInformationProcess)GetProcAddress(hmod_ntdll, "NtQueryInformationProcess");
	proc_NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);
	auto peb_addr = pbi.PebBaseAddress;
	PEB peb = { 0, };
	ReadProcessMemory(hProcess, peb_addr, &peb, sizeof(peb), nullptr);
	*/

	PROCESS_BASIC_INFORMATION pbi = { 0 };
	HMODULE hmod_ntdll = LoadLibrary(L"ntdll.dll");
	typedef NTSTATUS(*type_NtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
	type_NtQueryInformationProcess proc_NtQueryInformationProcess = (type_NtQueryInformationProcess)GetProcAddress(hmod_ntdll, "NtQueryInformationProcess");
	auto status = proc_NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);
	auto peb_addr = (PEB *)pbi.PebBaseAddress;
	PEB* peb = (PEB*)malloc(sizeof(PEB));
	memset(peb, 0, sizeof(PEB));
	ReadProcessMemory(hProcess, peb_addr, peb, sizeof(PEB), nullptr);

	peb->BeingDebugged = 0;


	if (g_settings.profile_.fixPebBeingDebugged)
	{
		peb->BeingDebugged = 0;
		WriteProcessMemory(hProcess, peb_addr, peb, sizeof(PEB), nullptr);
	}

	if (g_settings.profile_.fixPebHeapFlags)
	{
		//log(L"fixPebHeapFlags");

#define RTLDEBUGCREATEHEAP_HEAP_FLAGS   (HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED | HEAP_SKIP_VALIDATION_CHECKS)
#define NTGLOBALFLAGS_HEAP_FLAGS        (HEAP_DISABLE_COALESCE_ON_FREE | HEAP_FREE_CHECKING_ENABLED | HEAP_TAIL_CHECKING_ENABLED | HEAP_VALIDATE_ALL_ENABLED | HEAP_VALIDATE_PARAMETERS_ENABLED | HEAP_CAPTURE_STACK_BACKTRACES)
#define HEAP_CLEARABLE_FLAGS            (RTLDEBUGCREATEHEAP_HEAP_FLAGS | NTGLOBALFLAGS_HEAP_FLAGS)
#ifndef FLG_HEAP_ENABLE_TAIL_CHECK
#define FLG_HEAP_ENABLE_TAIL_CHECK 0x10
#endif

#ifndef FLG_HEAP_ENABLE_FREE_CHECK
#define FLG_HEAP_ENABLE_FREE_CHECK 0x20
#endif

#ifndef FLG_HEAP_VALIDATE_PARAMETERS
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#endif

#ifndef HEAP_SKIP_VALIDATION_CHECKS
#define HEAP_SKIP_VALIDATION_CHECKS 0x10000000
#endif

#ifndef HEAP_VALIDATE_PARAMETERS_ENABLED
#define HEAP_VALIDATE_PARAMETERS_ENABLED 0x40000000
#endif

#ifndef DBG_PRINTEXCEPTION_WIDE_C
#define DBG_PRINTEXCEPTION_WIDE_C ((DWORD)0x4001000A)
#endif
#define HEAP_VALIDATE_ALL_ENABLED       0x20000000
#define HEAP_CAPTURE_STACK_BACKTRACES   0x08000000

#define HEAP_CLEARABLE_FORCE_FLAGS      (HEAP_CLEARABLE_FLAGS & HEAP_VALID_FORCE_FLAGS)
#define HEAP_VALID_FORCE_FLAGS          (HEAP_NO_SERIALIZE | HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY | HEAP_REALLOC_IN_PLACE_ONLY | HEAP_VALIDATE_PARAMETERS_ENABLED | HEAP_VALIDATE_ALL_ENABLED | HEAP_TAIL_CHECKING_ENABLED | HEAP_CREATE_ALIGN_16 | HEAP_FREE_CHECKING_ENABLED)



#ifdef _WIN64


		std::vector<PVOID64> heaps;
		heaps.resize(peb->NumberOfHeaps);

		ReadProcessMemory(hProcess, (PVOID64)peb->ProcessHeaps, (PVOID64)heaps.data(), heaps.size() * sizeof(PVOID64), nullptr);

		std::basic_string<uint8_t> heap;
		heap.resize(peb->NumberOfHeaps); // hacky
		DWORD offsetProcessHeap = 0x30;
		DWORD HeapFlagsOffset = 0x70;
		DWORD HeapForceFlagsOffset = 0x74;

		for (DWORD i = 0; i < peb->NumberOfHeaps; i++)
		{
			ReadProcessMemory(hProcess, heaps[i], (PVOID64)heap.data(), heap.size(), nullptr);
			auto flags = (DWORD *)(heap.data() + HeapFlagsOffset);
			auto force_flags = (DWORD *)(heap.data() + HeapForceFlagsOffset);
			//*flags &= ~HEAP_CLEARABLE_FLAGS;
			//*force_flags &= ~HEAP_CLEARABLE_FORCE_FLAGS;

			//*flags &= ~0x40000060;
			//*force_flags &= ~0x40000060;

			*flags &= ~HEAP_CLEARABLE_FLAGS;

			*force_flags &= ~HEAP_CLEARABLE_FORCE_FLAGS;

			//*flags = 2;
			//*force_flags = 0;

			WriteProcessMemory(hProcess, heaps[i], (PVOID64)heap.data(), heap.size(), nullptr);
		}
		PVOID heap2 = (PVOID)*(PDWORD_PTR)((PBYTE)peb + offsetProcessHeap);
		PDWORD heapFlagsPtr = (PDWORD)((PBYTE)heap2 + HeapFlagsOffset);
		PDWORD heapForceFlagsPtr = (PDWORD)((PBYTE)heap2 + HeapForceFlagsOffset);
		*heapFlagsPtr &= HEAP_GROWABLE;
		*heapForceFlagsPtr = 0;

#else
		std::vector<PVOID> heaps;
		heaps.resize(peb->NumberOfHeaps);

		ReadProcessMemory(hProcess, (PVOID)peb->ProcessHeaps, (PVOID)heaps.data(), heaps.size() * sizeof(PVOID), nullptr);

		std::basic_string<uint8_t> heap;
		heap.resize(peb->NumberOfHeaps); // hacky
		DWORD offsetProcessHeap = 0x18;
		DWORD HeapFlagsOffset = 0x40;
		DWORD HeapForceFlagsOffset = 0x44;

		for (DWORD i = 0; i < peb->NumberOfHeaps; i++)
		{
			ReadProcessMemory(hProcess, heaps[i], (PVOID)heap.data(), heap.size(), nullptr);
			auto flags = (DWORD *)(heap.data() + HeapFlagsOffset);
			auto force_flags = (DWORD *)(heap.data() + HeapForceFlagsOffset);
			//*flags &= ~HEAP_CLEARABLE_FLAGS;
			//*force_flags &= ~HEAP_CLEARABLE_FORCE_FLAGS;

			//*flags &= ~0x40000060;
			//*force_flags &= ~0x40000060;

			*flags &= ~HEAP_CLEARABLE_FLAGS;

			*force_flags &= ~HEAP_CLEARABLE_FORCE_FLAGS;

			//*flags = 2;
			//*force_flags = 0;

			WriteProcessMemory(hProcess, heaps[i], (PVOID64)heap.data(), heap.size(), nullptr);
		}
		PVOID heap2 = (PVOID)*(PDWORD_PTR)((PBYTE)peb + offsetProcessHeap);
		PDWORD heapFlagsPtr = (PDWORD)((PBYTE)heap2 + HeapFlagsOffset);
		PDWORD heapForceFlagsPtr = (PDWORD)((PBYTE)heap2 + HeapForceFlagsOffset);
		*heapFlagsPtr &= HEAP_GROWABLE;
		*heapForceFlagsPtr = 0;

#endif

	}
	if (g_settings.profile_.fixPebNtGlobalFlag)
	{
		//log(L"fixPebNtGlobalFlag");
		peb->NtGlobalFlag &= ~0x70;
		WriteProcessMemory(hProcess, peb_addr, peb, sizeof(PEB), nullptr);
	}
	if (g_settings.profile_.fixPebStartupInfo)
	{
		RTL_USER_PROCESS_PARAMETERS rupp = { 0, };
		ReadProcessMemory(hProcess, (PVOID)peb->ProcessParameters, &rupp, sizeof(rupp), nullptr);
		/*
		WCHAR msg[256];
		swprintf_s(msg, L"%X", rupp.StartingX);
		log(msg);
		swprintf_s(msg, L"%X", rupp.StartingY);
		log(msg);
		swprintf_s(msg, L"%X", rupp.CountX);
		log(msg);
		swprintf_s(msg, L"%X", rupp.CountY);
		log(msg);
		swprintf_s(msg, L"%X", rupp.CountCharsX);
		log(msg);
		swprintf_s(msg, L"%X", rupp.CountCharsY);
		log(msg);
		swprintf_s(msg, L"%X", rupp.FillAttribute);
		log(msg);
		*/
		auto patch_size = (DWORD_PTR)&rupp.WindowFlags - (DWORD_PTR)&rupp.StartingX;
		rupp.WindowFlags = STARTF_USESHOWWINDOW;
		rupp.ShowWindowFlags = SW_SHOWNORMAL;
		rupp.Flags |= RTL_USER_PROCESS_PARAMETERS_IMAGE_KEY_MISSING;
		WriteProcessMemory(hProcess, (PVOID)peb->ProcessParameters, &rupp, sizeof(rupp), nullptr);
	}

	if (g_settings.profile_.fixPebOsBuildNumber)
	{
		peb->OSBuildNumber++;
	}
}

void hookFunction(scl::Settings g_settings, HANDLE hProcess)
{
	HMODULE hmod_ntdll = LoadLibrary(L"ntdll.dll");
	HMODULE hmod_kernel32 = LoadLibrary(L"kernelbase.dll");
	if (hmod_kernel32 == nullptr)
	{
		hmod_kernel32 = LoadLibrary(L"kernel32.dll");
	}
	HMODULE hmod_user32 = LoadLibrary(L"win32u.dll");
	if (hmod_user32 == nullptr)
	{
		hmod_user32 = LoadLibrary(L"user32.dll");
	}
	DWORD backupSize;

	if (g_settings.profile_.hookNtSetInformationThread)
	{
		t_NtSetInformationThread procaddr_NtSetInformationThread = (t_NtSetInformationThread)GetProcAddress(hmod_ntdll, "NtSetInformationThread");
		scl::hooked.dNtSetInformationThread = (t_NtSetInformationThread)DetourCreateRemote(hProcess, "NtSetInformationThread", procaddr_NtSetInformationThread, HookedNtSetInformationThread, true, &backupSize);
	}
	if (g_settings.profile_.hookNtSetInformationProcess)
	{
		t_NtSetInformationProcess procaddr_NtSetInformationProcess = (t_NtSetInformationProcess)GetProcAddress(hmod_ntdll, "NtSetInformationProcess");
		scl::hooked.dNtSetInformationProcess = (t_NtSetInformationProcess)DetourCreateRemote(hProcess, "NtSetInformationProcess", procaddr_NtSetInformationProcess, HookedNtSetInformationProcess, true, &backupSize);
	}
	if (g_settings.profile_.hookNtQueryInformationProcess)
	{
		t_NtQueryInformationProcess procaddr_NtQueryInformationProcess = (t_NtQueryInformationProcess)GetProcAddress(hmod_ntdll, "NtQueryInformationProcess");
		scl::hooked.dNtQueryInformationProcess = (t_NtQueryInformationProcess)DetourCreateRemote(hProcess, "NtQueryInformationProcess", procaddr_NtQueryInformationProcess, HookedNtQueryInformationProcess, true, &backupSize);
	}
	if (g_settings.profile_.hookNtQuerySystemInformation)
	{
		t_NtQuerySystemInformation procaddr_NtQuerySystemInformation = (t_NtQuerySystemInformation)GetProcAddress(hmod_ntdll, "NtQuerySystemInformation");
		scl::hooked.dNtQuerySystemInformation = (t_NtQuerySystemInformation)DetourCreateRemote(hProcess, "NtQuerySystemInformation", procaddr_NtQuerySystemInformation, HookedNtQuerySystemInformation, true, &backupSize);
	}
	if (g_settings.profile_.hookNtQueryObject)
	{
		t_NtQueryObject procaddr_NtQueryObject = (t_NtQueryObject)GetProcAddress(hmod_ntdll, "NtQueryObject");
		scl::hooked.dNtQueryObject = (t_NtQueryObject)DetourCreateRemote(hProcess, "NtQueryObject", procaddr_NtQueryObject, HookedNtQueryObject, true, &backupSize);
	}
	if (g_settings.profile_.hookNtYieldExecution)
	{
		t_NtYieldExecution procaddr_NtYieldExecution = (t_NtYieldExecution)GetProcAddress(hmod_ntdll, "NtYieldExecution");
		scl::hooked.dNtYieldExecution = (t_NtYieldExecution)DetourCreateRemote(hProcess, "NtYieldExecution", procaddr_NtYieldExecution, HookedNtYieldExecution, true, &backupSize);
	}
	if (g_settings.profile_.hookNtCreateThreadEx)
	{
		t_NtCreateThreadEx procaddr_NtCreateThreadEx = (t_NtCreateThreadEx)GetProcAddress(hmod_ntdll, "NtCreateThreadEx");
		scl::hooked.dNtCreateThreadEx = (t_NtCreateThreadEx)DetourCreateRemote(hProcess, "NtCreateThreadEx", procaddr_NtCreateThreadEx, HookedNtCreateThreadEx, true, &backupSize);
	}
	if (g_settings.profile_.hookOutputDebugStringA)
	{
		t_OutputDebugStringA procaddr_OutputDebugStringA = (t_OutputDebugStringA)GetProcAddress(hmod_kernel32, "OutputDebugStringA");
		scl::hooked.dOutputDebugStringA = (t_OutputDebugStringA)DetourCreateRemote(hProcess, "OutputDebugStringA", procaddr_OutputDebugStringA, HookedOutputDebugStringA, true, &backupSize);
	}
	if (g_settings.profile_.hookNtUserBlockInput)
	{
		t_NtUserBlockInput procaddr_NtUserBlockInput = (t_NtUserBlockInput)GetProcAddress(hmod_user32, "NtUserBlockInput");
		scl::hooked.dNtUserBlockInput = (t_NtUserBlockInput)DetourCreateRemote(hProcess, "NtUserBlockInput", procaddr_NtUserBlockInput, HookedNtUserBlockInput, true, &backupSize);
	}
	if (g_settings.profile_.hookNtUserFindWindowEx)
	{
		t_NtUserFindWindowEx procaddr_NtUserFindWindowEx = (t_NtUserFindWindowEx)GetProcAddress(hmod_user32, "NtUserFindWindowEx");
		scl::hooked.dNtUserFindWindowEx = (t_NtUserFindWindowEx)DetourCreateRemote(hProcess, "NtUserFindWindowEx", procaddr_NtUserFindWindowEx, HookedNtUserFindWindowEx, true, &backupSize);
	}
	if (g_settings.profile_.hookNtUserFindWindowEx)
	{
		t_NtUserFindWindowEx procaddr_NtUserFindWindowEx = (t_NtUserFindWindowEx)GetProcAddress(hmod_user32, "NtUserFindWindowEx");
		scl::hooked.dNtUserFindWindowEx = (t_NtUserFindWindowEx)DetourCreateRemote(hProcess, "NtUserFindWindowEx", procaddr_NtUserFindWindowEx, HookedNtUserFindWindowEx, true, &backupSize);
	}
	if (g_settings.profile_.hookNtUserFindWindowEx)
	{
		t_NtUserFindWindowEx procaddr_NtUserFindWindowEx = (t_NtUserFindWindowEx)GetProcAddress(hmod_user32, "NtUserFindWindowEx");
		scl::hooked.dNtUserFindWindowEx = (t_NtUserFindWindowEx)DetourCreateRemote(hProcess, "NtUserFindWindowEx", procaddr_NtUserFindWindowEx, HookedNtUserFindWindowEx, true, &backupSize);
	}
	if (g_settings.profile_.hookNtUserBuildHwndList)
	{
		scl::hooked.dNtUserBuildHwndList = (t_NtUserBuildHwndList)DetourCreateRemote(hProcess, "NtUserBuildHwndList", (t_NtUserBuildHwndList)GetProcAddress(hmod_user32, "NtUserBuildHwndList"), HookedNtUserBuildHwndList, true, &backupSize);
	}
	if (g_settings.profile_.hookNtUserQueryWindow)
	{
		scl::hooked.dNtUserQueryWindow = (t_NtUserQueryWindow)DetourCreateRemote(hProcess, "NtUserQueryWindow", (t_NtUserQueryWindow)GetProcAddress(hmod_user32, "NtUserQueryWindow"), HookedNtUserQueryWindow, true, &backupSize);
	}
	if (g_settings.profile_.hookNtSetDebugFilterState)
	{
		scl::hooked.dNtSetDebugFilterState = (t_NtSetDebugFilterState)DetourCreateRemote(hProcess, "NtSetDebugFilterState", (t_NtSetDebugFilterState)GetProcAddress(hmod_ntdll, "NtSetDebugFilterState"), HookedNtSetDebugFilterState, true, &backupSize);
	}
	if (g_settings.profile_.hookNtClose)
	{
		scl::hooked.dNtClose = (t_NtClose)DetourCreateRemote(hProcess, "NtClose", (t_NtClose)GetProcAddress(hmod_ntdll, "NtClose"), HookedNtClose, true, &backupSize);
	}
	if (g_settings.profile_.removeDebugPrivileges)
	{
		TOKEN_PRIVILEGES Debug_Privileges;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Debug_Privileges.Privileges[0].Luid))
		{
			HANDLE hToken = 0;
			if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
			{
				Debug_Privileges.Privileges[0].Attributes = 0;
				Debug_Privileges.PrivilegeCount = 1;

				AdjustTokenPrivileges(hToken, FALSE, &Debug_Privileges, 0, NULL, NULL);
				CloseHandle(hToken);
			}
		}
	}
	if (g_settings.profile_.hookNtGetContextThread)
	{
		scl::hooked.dNtGetContextThread = (t_NtGetContextThread)DetourCreateRemote(hProcess, "NtGetContextThread", (t_NtGetContextThread)GetProcAddress(hmod_ntdll, "NtGetContextThread"), HookedNtGetContextThread, true, &backupSize);
	}
	if (g_settings.profile_.hookNtSetContextThread)
	{
		scl::hooked.dNtSetContextThread = (t_NtSetContextThread)DetourCreateRemote(hProcess, "NtSetContextThread", (t_NtSetContextThread)GetProcAddress(hmod_ntdll, "NtSetContextThread"), HookedNtSetContextThread, true, &backupSize);
	}
	if (g_settings.profile_.hookNtContinue)
	{
		scl::hooked.dNtContinue = (t_NtContinue)DetourCreateRemote(hProcess, "NtContinue", (t_NtContinue)GetProcAddress(hmod_ntdll, "NtContinue"), HookedNtContinue, true, &backupSize);
	}
	if (g_settings.profile_.hookKiUserExceptionDispatcher)
	{
		scl::hooked.dKiUserExceptionDispatcher = (t_KiUserExceptionDispatcher)DetourCreateRemote(hProcess, "KiUserExceptionDispatcher", (t_KiUserExceptionDispatcher)GetProcAddress(hmod_ntdll, "KiUserExceptionDispatcher"), HookedKiUserExceptionDispatcher, true, &backupSize);
		/*
		#ifdef _WIN64
		// The x86_64 version of this function currently contains relative offset instructions
		// which will cause problems with the naive trampoline generation currently in use.
		// Therefore, let us apply some manual patching instead.
		PVOID address = (PVOID)_KiUserExceptionDispatcher;
		const bool startsWithCld = ((UINT8*)address)[0] == 0xFC; // true on Vista and later
		if ((startsWithCld && *(PUINT32)address != 0x058B48FC) ||
			(!startsWithCld && (*(PUINT32)address & 0xFFFFFF) != 0x058B48))
		{
			//log(L"ApplyNtdllHook -> KiUserExceptionDispatcher pattern mismatch 0x%lx");
		}
		else
		{
			// This function currently has a nine byte NOP before it, probably for hot patching?
			// There is also some alignment space. Let's borrow this to write our trampoline.
			uint8_t trampoline[] =
			{
				0xFF, 0x15, 0x0F, 0x00, 0x00, 0x00,         // call qword ptr[+15]
				0xFC,                                       // cld
				0x48, 0x8B, 0x05, 0x22, 0xA4, 0x0D, 0x00,   // mov rax, qword ptr:[<Wow64PrepareForException>]
				0x48, 0x85, 0xC0,                           // test rax,rax
				0xEB, 0x0B                                  // jmp <next real instruction>
			};

			// Deal with XP/2003
			if (!startsWithCld)
			{
				trampoline[6] = 0x90;                       // cld -> nop
				trampoline[18] -= 0x1;                      // <next real instruction> -= 1
			}

			// update RVA of Wow64PrepareForException
			UINT32 rvaWow64PrepareForException;
			ReadProcessMemory(hProcess, (LPCVOID)(((UINT_PTR)address) + (startsWithCld ? 4 : 3)), (PVOID)&rvaWow64PrepareForException,
				sizeof(rvaWow64PrepareForException), nullptr);

			// instruction is moved up 12/13 bytes. update trampoline
			rvaWow64PrepareForException += (startsWithCld ? 13 : 12);
			memcpy(&trampoline[10], &rvaWow64PrepareForException, sizeof(rvaWow64PrepareForException));

			uint8_t hook[] =
			{
				0xEB, 0xEB,     // jmp -21
				0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
			};
			// insert hook into payload
			memcpy(&hook[2], &HookedKiUserExceptionDispatcher, sizeof(PVOID));

			// for most hooks the following fields are for the trampoline. this works for them because
			// the trampoline is an identical copy of what was at the start of the function. since this
			// is not the case for us, we must preserve the original bytes in memory we deliberately set
			// aside for this purpose.
			PVOID backup_location = VirtualAllocEx(hProcess, nullptr, sizeof(hook), MEM_COMMIT,
				PAGE_READWRITE);

			//hdd->dKiUserExceptionDispatcher = (decltype(hdd->dKiUserExceptionDispatcher))(backup_location);
			//hdd->KiUserExceptionDispatcherBackupSize = sizeof(hook);

			// backup start of function
			uint8_t backup_prologue[sizeof(hook)];
			ReadProcessMemory(hProcess, address, backup_prologue, sizeof(backup_prologue), nullptr);
			WriteProcessMemory(hProcess, backup_location, backup_prologue, sizeof(backup_prologue), nullptr);

			// install trampoline
			PVOID trampoline_location = (PVOID)(((UINT_PTR)address) - sizeof(trampoline));
			WriteProcessMemory(hProcess, trampoline_location, trampoline, sizeof(trampoline), nullptr);

			// install hook
			WriteProcessMemory(hProcess, address, hook, sizeof(hook), nullptr);
		}

		#else

		#endif
		*/


	}


	if (g_settings.profile_.hookGetTickCount)
	{
		scl::hooked.dGetTickCount = (t_GetTickCount)DetourCreateRemote(hProcess, "GetTickCount", (t_GetTickCount)GetProcAddress(hmod_kernel32, "GetTickCount"), HookedGetTickCount, true, &backupSize);
	}
	if (g_settings.profile_.hookGetTickCount64)
	{
		scl::hooked.dGetTickCount64 = (t_GetTickCount64)DetourCreateRemote(hProcess, "GetTickCount64", (t_GetTickCount64)GetProcAddress(hmod_kernel32, "GetTickCount64"), HookedGetTickCount64, true, &backupSize);
	}
	if (g_settings.profile_.hookGetLocalTime)
	{
		scl::hooked.dGetLocalTime = (t_GetLocalTime)DetourCreateRemote(hProcess, "GetLocalTime", (t_GetLocalTime)GetProcAddress(hmod_kernel32, "GetLocalTime"), HookedGetLocalTime, true, &backupSize);
	}
	if (g_settings.profile_.hookGetSystemTime)
	{
		scl::hooked.dGetSystemTime = (t_GetSystemTime)DetourCreateRemote(hProcess, "GetSystemTime", (t_GetSystemTime)GetProcAddress(hmod_kernel32, "GetSystemTime"), HookedGetSystemTime, true, &backupSize);
	}
	if (g_settings.profile_.hookNtQuerySystemTime)
	{
		scl::hooked.dNtQuerySystemTime = (t_NtQuerySystemTime)DetourCreateRemote(hProcess, "NtQuerySystemTime", (t_NtQuerySystemTime)GetProcAddress(hmod_ntdll, "NtQuerySystemTime"), HookedNtQuerySystemTime, true, &backupSize);
	}
	if (g_settings.profile_.hookNtQueryPerformanceCounter)
	{
		scl::hooked.dNtQueryPerformanceCounter = (t_NtQueryPerformanceCounter)DetourCreateRemote(hProcess, "NtQueryPerformanceCounter", (t_NtQueryPerformanceCounter)GetProcAddress(hmod_ntdll, "NtQueryPerformanceCounter"), HookedNtQueryPerformanceCounter, true, &backupSize);
	}

	/*
	if (g_settings.profile_.CloseHandle)
	{
		t_CloseHandle procaddr_CloseHandle = (t_CloseHandle)GetProcAddress(hmod_kernel32, "CloseHandle");
		//WCHAR msg[256];
		//swprintf_s(msg, L"%X", procaddr_CloseHandle);
		//log(msg);
		//swprintf_s(msg, L"%X", HookedCloseHandle);
		//log(msg);
		scl::hooked.dCloseHandle = (t_CloseHandle)DetourCreateRemote(hProcess, "CloseHandle", procaddr_CloseHandle, HookedCloseHandle, true, &backupSize);
	}
	*/





}

void main()
{
	DWORD targetPid = GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION, 0, targetPid);
	WCHAR msg[256];
	GetCurrentDirectory(256, msg);
	swprintf_s(msg, L"%s%s", msg, L"\\config.ini");
	scl::Settings g_settings;

	g_settings.LoadProfile(msg, L"PROFILE", &g_settings.profile_);


	patchPEB(g_settings, hProcess);
	hookFunction(g_settings, hProcess);
	if (g_settings.profile_.killAntiAttach)
	{
		ApplyAntiAntiAttach(hProcess);
	}
	CloseHandle(hProcess);
	return;
}

void restore()
{
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		main();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
		restore();
        break;
    }
    return TRUE;
}

