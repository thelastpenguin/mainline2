#include <fstream>
#include <iostream>
#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <direct.h> // _getcwd
#include <string>
#include <iomanip>
#include <sstream>
#include <process.h>

#include <unordered_set>

#pragma comment(lib,"ntdll.lib")

using namespace std;


__declspec(naked) void stub()
{
	__asm
	{
		// Save registers

		pushad
			pushfd
			call start // Get the delta offset

		start :
		pop ecx
			sub ecx, 7

			lea eax, [ecx + 32] // 32 = Code length + 11 int3 + 1
			push eax
			call dword ptr[ecx - 4] // LoadLibraryA address is stored before the shellcode

			// Restore registers

			popfd
			popad
			ret

			// 11 int3 instructions here
	}
}

// this way we can difference the addresses of the instructions in memory
DWORD WINAPI stub_end()
{
	return 0;
}

// thread hijacking
string getCwd();
DWORD FindProcessId(const std::wstring&);
long InjectProcess(DWORD, const char*);

void dotdotdot(int count, int delay = 250);
void cls();


void createConfigFile();

int main_scanner();
int main_injector();

int main(int argc, char* argv) { 
	main_injector();
	main_scanner();
	Sleep(10000);
}

int main_injector() {
	cls();
	std::cout << "Elevating process privlages";

	// elevate process privlages
	TOKEN_PRIVILEGES tp;
	HANDLE hToken;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid.LowPart = 20; // 20 = SeDebugPrivilege
	tp.Privileges[0].Luid.HighPart = 0;

	if (OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, 0);
		CloseHandle(hToken);
	}
	else {
		std::cout << "Failed to elevate process privlages." << endl;
		Sleep(10000);
		return 0;
	}

	std::cout << endl << endl;

}

int main_scanner() {
	std::cout << "Loading";
	dotdotdot(4);
	std::cout << endl;

	cls();

	string processName;
	string payloadPath;

	while (true) {
		cls();

		ifstream config("needle.cfg");

		if (config.is_open()) {
			std::string configStr((std::istreambuf_iterator<char>(config)),
				std::istreambuf_iterator<char>());
			int breakPos = configStr.find("|");
			processName = configStr.substr(0, breakPos);

			string rawPath = configStr.substr(breakPos + 1);
			char fullPathBuff[MAX_PATH];
			_fullpath(fullPathBuff, rawPath.c_str(), sizeof(fullPathBuff));

			payloadPath = string(fullPathBuff);

			std::cout << "Found and loaded needle.cfg:" << endl;
			std::cout << "\tProcess Name: " << processName << endl;
			std::cout << "\tRaw Payload Path: " << rawPath << endl;
			std::cout << "\tRelative Path: " << payloadPath << endl;
		}

		if (!config.is_open()) {
			createConfigFile();
		}
		else {
			config.close();

			cout << "Use these settings or enter new ones (y/n): ";
			char result = '\0';
			do {
				cin >> result;
			} while (result != 'y' && result != 'n');

			if (result == 'y')
				break;
			else
				createConfigFile();
		}
	}

	cls();
	std::cout << "\tProcess Name: " << processName << endl;
	std::cout << "\tRelative Path: " << payloadPath << endl;

	std::wstring fatProcessName(processName.begin(), processName.end());
	
	std::unordered_set<DWORD> injectedProcesses;


	while (true) {
		std::cout << "Scanning";
		while (true) {
			dotdotdot(4);

			DWORD processId = FindProcessId(fatProcessName);
			if (processId && injectedProcesses.find(processId) == injectedProcesses.end()) {
				
				std::cout << "Found a process to inject!" << endl;
				std::cout << "\tProcess ID: " << processId << endl;
				std::cout << "\tWaiting a 5 seconds to allow for load time";
				for (int i = 0; i < 5; ++i) dotdotdot(4);
				std::cout << endl << "\tInjecting Process: " << endl;

				if (InjectProcess(processId, payloadPath.c_str()) == 0) {
					std::cout << "\tSuccess!" << endl;
				}
				else {
					std::cout << "\tError!" << endl;
				}

				injectedProcesses.insert(processId);
				break;
			}
		}
	}

	Sleep(10000);
}

void createConfigFile() {
	cls();

	ofstream config("needle.cfg");
	cout << "Enter the process name to target:\n";
	string processName;
	cin >> processName;
	cout << "Enter the relative path to the payload dll:\n";
	string payloadName;
	cin >> payloadName;

	config << processName;
	config << "|";
	config << payloadName;

	config.close();

	cout << "Encoding config";
	dotdotdot(4);
}


void dotdotdot(int count, int delay) {
	int width = count;
	for (int dots = 0; dots <= count; ++dots) {
		std::cout << std::left << std::setw(width) << std::string(dots, '.');
		Sleep(delay);
		std::cout << std::string(width, '\b');
	}
}

void cls() {
	std::system("cls");
	std::cout <<
		" -------------------------------\n"
		"  mainline v2 by thelastpenguin \n"
		" -------------------------------\n";
}

DWORD FindProcessId(const std::wstring& processName) {
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processesSnapshot);
	return 0;
}

long InjectProcess(DWORD ProcessId, const char* dllPath) {

	HANDLE hProcess, hThread, hSnap;
	DWORD stublen;
	PVOID LoadLibraryA_Addr, mem;

	THREADENTRY32 te32;
	CONTEXT ctx;

	// determine the size of the stub that we will insert
	stublen = (DWORD)stub_end - (DWORD)stub;
	cout << "Calculated the stub size to be: " << stublen << endl;


	// opening target process
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);

	if (!hProcess) {
		cout << "Failed to load hProcess with id " << ProcessId << endl;
		Sleep(10000);
		return 0;
	}

	// todo: identify purpose of this code
	te32.dwSize = sizeof(te32);
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);


	Thread32First(hSnap, &te32);
	cout << "Identifying a thread to hijack" << endl;
	while (Thread32Next(hSnap, &te32))
	{
		if (te32.th32OwnerProcessID == ProcessId)
		{
			cout << "Target thread found. TID: " << te32.th32ThreadID << endl;

			CloseHandle(hSnap);
			break;
		}
	}

	// opening a handle to the thread that we will be hijacking
	hThread = OpenThread(THREAD_ALL_ACCESS, false, te32.th32ThreadID);
	if (!hThread) {
		cout << "Failed to open a handle to the thread " << te32.th32ThreadID << endl;
		Sleep(10000);
		return 0;
	}

	// now we suspend it.
	ctx.ContextFlags = CONTEXT_FULL;
	SuspendThread(hThread);

	cout << "Getting the thread context" << endl;
	if (!GetThreadContext(hThread, &ctx)) // Get the thread context
	{
		cout << "Unable to get the thread context of the target thread " << GetLastError() << endl;
		ResumeThread(hThread);
		Sleep(10000);
		return -1;
	}

	cout << "Current EIP: " << ctx.Eip << endl;
	cout << "Current EIP: " << ctx.Esp << endl;

	cout << "Allocating memory in target process." << endl;
	mem = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!mem) {
		cout << "Unable to reserve memory in the target process." << endl;
		ResumeThread(hThread);
		Sleep(10000);
		return -1;
	}

	cout << "Memory allocated at " << mem << endl;
	LoadLibraryA_Addr = LoadLibraryA;

	cout << "Writing shell code, LoadLibraryA address, and DLL path into target process" << endl;

	cout << "Writing out path buffer " << dllPath << endl;
	size_t dllPathLen = strlen(dllPath);

	WriteProcessMemory(hProcess, mem, &LoadLibraryA_Addr, sizeof(PVOID), NULL); // Write the address of LoadLibraryA into target process
	WriteProcessMemory(hProcess, (PVOID)((LPBYTE)mem + 4), stub, stublen, NULL); // Write the shellcode into target process
	WriteProcessMemory(hProcess, (PVOID)((LPBYTE)mem + 4 + stublen), dllPath, dllPathLen, NULL); // Write the DLL path into target process

	ctx.Esp -= 4; // Decrement esp to simulate a push instruction. Without this the target process will crash when the shellcode returns!
	WriteProcessMemory(hProcess, (PVOID)ctx.Esp, &ctx.Eip, sizeof(PVOID), NULL); // Write orginal eip into target thread's stack
	ctx.Eip = (DWORD)((LPBYTE)mem + 4); // Set eip to the injected shellcode

	cout << "new eip value: " << ctx.Eip << endl;
	cout << "new esp value: " << ctx.Esp << endl;

	cout << "Setting the thread context " << endl;

	if (!SetThreadContext(hThread, &ctx)) // Hijack the thread
	{
		cout << "Unable to SetThreadContext" << endl;
		VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
		ResumeThread(hThread);
		Sleep(10000);
		return -1;
	}

	ResumeThread(hThread);

	cout << "Done." << endl;

	return 0;
}