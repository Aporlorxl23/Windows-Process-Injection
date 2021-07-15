#undef UNICODE

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

LPCSTR Banner = \
"Usage>\n	DLLInj.exe name notepad.exe DLLInj.dll\n	DLLInj.exe pid 2323 DLLInj.dll";

DWORD FindProcess(DWORD PID, LPCSTR ProcessName, LPCSTR Mode) {

	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, FALSE);
	/*
	https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
	TH32CS_SNAPPROCESS = Includes all processes in the system in the snapshot. To enumerate the processes, see Process32First.
	FALSE = The process identifier of the process to be included in the snapshot. This parameter can be zero to indicate the current process.
	*/


	PROCESSENTRY32 Entry;
	/*
	The size of the structure, in bytes. Before calling the Process32First function, set this member to sizeof(PROCESSENTRY32).
	If you do not initialize dwSize, Process32First fails
	https://docs.microsoft.com/tr-tr/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32
	*/
	Entry.dwSize = sizeof(Entry);

	if (strcmp(Mode, "Name") == 0) {
		//Here the purpose is to find the PID of the entered process name.
		if (Process32First(Snapshot, &Entry) == TRUE) {
			/*
			https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first
			Snapshot = A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.
			Entry = A pointer to a PROCESSENTRY32 structure. It contains process information such as the name of the executable file, the process identifier, and the process identifier of the parent process.
			*/
			while (Process32Next(Snapshot, &Entry) == TRUE) {

				/*
				https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next
				Snapshot = A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.
				Entry = A pointer to a PROCESSENTRY32 structure.
				*/

				if (strcmp(Entry.szExeFile, ProcessName) == 0) {

					CloseHandle(Snapshot);
					return Entry.th32ProcessID; // This return my process PID
				}
			}
		}
	}
	else if (strcmp(Mode, "Pid") == 0) {
		//The purpose here is to learn whether the entered PID value works in the system.
		if (Process32First(Snapshot, &Entry) == TRUE) {

			while (Process32Next(Snapshot, &Entry) == TRUE) {

				if (Entry.th32ProcessID == PID) {
					CloseHandle(Snapshot);
					return TRUE;
				}

			}
			CloseHandle(Snapshot);
			return FALSE;
		}
	}
	else {
		std::cout << "[?] Mode Not Found ?" << std::endl;
		CloseHandle(Snapshot);
	}
}

void InjectProcess(DWORD PID, LPCSTR DllPath) {
	std::cout << "[+] Started DLL Injection on " << PID << " Dll Path> " << DllPath << std::endl;

	HANDLE hProcess = OpenProcess(
		PROCESS_ALL_ACCESS, //The access to the process object. This access right is checked against the security descriptor for the process. 
		FALSE, //If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.
		PID); //The identifier of the local process to be opened.

	//https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess

	LPVOID LoadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	/*
	https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea
	https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
	Retrieves the address of an exported function or variable from the specified dynamic-link library (DLL).

	A handle to the DLL module that contains the function or variable.
	The LoadLibrary, LoadLibraryEx, LoadPackagedLibrary, or GetModuleHandle function returns this handle.
	*/

	LPVOID Mem = VirtualAllocEx(
		hProcess, //The handle to a process. The function allocates memory within the virtual address space of this process.
		NULL,  //The pointer that specifies a desired starting address for the region of pages that you want to allocate.
		strlen(DllPath) + 1, //The size of the region of memory to allocate, in bytes.
		// Note : You have to allocate 1 extra byte for the null-character at the end.
		(MEM_COMMIT | MEM_RESERVE), //The type of memory allocation. 
		//To reserve and commit pages in one step, call VirtualAllocEx with MEM_COMMIT | MEM_RESERVE.
		PAGE_READWRITE); //The memory protection for the region of pages to be allocated. If the pages are being committed, you can specify any one of the memory protection constants.

	/*
	https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
	Reserves, commits, or changes the state of a region of memory within the virtual address space of a specified process.
	The function initializes the memory it allocates to zero.

	*/

	WriteProcessMemory(
		hProcess, //A handle to the process memory to be modified. The handle must have PROCESS_VM_WRITE and PROCESS_VM_OPERATION access to the process.
		Mem, //A pointer to the base address in the specified process to which data is written. 
		DllPath, //A pointer to the buffer that contains data to be written in the address space of the specified process.
		strlen(DllPath) + 1, // The number of bytes to be written to the specified process. (Note valid here)
		NULL); //A pointer to a variable that receives the number of bytes transferred into the specified process. This parameter is optional. 
			   //If lpNumberOfBytesWritten is NULL, the parameter is ignored.

	/*
	https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
	Writes data to an area of memory in a specified process. The entire area to be written to must be accessible or the operation fails.
	*/

	HANDLE ThreadID = CreateRemoteThread(
		hProcess, // A handle to the process in which the thread is to be created.
		NULL, NULL,
		// First Parameter A pointer to a SECURITY_ATTRIBUTES structure that specifies a security descriptor for the new thread and determines whether child processes can inherit the returned handle. 
		//If lpThreadAttributes is NULL, the thread gets a default security descriptor and the handle cannot be inherited. 
		// Second Parameter The initial size of the stack, in bytes. The system rounds this value to the nearest page. If this parameter is 0 (zero), the new thread uses the default size for the executable.
		(LPTHREAD_START_ROUTINE)LoadLibrary, // A pointer to the application-defined function of type LPTHREAD_START_ROUTINE to be executed by the thread and represents the starting address of the thread in the remote process. The function must exist in the remote process. 
		Mem, // A pointer to a variable to be passed to the thread function.
		NULL, NULL);
		// First Parameter The flags that control the creation of the thread. 0 The thread runs immediately after creation.
		// Second Parameter A pointer to a variable that receives the thread identifier. 
		// If this parameter is NULL, the thread identifier is not returned.


/*
https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
Creates a thread that runs in the virtual address space of another process.
*/

	if (ThreadID != NULL) { // Here we check if the operation was successful
		std::cout << "[+] DLL Successfully Injected !" << std::endl;
	}
	else {
		std::cout << "[-] DLL Failed to Inject !" << std::endl;
	}

	CloseHandle(hProcess);
}

int main(int argc, char *argv[])
{

	if (argv[1] == NULL || argv[2] == NULL || argv[3] == NULL) {
		std::cout << Banner << std::endl;
		exit(0);
	}

	std::string Option = argv[1];

	if (strcmp(argv[1], "name") == 0) {

		if (FindProcess(NULL, argv[2], "Name") == 0) {

			std::cout << "[-] Process Not Found !" << std::endl;
			exit(0);
		}

		InjectProcess(FindProcess(NULL, argv[2], "Name"), argv[3]);
	}
	else if (strcmp(argv[1], "pid") == 0) {

		int PID = atoi((char*)argv[2]);

		if (FindProcess(PID, NULL, "Pid") == 0) {

			std::cout << "[-] Process Not Found !" << std::endl;
			exit(0);
		}

		InjectProcess(PID, argv[3]);
	}
	else {
		std::cout << Banner << std::endl;
		exit(0);
	}

	return 0;
}
