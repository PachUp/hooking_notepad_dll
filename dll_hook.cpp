// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "dll_hook.h"
#pragma warning(disable:4996)

BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{

  switch (ul_reason_for_call)
  {
  case DLL_PROCESS_ATTACH:
    hook_function(GetModuleHandleA(NULL), TARGET_FUNCTION, xor_notepad);
  case DLL_THREAD_ATTACH:
  case DLL_THREAD_DETACH:
  case DLL_PROCESS_DETACH:
    break;
  }
  return TRUE;
}

/*
* acts as the actual "main" function
* mod_instance: the notepad handler
* target_function: the function that I'd like to replace the address in the iat
* xor_notepad: the function that replaces the address of the TARGET_FUNCTION with XOR_NOTEPAD in the iat.
*/
bool hook_function(HMODULE mod_instance, LPCSTR target_function, PVOID xor_notepad)
{
  PIMAGE_IMPORT_DESCRIPTOR top_import_table;
  PIMAGE_THUNK_DATA iat_ptr, ilt_ptr;
  PIMAGE_IMPORT_BY_NAME ilt_data;
  PBYTE bytes_mod_instance = (PBYTE)mod_instance; // (PBYTE = byte*)
  bool found_fun = false; // checking when the dll reached the wanted function.
  top_import_table = import_table(mod_instance); // getting the import table structure
  while (top_import_table->OriginalFirstThunk) { // go through the entire import table
    char * dll_name = (char *)(bytes_mod_instance + top_import_table->Name);
    if(strcmp(dll_name, TARGET_DLL) == 0){
      iat_ptr = (PIMAGE_THUNK_DATA)(bytes_mod_instance + top_import_table->FirstThunk);//ptr iat
      ilt_ptr = (PIMAGE_THUNK_DATA)(bytes_mod_instance + top_import_table->OriginalFirstThunk); // ptr ilt
      ilt_data = (PIMAGE_IMPORT_BY_NAME)(bytes_mod_instance + ilt_ptr->u1.AddressOfData); // getting the ilt relevent deails (name & location)
      while (*(ULONGLONG*)ilt_ptr > 0 && *(ULONGLONG*)iat_ptr > 0 && ilt_ptr->u1.Function && ilt_ptr != NULL) { // going though the ilt and iat pointers to make sure that the loop will stop when it's finished 
        if (!found_fun) { 
          char* current_function = (char*)((PBYTE)ilt_data + sizeof(WORD)); // getting the current function name (+word to only get the name)
          //MessageBoxA(NULL, (char*)current_function, (LPCSTR)(bytes_mod_instance + top_import_table->Name), MB_OK);
          if (current_function != NULL && target_function != NULL && ilt_ptr->u1.Function && current_function != "") { // double check that the name is ok
            if (strcmp(target_function, current_function) == 0) { // checking if the function name in the import table is the same as our targeted function that we want to hook
              //MessageBoxA(NULL, (char*)ilt_data, "Hooked!", MB_OK);
              if (rewirte_thunk_addr(iat_ptr, xor_notepad)) {
               // MessageBoxA(NULL, (LPCSTR)current_function, (LPCSTR)((PBYTE)mod_instance + top_import_table->Name), MB_OK);
                found_fun = true;
              }
            }
          }
        }
        ilt_ptr++;
        ilt_data = (PIMAGE_IMPORT_BY_NAME)(bytes_mod_instance + ilt_ptr->u1.AddressOfData); // getting the next details
        iat_ptr++;
      }
    }
    top_import_table++; // go to the next dll
  }
  return true;
}

/*
* The following function is hooking TARGET_FUNCTION and xors LPBUFFER
* all the params has to be the same params of the targeted function so the program could autoclean the params.
*/
BOOL WINAPI xor_notepad(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
  // MessageBoxA(NULL, (char*)lpBuffer, (char*)lpBuffer, MB_OK);
  char* write_file_input = (char*)lpBuffer;
  int charr;
  for (charr = 0; charr < nNumberOfBytesToWrite; charr++) {
      write_file_input[charr] = write_file_input[charr] ^ 0xff;
  }
  BOOL write_file_fun = WriteFile(hFile, write_file_input, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped); // calling the original WriteFile so it'll write the new input
  return TRUE;
}

/*
* The following function return the import table for notepad (all of notepad's dll files)
* top_import_table: a handler for notepad (used to get the address)
*/
PIMAGE_IMPORT_DESCRIPTOR import_table(HMODULE top_import_table) {
  PIMAGE_DOS_HEADER magic_number_header;
  IMAGE_OPTIONAL_HEADER optional_header;
  PIMAGE_NT_HEADERS base_header;
  IMAGE_DATA_DIRECTORY data_dir;
  magic_number_header = (PIMAGE_DOS_HEADER)top_import_table;
  base_header = (PIMAGE_NT_HEADERS)((PBYTE)magic_number_header + magic_number_header->e_lfanew);
  optional_header = (IMAGE_OPTIONAL_HEADER)(base_header->OptionalHeader);
  data_dir = (IMAGE_DATA_DIRECTORY)(optional_header.DataDirectory[IMPORT_TABLE_OFFSET]);
  return (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)top_import_table + data_dir.VirtualAddress);

}

/*
* the following function rewrites the address of TARGET_FUNCTION in the IAT with NEW_FUNCTION
* thunk: the pointer for the IAT table at the location of TARGET_FUNCTION
* new_function: the second param is meant to take the address of the new function
*/
bool rewirte_thunk_addr(PIMAGE_THUNK_DATA thunk, void* new_function) {
  DWORD current_protection_state;
  DWORD junk;
  VirtualProtect(thunk, 4096, PAGE_READWRITE, &current_protection_state); // changing the protection for the page
  original_addr = thunk->u1.Function;
  thunk->u1.Function = (ULONGLONG)new_function; // changing the address of TARGET_FUNCTION to NEW_FUNCTION
  VirtualProtect(thunk, 4096, current_protection_state, &junk); // changing back the protection 
  return true;
}

