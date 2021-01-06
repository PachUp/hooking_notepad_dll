#ifndef _DLL_H_
#define _DLL_H_

#include <windows.h>
#include<conio.h>
#include<iostream>
#include<string>
#include <stdio.h>

#define TARGET_FUNCTION "WriteFile"
#define TARGET_DLL "KERNEL32.DLL"
#define IMPORT_TABLE_OFFSET 1 // the location of the import table in the configuration
DWORD original_addr; // the original address in the iat of TARGET_FUNCTION

BOOL APIENTRY DllMain(HINSTANCE, DWORD, LPVOID);
/*
* The following function return the import table for notepad (all of notepad's dll files)
* param1: a handler for notepad (used to get the address)
*/
PIMAGE_IMPORT_DESCRIPTOR import_table(HMODULE);

/*
* The following function is hooking TARGET_FUNCTION and xors LPBUFFER
* all the params has to be the same params of the targeted function so the program could autoclean the params.
*/
BOOL WINAPI xor_notepad(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);

/*
* acts as the actual "main" function
* param1: the notepad handler
* param2: the function that I'd like to replace the address in the iat
* param3: the function that replaces the address of the TARGET_FUNCTION with XOR_NOTEPAD in the iat.
*/
bool hook_function(HMODULE, LPCSTR, PVOID);

/*
* the following function rewrites the address of TARGET_FUNCTION in the IAT with NEW_FUNCTION
* param1: the pointer for the IAT table at the location of TARGET_FUNCTION
* param2: the second param is meant to take the address of the new function
*/
bool rewirte_thunk_addr(PIMAGE_THUNK_DATA, void*);
#endif