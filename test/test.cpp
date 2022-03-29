// testDevice.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <windows.h>
#include <iostream>
#include <Shlwapi.h>
#include "common.h"

#define DLLNAME L"fmdfdll.dll"

#pragma comment(lib,"shlwapi.lib")
using namespace std;

typedef HANDLE  (*kmdfOpen)();
typedef BOOL    (*kmdfRevc)(HANDLE, PVOID, UINT,UINT*, LPOVERLAPPED);
typedef BOOL    (*kmdfClose)(HANDLE);
static kmdfOpen _kmdfOpen;
static kmdfRevc _kmdfRevc;
static kmdfClose _kmdfClose;

bool InitLibrary()
{
    HMODULE hmodule = nullptr;
    wstring dllfile = GetExePath(DLLNAME);
    printf("%ws\n",dllfile.c_str());
    hmodule = LoadLibraryEx(GetExePath(DLLNAME).c_str(), NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (hmodule == nullptr)
    {
        printf("LoadLibraryExA error:%d\n", GetLastError());
        return false;
    }
#define X(Name, Type) ((Name = (Type)GetProcAddress(hmodule, #Type)) == NULL)
    if (X(_kmdfOpen, kmdfOpen)
        || X(_kmdfRevc, kmdfRevc)
        || X(_kmdfClose, kmdfClose)
        )
    {
        printf("load library error:%d\n", GetLastError());
        FreeLibrary(hmodule);
        return false;
    }
    return true;
}


int main()
{
    if (!InitLibrary())
    {
        system("pause");
        exit(0);
    }
    HANDLE handle;
    rewind(stdin);
    switch (getchar())
    {
    case '0':
        handle = _kmdfOpen();
        if (handle == INVALID_HANDLE_VALUE)
        {
            printf("_kmdfOpen failed \n");
        }
        else
        {
            printf("_kmdfOpen succ \n");
        }
        break;
    }
    system("pause");
	return 0;
}