// testDevice.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <windows.h>
#include <iostream>
#include <Shlwapi.h>
#include "common.h"
#include "tlhelp32.h"

#define DLLNAME L"fmdfdll.dll"

#pragma comment(lib,"shlwapi.lib")
#pragma comment( lib,"winmm.lib" )
using namespace std;

typedef void(*PrintCallback)(const char*);

typedef HANDLE  (*kmdfOpen)();
typedef BOOL    (*kmdfRevc)(HANDLE, PVOID, UINT,UINT*, LPOVERLAPPED);
typedef BOOL    (*kmdfClose)(HANDLE);
typedef void    (*setPrintCallBack)(PrintCallback);
typedef void    (*testPrintCallBack)(const char*);
static kmdfOpen _kmdfOpen;
static kmdfRevc _kmdfRevc;
static kmdfClose _kmdfClose;
static setPrintCallBack _setPrintCallBack;
static testPrintCallBack _testPrintCallBack;

static void PrintCallBack(const char* msg) {
    if (msg)
    {
        printf(msg);
    }
}

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
        || X(_setPrintCallBack, setPrintCallBack)
        || X(_testPrintCallBack, testPrintCallBack)
        )
    {
        printf("load library error:%d\n", GetLastError());
        FreeLibrary(hmodule);
        return false;
    }
    _setPrintCallBack(PrintCallBack);
    return true;
}

//根据进程id获得进程名
wstring GetModuleName(DWORD dwPid)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, dwPid);
    if (INVALID_HANDLE_VALUE == hSnapshot)
    {
        return L"";
    }
    PROCESSENTRY32 pe = { sizeof(pe) }; //存放进程快照信息的结构体
    BOOL ret = Process32First(hSnapshot, &pe); //获得第一个进程的信息
    //遍历
    while (ret)
    {
        if (dwPid == pe.th32ProcessID)
        {
            CloseHandle(hSnapshot);
            return wstring(pe.szExeFile);
        }
        ret = Process32Next(hSnapshot, &pe); //接着往下遍历
    }
    return L"";
}

PROCESSINFO pinfo;
int main()
{
    if (!InitLibrary())
    {
        system("pause");
        exit(0);
    }
    HANDLE handle = NULL;
    OVERLAPPED __Overlapped = { 0 };
    UINT		ulResult = 0;
    bool ret = false;
    int idx = 0;
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
        if (_kmdfClose(handle))
        {
            printf("0 close error!\n");
        }
        break;
    case '1':
        handle = _kmdfOpen();
        __Overlapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
        while(handle != INVALID_HANDLE_VALUE&& idx <= 50)
        {
            memset(&pinfo, sizeof(PROCESSINFO), 0);
            ret = _kmdfRevc(handle, (PVOID)&pinfo, sizeof(PROCESSINFO), &ulResult, &__Overlapped);
            printf("%d-%ld: PPID = %d, PID = %d NEW=%d \r\n",
                idx++,
                timeGetTime(),
                (int)pinfo.parentId,
                (int)pinfo.processId,
                pinfo.isCreate);
            if (pinfo.isCreate)
            {
                wstring ppname = GetModuleName(pinfo.parentId);
                wstring pname = GetModuleName(pinfo.processId);
                printf("ModuleName: PPNAME = %ws, PNAME = %ws \r\n",ppname.c_str(),pname.c_str());
            }
            //Sleep(100);
        }
        if (_kmdfClose(handle))
        {
            printf("1 close error!\n");
        }
        break;
    default:
        printf("exit!\n");
        break;
    }
    system("pause");
	return 0;
}