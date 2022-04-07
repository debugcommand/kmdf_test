// testDevice.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <windows.h>
#include <iostream>
#include <Shlwapi.h>
#include "common.h"
#include "tlhelp32.h"
#include <Psapi.h>
#include <tchar.h>

#define DLLNAME L"fmdfdll.dll"

#pragma comment(lib,"shlwapi.lib")
#pragma comment( lib,"winmm.lib" )
#pragma comment (lib,"Psapi.lib")

using namespace std;

typedef void(*PrintCallback)(const char*);

typedef HANDLE  (*kmdfOpen)();
typedef BOOL    (*kmdfRevc)(HANDLE, PVOID, UINT,UINT*, LPOVERLAPPED);
typedef BOOL    (*kmdfRead)(HANDLE, PVOID, UINT, UINT*, LPOVERLAPPED);
typedef BOOL    (*kmdfClose)(HANDLE);
typedef void    (*setPrintCallBack)(PrintCallback);
typedef void    (*testPrintCallBack)(const char*);
static kmdfOpen _kmdfOpen;
static kmdfRevc _kmdfRevc;
static kmdfRead _kmdfRead;
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
        || X(_kmdfRead, kmdfRead)
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

BOOL DosPathToNtPath(LPTSTR pszDosPath, LPTSTR pszNtPath)
{
    TCHAR            szDriveStr[500];
    TCHAR            szDrive[3];
    TCHAR            szDevName[100];
    INT                iDevName;
    INT                i;

    //检查参数
    if (!pszDosPath || !pszNtPath)
        return FALSE;

    //获取本地磁盘所有盘符,以'\0'分隔,所以下面+4
    if (GetLogicalDriveStrings(sizeof(szDriveStr), szDriveStr))
    {
        for (i = 0; szDriveStr[i]; i += 4)
        {
            if (!lstrcmpi(&(szDriveStr[i]), _T("A:\\")) || !lstrcmpi(&(szDriveStr[i]), _T("B:\\")))
                continue;    //从C盘开始

            //盘符
            szDrive[0] = szDriveStr[i];
            szDrive[1] = szDriveStr[i + 1];
            szDrive[2] = '\0';
            if (!QueryDosDevice(szDrive, szDevName, 100))//查询 Dos 设备名(盘符由NT查询DOS)
                return FALSE;

            iDevName = lstrlen(szDevName);
            if (_tcsnicmp(pszDosPath, szDevName, iDevName) == 0)//是否为此盘
            {
                lstrcpy(pszNtPath, szDrive);//复制驱动器
                lstrcat(pszNtPath, pszDosPath + iDevName);//复制路径

                return TRUE;
            }
        }
    }

    lstrcpy(pszNtPath, pszDosPath);

    return FALSE;
}
//获取进程完整路径
BOOL GetProcessFullPath(DWORD dwPID)
{
    TCHAR        szImagePath[MAX_PATH];
    TCHAR        pszFullPath[MAX_PATH];
    HANDLE        hProcess;
    if (!pszFullPath)
        return FALSE;

    pszFullPath[0] = '\0';

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, dwPID);    //由线程ID获得线程信息
    if (!hProcess)
        return FALSE;

    if (!GetProcessImageFileName(hProcess, szImagePath, MAX_PATH))    //得到线程完整DOS路径
    {
        CloseHandle(hProcess);
        return FALSE;
    }
    if (!DosPathToNtPath(szImagePath, pszFullPath))    //DOS路径转NT路径
    {
        CloseHandle(hProcess);
        return FALSE;
    }

    CloseHandle(hProcess);

    _tprintf(_T("%5d  %s \r\n"), dwPID, pszFullPath);
    return TRUE;
}

PROCESSINFO pinfo;
int main()
{
    setlocale(LC_ALL, "chs");    //不设置解析中文字符时可能会出问题
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
                /*wstring ppname = GetModuleName(pinfo.parentId);
                wstring pname = GetModuleName(pinfo.processId);
                printf("ModuleName: PPNAME = %ws, PNAME = %ws \r\n",ppname.c_str(),pname.c_str());*/
                GetProcessFullPath(pinfo.parentId);
                GetProcessFullPath(pinfo.processId);
            }
            //Sleep(100);
        }
        if (_kmdfClose(handle))
        {
            printf("1 close error!\n");
        }
        break;
    case '2':
        handle = _kmdfOpen();
        __Overlapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
        while (handle != INVALID_HANDLE_VALUE)
        {
            memset(&pinfo, sizeof(PROCESSINFO), 0);
            ret = _kmdfRead(handle, (PVOID)&pinfo, sizeof(PROCESSINFO), &ulResult, &__Overlapped);
            printf("%d-%ld: PPID = %d, PID = %d NEW=%d \r\n",
                idx++,
                timeGetTime(),
                (int)pinfo.parentId,
                (int)pinfo.processId,
                pinfo.isCreate);
            if (pinfo.isCreate)
            {
                /*wstring ppname = GetModuleName(pinfo.parentId);
                wstring pname = GetModuleName(pinfo.processId);
                printf("ModuleName: PPNAME = %ws, PNAME = %ws \r\n", ppname.c_str(), pname.c_str());*/
                GetProcessFullPath(pinfo.parentId);
                GetProcessFullPath(pinfo.processId);
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