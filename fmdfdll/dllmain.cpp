// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <string>
#include <iostream>
#include <Shlwapi.h>
#include "common.h"

using namespace std;

#pragma comment(lib,"shlwapi.lib")

#define SERVICE_NAME L"_ProcessMonitor"
#define DEVICE_NAME L"\\\\.\\_ProcessMonitor"

static BOOL InstallService();

/*
 * Thread local.
 */
static DWORD tls_idx;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	HANDLE event;
    switch (ul_reason_for_call)
    {
		case DLL_PROCESS_ATTACH:
		{
			if ((tls_idx = TlsAlloc()) == TLS_OUT_OF_INDEXES)
			{
				return FALSE;
			}
		}
		break;
		case DLL_THREAD_ATTACH:
		{
			event = CreateEvent(NULL, FALSE, FALSE, NULL);
			if (event == NULL)
			{
				return FALSE;
			}
			TlsSetValue(tls_idx, (LPVOID)event);
		}
		break;
		case DLL_THREAD_DETACH:
		{
			event = (HANDLE)TlsGetValue(tls_idx);
			if (event != (HANDLE)NULL)
			{
				CloseHandle(event);
			}
		}
		break;
		case DLL_PROCESS_DETACH:
		{
			event = (HANDLE)TlsGetValue(tls_idx);
			if (event != (HANDLE)NULL)
			{
				CloseHandle(event);
			}
			TlsFree(tls_idx);
		}
        break;
    }
    return TRUE;
}

HANDLE kmdfOpen()
{
	HANDLE handle;
	DWORD err;
	handle = CreateFile(L"\\\\.\\" DEVICE_NAME,
		GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, INVALID_HANDLE_VALUE);
	if (INVALID_HANDLE_VALUE == handle)
	{
		err = GetLastError();
		if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND)
		{
			SetLastError(err);
			return INVALID_HANDLE_VALUE;
		}

		SetLastError(0);
		if (!InstallService())
		{
			err = GetLastError();
			err = (err == 0 ? ERROR_OPEN_FAILED : err);
			SetLastError(err);
			return INVALID_HANDLE_VALUE;
		}
		handle = CreateFile(L"\\\\.\\" DEVICE_NAME,
			GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
			INVALID_HANDLE_VALUE);
		if (handle == INVALID_HANDLE_VALUE)
		{
			err = GetLastError();
			SetLastError(err);
			return INVALID_HANDLE_VALUE;
		}
	}
    return handle;
}

//static wstring GetExePath(const wchar_t* appName)
//{
//	WCHAR buf[MAX_PATH] = { 0 };
//	wstring strPath;
//	GetModuleFileName(nullptr, buf, MAX_PATH);
//	PathRemoveFileSpec(buf);
//	strPath = buf;
//	strPath += L"\\";
//	strPath += appName;
//	return strPath;
//}

static BOOL InstallService()
{
	SC_HANDLE manager = NULL, service = NULL;
	BOOL success = TRUE;
	wstring sysFile = L"kmdf.sys";
	wstring sysPath(GetExePath(sysFile.c_str()));
	// Open the service manager:
	manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (manager == NULL)
	{
		goto InstallExit;
	}

	service = OpenService(manager, SERVICE_NAME, SERVICE_ALL_ACCESS);
	if (service != NULL)
	{
		goto InstallExit;
	}
	
	// Create the service:
	service = CreateService(manager, SERVICE_NAME,
		SERVICE_NAME, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, sysPath.c_str(), NULL, NULL,
		NULL, NULL, NULL);
	if (service == NULL)
	{
		if (GetLastError() == ERROR_SERVICE_EXISTS)
		{
			service = OpenService(manager, SERVICE_NAME, SERVICE_ALL_ACCESS);
		}
		goto InstallExit;
	}
InstallExit:
	success = (service != NULL);
	if (service != NULL)
	{
		// Start the service:
		success = StartService(service, 0, NULL);		
		if (!success)
		{
			success = (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING);
		}
		else
		{
			// Mark the service for deletion.  This will cause the driver to
			// unload if (1) there are no more open handles, and (2) the
			// service is STOPPED or on system reboot.
			printf("DeleteService failed\n");
			(VOID)DeleteService(service);
		}
	}

	DWORD err = GetLastError();
	if (manager != NULL)
	{
		CloseServiceHandle(manager);
	}
	if (service != NULL)
	{
		CloseServiceHandle(service);
	}
	SetLastError(err);
	return success;
}

/*
 * Perform an (overlapped) DeviceIoControl.
 */
static BOOL IoControlEx(HANDLE handle, DWORD code,
	PVOID buf, UINT len, UINT* iolen,
	LPOVERLAPPED overlapped)
{
	BOOL result;
	DWORD iolen0;

	result = DeviceIoControl(handle, code, NULL, 0, &buf, (DWORD)len, &iolen0, overlapped);
	if (result && iolen != NULL)
	{
		*iolen = (UINT)iolen0;
	}
	return result;
}

/*
 * Perform a DeviceIoControl.
 */
static BOOL IoControl(HANDLE handle, DWORD code,PVOID buf, UINT len, UINT* iolen)
{
	OVERLAPPED overlapped;
	DWORD iolen0;
	HANDLE event;

	event = (HANDLE)TlsGetValue(tls_idx);
	if (event == (HANDLE)NULL)
	{
		event = CreateEvent(NULL, FALSE, FALSE, NULL);
		if (event == NULL)
		{
			return FALSE;
		}
		TlsSetValue(tls_idx, (LPVOID)event);
	}

	memset(&overlapped, 0, sizeof(overlapped));
	overlapped.hEvent = event;
	if (!IoControlEx(handle, code,buf, len, iolen,
		&overlapped))
	{
		if (GetLastError() != ERROR_IO_PENDING ||
			!GetOverlappedResult(handle, &overlapped, &iolen0, TRUE))
		{
			return FALSE;
		}
		if (iolen != NULL)
		{
			*iolen = (UINT)iolen0;
		}
	}
	return TRUE;
}

/*
 * Receive.
 */
BOOL kmdfRevc(HANDLE handle, PVOID pPacket, UINT packetLen,
	UINT* readLen,LPOVERLAPPED overlapped)
{
	if (overlapped == NULL)
	{
		return IoControl(handle, CWK_DVC_RECV_STR,
			pPacket, packetLen, readLen);
	}
	else
	{
		return IoControlEx(handle, CWK_DVC_RECV_STR,
			pPacket, packetLen, readLen, overlapped);
	}
}

BOOL kmdfClose(HANDLE handle)
{
	return CloseHandle(handle);
}