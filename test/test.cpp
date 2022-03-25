// testDevice.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>

#define IOCTL_STARTUP                                             \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x921, METHOD_IN_DIRECT, FILE_READ_DATA | \
        FILE_WRITE_DATA)
#define IOCTL_RECV                                             \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x922, METHOD_IN_DIRECT, FILE_READ_DATA | \
        FILE_WRITE_DATA)
#define IOCTL_SHUTDOWN                                       \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x923, METHOD_IN_DIRECT, FILE_READ_DATA | \
        FILE_WRITE_DATA)

#pragma pack(push, 1)
typedef union
{
	struct
	{
		UINT64 addr;                // WINDIVERT_ADDRESS pointer.
		UINT64 addr_len_ptr;        // sizeof(addr) pointer.
	} recv;
	struct
	{
		UINT64 addr;                // WINDIVERT_ADDRESS pointer.
		UINT64 addr_len;            // sizeof(addr).
	} send;
	struct
	{
		UINT32 layer;               // Handle layer.
		UINT32 priority;            // Handle priority.
		UINT64 flags;               // Handle flags.
	} initialize;
	struct
	{
		UINT64 flags;               // Filter flags.
	} startup;
	struct
	{
		UINT32 how;                 // WINDIVERT_SHUTDOWN_*
	} shutdown;
	struct
	{
		UINT32 param;               // WINDIVERT_PARAM_*
	} get_param;
	struct
	{
		UINT64 val;                 // Value pointer.
		UINT32 param;               // WINDIVERT_PARAM_*
	} set_param;
} WINDIVERT_IOCTL, * PWINDIVERT_IOCTL;
#pragma pack(pop)

typedef struct
{
	INT32 processId;
	INT32 parentId;
	BOOLEAN isCreate;
}CUSTOMERDATA, *PCUSTOMERDATA;

static DWORD tls_idx;
static BOOL IoControlEx(HANDLE handle, DWORD code,
	PVOID ioctl, PVOID buf, UINT len, UINT* iolen,
	LPOVERLAPPED overlapped);
static BOOL IoControl(HANDLE handle, DWORD code,
	PVOID ioctl, PVOID buf, UINT len, UINT* iolen);
static BOOL InstallService();

int main()
{
	if (InstallService())
	{
		printf("InstallService failed \n");
		system("pause");
		return 0;
	}
	printf("install succ \n");
	// 打开符号，设备句柄
	HANDLE handle = CreateFile(L"\\\\.\\kmdfTest",
		GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		INVALID_HANDLE_VALUE);
	if (handle == INVALID_HANDLE_VALUE)
	{
		printf("create file failed:%ld\n", GetLastError());
		system("pause");
		return 0;
	}
	printf("create succ \n");
	system("pause");
	//创建一个缓冲区进行读写
	PCUSTOMERDATA buffer = new CUSTOMERDATA();
	UINT size;
	WINDIVERT_IOCTL ioctl;
	memset(&ioctl, 0, sizeof(ioctl));
	ioctl.recv.addr = (UINT64)(ULONG_PTR)buffer;
	ioctl.recv.addr_len_ptr = (UINT64)(ULONG_PTR)NULL;
	BOOL ret = false;
	BOOL out = false;
	while (true)
	{
		ret = IoControl(handle, IOCTL_RECV, &ioctl, NULL, 0, &size);
		if (ret == FALSE)
		{
			printf("IoControl failed \n");
			switch (getchar())
			{
			case '0':
				out = true;
				break;
			}
		}
		else
		{
			out = false;
			printf("%d-%d-%d-%d\n",size,buffer->parentId,buffer->processId,buffer->isCreate);
		}
		if (out)
		{
			break;
		}
		Sleep(100);
	}
	printf("out \n");
   //// 从设备中读取数据
   //BOOL result = ReadFile(hDevice,buffer,10,&size,NULL);
   //if (result)
   //{
   //	//printf
   //	printf("size=%d:", size);
   //	for (size_t i = 0; i < size; i++)
   //	{
   //		printf("%02X ",buffer[i]);
   //	}
   //	printf("\n");
   //}
   //else
   //{
   //	printf("read failed:%ld \n", GetLastError());
   //}
	system("pause");
	CloseHandle(handle);
	return 0;
}

static BOOL InstallService()
{
	SC_HANDLE manager = NULL, service = NULL;
	BOOL success = TRUE;
	// Open the service manager:
	manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (manager == NULL)
	{
		printf("OpenSCManager failed\n");
		goto InstallExit;
	}

	service = OpenService(manager, L"kmdfTest", SERVICE_ALL_ACCESS);
	if (service != NULL)
	{
		printf("OpenService succ\n");
		goto InstallExit;
	}

	// Create the service:
	service = CreateService(manager, L"kmdfTest",
		L"kmdfTest", SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, L"C:\\Users\\vvx\\Desktop\\bin\\kmdf.sys", NULL, NULL,
		NULL, NULL, NULL);
	if (service == NULL)
	{
		if (GetLastError() == ERROR_SERVICE_EXISTS)
		{
			service = OpenService(manager, L"kmdfTest", SERVICE_ALL_ACCESS);
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

static BOOL IoControl(HANDLE handle, DWORD code,
	PVOID ioctl, PVOID buf, UINT len, UINT* iolen)
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
	if (!IoControlEx(handle, code, ioctl, buf, len, iolen,
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

static BOOL IoControlEx(HANDLE handle, DWORD code,
	PVOID ioctl, PVOID buf, UINT len, UINT* iolen,
	LPOVERLAPPED overlapped)
{
	BOOL result;
	DWORD iolen0;

	result = DeviceIoControl(handle, code, ioctl, sizeof(UCHAR) * 100, buf,
		(DWORD)len, &iolen0, overlapped);
	if (result && iolen != NULL)
	{
		*iolen = (UINT)iolen0;
	}
	return result;
}