#pragma once
#ifndef KMDF
#include <winioctl.h>
#include <string>
using namespace std;
#endif // !KMDF

// 内存分配 TAG
#define MEM_TAG 'MEM'

// 从应用层给驱动发送一个字符串。
#define  CWK_DVC_SEND_STR \
	(ULONG)CTL_CODE( \
	FILE_DEVICE_UNKNOWN, \
	0x911,METHOD_BUFFERED, \
	FILE_WRITE_DATA)

// 从驱动读取一个字符串
#define  CWK_DVC_RECV_STR \
	(ULONG)CTL_CODE( \
	FILE_DEVICE_UNKNOWN, \
	0x912,METHOD_BUFFERED, \
	FILE_READ_DATA)

typedef struct _PROCESSINFO
{
	int processId;
	int parentId;
	BOOLEAN isCreate;
} PROCESSINFO, * PPROCESSINFO;

#ifndef KMDF
static wstring GetExePath(const wchar_t* appName)
{
	WCHAR buf[MAX_PATH] = { 0 };
	wstring strPath;
	GetModuleFileName(nullptr, buf, MAX_PATH);
	PathRemoveFileSpec(buf);
	strPath = buf;
	strPath += L"\\";
	strPath += appName;
	return strPath;
}
#endif