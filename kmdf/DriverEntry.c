#include <ntifs.h>
#include <fltKernel.h>
#include <wdf.h>
#include <wdfdriver.h>
#include <wdfrequest.h>
#include "common.h"

KSPIN_LOCK		g_Lock;			// 用于链表的锁
LIST_ENTRY		g_ListHead;		// 链表头
KEVENT			g_Event;		// 用于通知的事件
BOOLEAN			g_Collect;		// 开始收集

NTKERNELAPI
UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);

VOID CreateProcessRoutineSpy(
	IN HANDLE  parentId, IN HANDLE  processId, IN BOOLEAN  isCreate
);
VOID CreateProcessRoutineSpyEx(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

typedef struct
{
	LIST_ENTRY		list_entry;
	PPROCESSINFO	pProcessInfo;
} PROCESSNODE, * PPROCESSNODE;

PPROCESSNODE InitListNode()
{
	PPROCESSNODE pNode = NULL;

	pNode = (PPROCESSNODE)ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESSNODE), MEM_TAG);
	if (pNode == NULL)
	{
		return NULL;
	}

	return pNode;
}

NTSTATUS CreateDevice(PDRIVER_OBJECT pDriverObject)
{
	NTSTATUS status;
	PDEVICE_OBJECT pDeviceObject;
	UNICODE_STRING usDeviceName;
	UNICODE_STRING usSymbolicName;

	RtlInitUnicodeString(&usDeviceName, L"\\Device\\_ProcessMonitor");

	status = IoCreateDevice(
		pDriverObject,
		0,
		&usDeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		TRUE,
		&pDeviceObject);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	pDeviceObject->Flags |= DO_BUFFERED_IO;

	RtlInitUnicodeString(&usSymbolicName, L"\\??\\_ProcessMonitor");

	status = IoCreateSymbolicLink(&usSymbolicName, &usDeviceName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDeviceObject);
		return status;
	}

	return STATUS_SUCCESS;
}

NTSTATUS CreateCompleteRoutine(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;

	KdPrint(("[t]Create...\r\n"));
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	// 设置 Irp 请求已经处理完成，不要再继续传递
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	g_Collect = TRUE;
	return status;
}

NTSTATUS CloseCompleteRoutine(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;

	KdPrint(("[t]Close...\r\n"));
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	// 设置 Irp 请求已经处理完成，不要再继续传递
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	g_Collect = FALSE;
	return status;
}

NTSTATUS ReadCompleteRoutine(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	KdPrint(("[t]Read...\r\n"));

	NTSTATUS			status = STATUS_SUCCESS;
	PIO_STACK_LOCATION	pIrpsp = IoGetCurrentIrpStackLocation(pIrp);
	ULONG				uLength = 0;

	PVOID pBuffer = pIrp->AssociatedIrp.SystemBuffer;
	ULONG ulBufferlength = pIrpsp->Parameters.Read.Length;
	ASSERT(pBuffer != NULL);
	ASSERT(ulBufferlength == 0);
	// 如果给出的 Buffer 大小小于 PROCESSINFO 结构体大小，则判断非法
	if (ulBufferlength < sizeof(PROCESSINFO))
	{
		status = STATUS_INVALID_BUFFER_SIZE;
		goto _OUT;
	}
	// 创建一个循环，不断从链表中拿是否有节点
	while (TRUE)
	{
		PPROCESSNODE pNode = (PPROCESSNODE)ExInterlockedRemoveHeadList(&g_ListHead, &g_Lock);

		// 如果拿到了节点，则传给应用层，直接想 pBuffer 里面赋值，应用层 DeviceIoControl 就能收到数据
		if (NULL != pNode)
		{
			PPROCESSINFO pProcessInfo = (PPROCESSINFO)pBuffer;
			if (NULL != pNode->pProcessInfo)
			{
				// 给应用层 Buffer 赋值
				pProcessInfo->parentId = pNode->pProcessInfo->parentId;
				pProcessInfo->processId = pNode->pProcessInfo->processId;
				pProcessInfo->isCreate = pNode->pProcessInfo->isCreate;
				uLength = sizeof(PROCESSINFO);
				KdPrint(("[t]Read PPID = %d, PID = %d,New=%d..\r\n", pProcessInfo->parentId, pProcessInfo->processId, pProcessInfo->isCreate));
				// 释放内存
				ExFreePoolWithTag(pNode->pProcessInfo, MEM_TAG);
			}
			// 释放内存
			ExFreePoolWithTag(pNode, MEM_TAG);
			break;
		}
		else
		{
			// 如果没有取到节点，则等待一个事件通知，该事件在 CreateProcessNotifyEx 函数中会被设置
			// 当产生一个新的进程时会向链表插入一个节点，同时该事件被设置为有信号状态
			// 随后 KeWaitForSingleObject 返回继续执行循环，继续执行时就可以取到新的节点数据了
			KeWaitForSingleObject(&g_Event, Executive, KernelMode, 0, 0);
		}
	}
_OUT:
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = uLength;
	// 设置 Irp 请求已经处理完成，不要再继续传递
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	KdPrint(("[t]ReadCompleteRoutine status:0x%08X \r\n", status));
	return status;
}

NTSTATUS WriteCompleteRoutine(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;

	KdPrint(("[t]Write...\r\n"));

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	// 设置 Irp 请求已经处理完成，不要再继续传递
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS DeviceControlCompleteRoutine(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	NTSTATUS			status = STATUS_SUCCESS;
	PIO_STACK_LOCATION	pIrpsp = IoGetCurrentIrpStackLocation(pIrp);
	ULONG				uLength = 0;

	PVOID pBuffer = pIrp->AssociatedIrp.SystemBuffer;
	ULONG ulInputlength = pIrpsp->Parameters.DeviceIoControl.InputBufferLength;
	ULONG ulOutputlength = pIrpsp->Parameters.DeviceIoControl.OutputBufferLength;

	do
	{
		switch (pIrpsp->Parameters.DeviceIoControl.IoControlCode)
		{
		case CWK_DVC_SEND_STR:			// 接收到发送数据请求
		{
			ASSERT(pBuffer != NULL);
			ASSERT(ulInputlength > 0);
			ASSERT(ulOutputlength == 0);
			KdPrint(("pBuffer = %s", (char*)pBuffer));
		}
		break;
		case CWK_DVC_RECV_STR:			// 接收到获取数据请求
		{
			ASSERT(pBuffer != NULL);
			ASSERT(ulInputlength == 0);

			// 如果给出的 Buffer 大小小于 PROCESSINFO 结构体大小，则判断非法
			if (ulOutputlength < sizeof(PROCESSINFO))
			{
				status = STATUS_INVALID_BUFFER_SIZE;
				break;
			}

			// 创建一个循环，不断从链表中拿是否有节点
			while (TRUE)
			{
				PPROCESSNODE pNode = (PPROCESSNODE)ExInterlockedRemoveHeadList(&g_ListHead, &g_Lock);

				// 如果拿到了节点，则传给应用层，直接想 pBuffer 里面赋值，应用层 DeviceIoControl 就能收到数据
				if (NULL != pNode)
				{
					PPROCESSINFO pProcessInfo = (PPROCESSINFO)pBuffer;
					if (NULL != pNode->pProcessInfo)
					{
						// 给应用层 Buffer 赋值
						pProcessInfo->parentId = pNode->pProcessInfo->parentId;
						pProcessInfo->processId = pNode->pProcessInfo->processId;
						pProcessInfo->isCreate = pNode->pProcessInfo->isCreate;
						uLength = sizeof(PROCESSINFO);
						KdPrint(("[t]IOCtrl PPID = %d, PID = %d,New=%d..\r\n", pProcessInfo->parentId, pProcessInfo->processId, pProcessInfo->isCreate));
						// 释放内存
						ExFreePoolWithTag(pNode->pProcessInfo, MEM_TAG);
					}
					// 释放内存
					ExFreePoolWithTag(pNode, MEM_TAG);
					break;
				}
				else
				{
					// 如果没有取到节点，则等待一个事件通知，该事件在 CreateProcessNotifyEx 函数中会被设置
					// 当产生一个新的进程时会向链表插入一个节点，同时该事件被设置为有信号状态
					// 随后 KeWaitForSingleObject 返回继续执行循环，继续执行时就可以取到新的节点数据了
					KeWaitForSingleObject(&g_Event, Executive, KernelMode, 0, 0);
				}
			}
		}
		break;
		default:
		{
			status = STATUS_INVALID_PARAMETER;
		}
		break;
		}
	} while (FALSE);

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = uLength;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return status;
}

VOID CreateProcessRoutineSpy(
	IN HANDLE  parentId, IN HANDLE  processId, IN BOOLEAN  isCreate
)
{
	if (!g_Collect)
	{
		KdPrint(("[t]ignore PPID = %d, PID = %d,New=%d..\r\n", (int)parentId, (int)processId, isCreate));
		return;
	}
	// 创建一个链表节点
	PPROCESSNODE pNode = InitListNode();
	if (pNode != NULL)
	{
		// 给节点的 pProcessInfo 分配内存
		// 该 ProcessInfo 结构体与应用层使用的是同样的结构体
		// 应用层传入相同大小的内存提供内核写入相应数据
		pNode->pProcessInfo = ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESSINFO), MEM_TAG);
		if (pNode->pProcessInfo)
		{
			// 给各节点赋值
			pNode->pProcessInfo->parentId = parentId;
			pNode->pProcessInfo->processId = processId;
			pNode->pProcessInfo->isCreate = isCreate;
			KdPrint(("[t]Collect PPID = %d, PID = %d,New=%d..\r\n", parentId, processId, isCreate));
			// 插入链表，设置事件
			ExInterlockedInsertTailList(&g_ListHead, (PLIST_ENTRY)pNode, &g_Lock);
		}
		// 这里第三个参数一定要注意，如果为 TRUE 则表示 KeSetEvent 后面一定会有一个 KeWaitForSigleObject
		// 而如果 KeWaitForSigleObject 不在 KeSetEvent 调用之后，则设置为 FLASE，否则会导致 0x0000004A 蓝屏
		KeSetEvent(&g_Event, 0, FALSE);
	}
}

VOID CreateProcessRoutineSpyEx(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	PUCHAR ExeName = PsGetProcessImageFileName(Process);
	KdPrint(("[t]Ex PNAME=%s,PID = %d,New=%d..\r\n", ExeName,(int)ProcessId, CreateInfo != NULL));
	if (CreateInfo)
	{
		
		KdPrint(("[t]Ex FileOpenNameAvailable=%d,IsSubsystemProcess = %d,PPID=%d..\r\n", CreateInfo->FileOpenNameAvailable,CreateInfo->IsSubsystemProcess, CreateInfo->ParentProcessId));
		if (CreateInfo->IsSubsystemProcess)
		{
			KdPrint(("[t]Ex FileName=%s..\r\n", CreateInfo->FileObject->FileName.Buffer));
		}
		KdPrint(("[t]Ex ImageFileName=%s..\r\n", CreateInfo->ImageFileName));
	}
}

VOID DriverUnLoad(PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING usSymbolicName;
	RtlInitUnicodeString(&usSymbolicName, L"\\??\\_ProcessMonitor");

	// 删除符号链接和设备对象
	if (NULL != pDriverObject->DeviceObject)
	{
		IoDeleteSymbolicLink(&usSymbolicName);
		IoDeleteDevice(pDriverObject->DeviceObject);
		KdPrint(("[t]Unload driver success..\r\n"));
	}

	g_Collect = FALSE;
	// 恢复进程监控回调
	NTSTATUS status = PsSetCreateProcessNotifyRoutine(CreateProcessRoutineSpy, TRUE);
	//NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(CreateProcessRoutineSpyEx, TRUE);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[t]Failed to call PsSetCreateProcessNotifyRoutineEx, error code = 0x%08X\r\n", status));
	}

	// 释放链表所有内存
	while (TRUE)
	{
		// 从链表中取出一个节点
		PPROCESSNODE pNode = (PPROCESSNODE)ExInterlockedRemoveHeadList(&g_ListHead, &g_Lock);
		if (NULL != pNode)
		{
			if (NULL != pNode->pProcessInfo)
			{
				ExFreePoolWithTag(pNode->pProcessInfo, MEM_TAG);
			}
			ExFreePoolWithTag(pNode, MEM_TAG);
		}
		else
		{
			break;
		}
	};
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;

	KdPrint(("[t]pRegistryPath = %wZ\r\n", pRegistryPath));

	// 初始化事件、锁、链表头
	KeInitializeEvent(&g_Event, SynchronizationEvent, TRUE);
	KeInitializeSpinLock(&g_Lock);
	InitializeListHead(&g_ListHead);

	// 创建设备和符号链接
	CreateDevice(pDriverObject);

	// 处理不同的 IRP 请求
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCompleteRoutine;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = CloseCompleteRoutine;
	pDriverObject->MajorFunction[IRP_MJ_READ] = ReadCompleteRoutine;
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = WriteCompleteRoutine;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlCompleteRoutine;

	pDriverObject->DriverUnload = DriverUnLoad;

	g_Collect = FALSE;
	// 创建进程监视回调
	status = PsSetCreateProcessNotifyRoutine(CreateProcessRoutineSpy, FALSE);
	//status = PsSetCreateProcessNotifyRoutineEx(CreateProcessRoutineSpyEx, FALSE);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[t]Failed to call PsSetCreateProcessNotifyRoutineEx, error code = 0x%08X\r\n", status));
	}

	return status;
}