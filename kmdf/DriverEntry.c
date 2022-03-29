#include <ntifs.h>
#include <fltKernel.h>
#include <wdf.h>
#include <wdfdriver.h>
#include <wdfrequest.h>
#include "common.h"

KSPIN_LOCK		g_Lock;			// �����������
LIST_ENTRY		g_ListHead;		// ����ͷ
KEVENT			g_Event;		// ����֪ͨ���¼�

VOID CreateProcessRoutineSpy(
	IN HANDLE  parentId, IN HANDLE  processId, IN BOOLEAN  isCreate
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
	// �������̼��ӻص�
	status = PsSetCreateProcessNotifyRoutine(CreateProcessRoutineSpy, FALSE);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[t]Failed to call PsSetCreateProcessNotifyRoutineEx, error code = 0x%08X\r\n", status));
	}
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	// ���� Irp �����Ѿ�������ɣ���Ҫ�ټ�������
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS CloseCompleteRoutine(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;

	KdPrint(("[t]Close...\r\n"));
	// �ָ����̼�ػص�
	status = PsSetCreateProcessNotifyRoutine(CreateProcessRoutineSpy, TRUE);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[t]Failed to call PsSetCreateProcessNotifyRoutineEx, error code = 0x%08X\r\n", status));
	}
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	// ���� Irp �����Ѿ�������ɣ���Ҫ�ټ�������
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS ReadCompleteRoutine(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;

	KdPrint(("[t]Read...\r\n"));

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	// ���� Irp �����Ѿ�������ɣ���Ҫ�ټ�������
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS WriteCompleteRoutine(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;

	KdPrint(("[t]Write...\r\n"));

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	// ���� Irp �����Ѿ�������ɣ���Ҫ�ټ�������
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
		case CWK_DVC_SEND_STR:			// ���յ�������������
		{
			ASSERT(pBuffer != NULL);
			ASSERT(ulInputlength > 0);
			ASSERT(ulOutputlength == 0);
			KdPrint(("pBuffer = %s", (char*)pBuffer));
		}
		break;
		case CWK_DVC_RECV_STR:			// ���յ���ȡ��������
		{
			ASSERT(pBuffer != NULL);
			ASSERT(ulInputlength == 0);

			// ��������� Buffer ��СС�� PROCESSINFO �ṹ���С�����жϷǷ�
			if (ulOutputlength < sizeof(PROCESSINFO))
			{
				status = STATUS_INVALID_BUFFER_SIZE;
				break;
			}

			// ����һ��ѭ�������ϴ����������Ƿ��нڵ�
			while (TRUE)
			{
				PPROCESSNODE pNode = (PPROCESSNODE)ExInterlockedRemoveHeadList(&g_ListHead, &g_Lock);

				// ����õ��˽ڵ㣬�򴫸�Ӧ�ò㣬ֱ���� pBuffer ���渳ֵ��Ӧ�ò� DeviceIoControl �����յ�����
				if (NULL != pNode)
				{
					PPROCESSINFO pProcessInfo = (PPROCESSINFO)pBuffer;
					if (NULL != pNode->pProcessInfo)
					{
						// ��Ӧ�ò� Buffer ��ֵ
						pProcessInfo->parentId = pNode->pProcessInfo->parentId;
						pProcessInfo->processId = pNode->pProcessInfo->processId;
						pProcessInfo->isCreate = pNode->pProcessInfo->isCreate;
						uLength = sizeof(PROCESSINFO);
						// �ͷ��ڴ�
						ExFreePoolWithTag(pNode->pProcessInfo, MEM_TAG);
					}
					// �ͷ��ڴ�
					ExFreePoolWithTag(pNode, MEM_TAG);
					break;
				}
				else
				{
					// ���û��ȡ���ڵ㣬��ȴ�һ���¼�֪ͨ�����¼��� CreateProcessNotifyEx �����лᱻ����
					// ������һ���µĽ���ʱ�����������һ���ڵ㣬ͬʱ���¼�������Ϊ���ź�״̬
					// ��� KeWaitForSingleObject ���ؼ���ִ��ѭ��������ִ��ʱ�Ϳ���ȡ���µĽڵ�������
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
	// ����һ������ڵ�
	PPROCESSNODE pNode = InitListNode();
	if (pNode != NULL)
	{
		// ���ڵ�� pProcessInfo �����ڴ�
		// �� ProcessInfo �ṹ����Ӧ�ò�ʹ�õ���ͬ���Ľṹ��
		// Ӧ�ò㴫����ͬ��С���ڴ��ṩ�ں�д����Ӧ����
		pNode->pProcessInfo = ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESSINFO), MEM_TAG);
		if (pNode->pProcessInfo)
		{
			// �����ڵ㸳ֵ
			pNode->pProcessInfo->parentId = parentId;
			pNode->pProcessInfo->processId = processId;
			pNode->pProcessInfo->isCreate = isCreate;
			KdPrint(("[t]PPID = %d, PID = %d,New=%d..\r\n", parentId, processId, isCreate));
			// �������������¼�
			ExInterlockedInsertTailList(&g_ListHead, (PLIST_ENTRY)pNode, &g_Lock);
		}
		// �������������һ��Ҫע�⣬���Ϊ TRUE ���ʾ KeSetEvent ����һ������һ�� KeWaitForSigleObject
		// ����� KeWaitForSigleObject ���� KeSetEvent ����֮��������Ϊ FLASE������ᵼ�� 0x0000004A ����
		KeSetEvent(&g_Event, 0, FALSE);
	}
}

VOID DriverUnLoad(PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING usSymbolicName;
	RtlInitUnicodeString(&usSymbolicName, L"\\??\\_ProcessMonitor");

	// ɾ���������Ӻ��豸����
	if (NULL != pDriverObject->DeviceObject)
	{
		IoDeleteSymbolicLink(&usSymbolicName);
		IoDeleteDevice(pDriverObject->DeviceObject);
		KdPrint(("[t]Unload driver success..\r\n"));
	}
	// �ͷ����������ڴ�
	while (TRUE)
	{
		// ��������ȡ��һ���ڵ�
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

	// ��ʼ���¼�����������ͷ
	KeInitializeEvent(&g_Event, SynchronizationEvent, TRUE);
	KeInitializeSpinLock(&g_Lock);
	InitializeListHead(&g_ListHead);

	// �����豸�ͷ�������
	CreateDevice(pDriverObject);

	// ����ͬ�� IRP ����
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCompleteRoutine;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = CloseCompleteRoutine;
	pDriverObject->MajorFunction[IRP_MJ_READ] = ReadCompleteRoutine;
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = WriteCompleteRoutine;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlCompleteRoutine;

	pDriverObject->DriverUnload = DriverUnLoad;

	return status;
}