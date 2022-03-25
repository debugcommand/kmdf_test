#include <fltKernel.h>
#include <wdf.h>
#include <wdfdriver.h>
#include <wdfrequest.h>

#define MYWDF_KDEVICE L"\\Device\\kmdfTest"//�豸���ƣ������ں�ģʽ�µ���������ʹ��
#define MYWDF_LINKNAME L"\\??\\kmdfTest"//�������ӣ������û�ģʽ�µĳ������ʹ����������豸��

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

typedef enum
{
	CONTEXT_STATE_OPENING = 0xA0,		// Context is opening.
	CONTEXT_STATE_OPEN = 0xB1,			// Context is open.
	CONTEXT_STATE_CLOSING = 0xC2,		// Context is closing.
	CONTEXT_STATE_CLOSED = 0xD3,		// Context is closed.
	CONTEXT_STATE_INVALID = 0xE4		// Context is invalid.
} context_state_t;

typedef struct
{
	context_state_t state;
	KSPIN_LOCK lock;                            // Context-wide lock.
	WDFDEVICE device;                           // Context's device.
	WDFFILEOBJECT object;                       // Context's parent object.
	PEPROCESS process;                          // Context's process.
	LIST_ENTRY data_queue;
	ULONGLONG data_queue_length;
	WDFQUEUE read_queue;                        // Read queue.
}DEVICE_CONTEXT, * PDEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, kmdf_context_get)

typedef struct
{
	INT32 processId;
	INT32 parentId;
	BOOLEAN isCreate;
}CUSTOMERDATA, * PCUSTOMERDATA;

/*
 * request context.
 */
struct req_context_s
{
	PCUSTOMERDATA addr;						// Pointer to address structure.
	UINT32* addr_len_ptr;                   // Pointer to address length.
	UINT32 addr_len;                        // Address length (in bytes).
};
typedef struct req_context_s req_context_s;
typedef struct req_context_s* req_context_t;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(req_context_s, kmdf_req_context_get);

VOID CreateProcessRoutineSpy(IN HANDLE  ParentId, IN HANDLE  ProcessId, IN BOOLEAN  Create);
static NTSTATUS kmdf_read(PDEVICE_CONTEXT context, WDFREQUEST request);

DRIVER_INITIALIZE DriverEntry;
//�����ص�
EVT_WDF_DRIVER_UNLOAD kmdf_unload;
EVT_WDF_DEVICE_FILE_CREATE kmdf_create;
EVT_WDF_FILE_CLOSE kmdf_close;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL kmdf_ioctl;
EVT_WDF_OBJECT_CONTEXT_DESTROY kmdf_destroy;
EVT_WDF_IO_IN_CALLER_CONTEXT kmdf_caller_context;

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	KdPrint(("[MyWDFDevice]DriverEntry �[[start]\n"));

	//�����������
	WDF_DRIVER_CONFIG cfg;//����������
	WDFDRIVER drv;//wdf framework ��������

	//�豸�������
	PWDFDEVICE_INIT device_init;
	UNICODE_STRING ustring;
	WDF_FILEOBJECT_CONFIG f_cfg;
	WDFDEVICE control_device;
	WDF_OBJECT_ATTRIBUTES obj_attrs;

	//IO QUEUE���
	WDF_IO_QUEUE_CONFIG qcfg;
	WDFQUEUE queue;
	//��ʼ��WDF_DRIVER_CONFIG
	WDF_DRIVER_CONFIG_INIT(
		&cfg,
		WDF_NO_EVENT_CALLBACK //���ṩAddDevice����
	);
	cfg.DriverInitFlags |= WdfDriverInitNonPnpDriver;  //ָ����pnp����
	cfg.EvtDriverUnload = kmdf_unload;  //ָ��ж�غ���
	//����һ��framework����������WDF�������棬WdfDriverCreate�Ǳ���Ҫ���õġ�
	//framework������������������wdf����ĸ����󣬻��仰˵framework����������wdf�������Ķ��㣬��û�и������ˡ�
	status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &cfg, &drv);
	if (!NT_SUCCESS(status))
	{
		goto DriverEntry_Complete;
	}

	KdPrint(("[MyWDFDevice]Create wdf driver object successfully\n"));
	//����һ���豸
	//��Ҫ����һ���ڴ�WDFDEVICE_INIT,����ڴ��ڴ����豸��ʱ����õ���
	device_init = WdfControlDeviceInitAllocate(drv, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
	if (device_init == NULL)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto DriverEntry_Complete;
	}
	WdfDeviceInitSetDeviceType(device_init, FILE_DEVICE_UNKNOWN);
	WdfDeviceInitSetIoType(device_init, WdfDeviceIoDirect);

	//�����豸�����֣��ں�ģʽ�£���������: L"\\Device\\MyWDF_Device"
	RtlInitUnicodeString(&ustring, MYWDF_KDEVICE);
	//���豸���ִ���device_init��
	status = WdfDeviceInitAssignName(device_init, &ustring);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[MyWDFDevice]WdfDeviceInitAssignName status:(%x)\n", status));
		WdfDeviceInitFree(device_init);
		goto DriverEntry_Complete;
	}	
	KdPrint(("[MyWDFDevice]Device name Unicode string: %wZ (this name can only be used by other kernel mode code, like other drivers)\n", &ustring));

	//����FILEOBJECT�����ļ�������FILECREATE,FILECLOSE�ص���
	WDF_FILEOBJECT_CONFIG_INIT(&f_cfg, kmdf_create, kmdf_close, NULL);
	//���豸������������һ��DEVICE_CONTEXT,��WDF_OBJECT_ATTRIBUTES_INIT��ȣ�WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE
	//�����һ���ڴ沢�Ҵ���WDF_OBJECT_ATTRIBUTES���� (object_attribs.ContextTypeInfo)��DEVICE_CONEXT�Ǹ��Զ���ṹ��
	WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&obj_attrs, DEVICE_CONTEXT);
	obj_attrs.ExecutionLevel = WdfExecutionLevelPassive;
	obj_attrs.SynchronizationScope = WdfSynchronizationScopeNone;
	obj_attrs.EvtDestroyCallback = kmdf_destroy;

	//��FILEOBJECT�����ô���device_init��
	WdfDeviceInitSetFileObjectConfig(device_init, &f_cfg, &obj_attrs);
	WdfDeviceInitSetIoInCallerContextCallback(device_init, kmdf_caller_context);

	//��ʼ���豸����
	WDF_OBJECT_ATTRIBUTES_INIT(&obj_attrs);
	//����ǰ�洴����device_init������һ���豸. (control device)
	status = WdfDeviceCreate(&device_init, &obj_attrs, &control_device);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[MyWDFDevice]create device failed:[%x]\n", status));
		goto DriverEntry_Complete;
	}
	//����IO queue
	//��ʼ��IO QUEUE CONFIG, WdfIoQueueDispatchParallel��˼��
	//The framework presents requests to the driver's request handlers as soon as the requests are available. 
	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&qcfg, WdfIoQueueDispatchParallel);
	qcfg.EvtIoRead = NULL;
	qcfg.EvtIoWrite = NULL;
	qcfg.EvtIoDeviceControl = kmdf_ioctl;

	//���豸control_device����IO QUEUE
	WDF_OBJECT_ATTRIBUTES_INIT(&obj_attrs);
	obj_attrs.ExecutionLevel = WdfExecutionLevelPassive;
	obj_attrs.SynchronizationScope = WdfSynchronizationScopeNone;
	status = WdfIoQueueCreate(control_device, &qcfg, &obj_attrs, &queue);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[MyWDFDevice]Create IoQueue failed:[%x]\n", status));
		goto DriverEntry_Complete;
	}
	//�����������ӣ������û�ģʽ�µĳ������ʹ���������������Ǳ���ģ���Ȼ�û�ģʽ�µĳ����ܷ�������豸��
	RtlInitUnicodeString(&ustring, MYWDF_LINKNAME);
	status = WdfDeviceCreateSymbolicLink(control_device, &ustring);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[MyWDFDevice]Failed to create Link\n"));
		goto DriverEntry_Complete;
	}

	KdPrint(("[MyWDFDevice]Create symbolic link successfully, %wZ (user mode code should use this name, like in CreateFile())\n", &ustring));

	WdfControlFinishInitializing(control_device);//�����豸��ɡ�
	/*******************************************
	��������Ǿͳɹ�������һ��control device��
	control device �ǲ�֧��png��power�ģ���������Ҳ����Ҫ�ֹ���ɾ����
	��Ϊframework�������ɾ������MSDN

	If your driver creates control device objects but does not create framework device objects that support PnP and power management,
	the driver does not have to delete the control device objects.

	In this case, the framework deletes the control device objects after the driver's EvtDriverUnload callback function returns.

	����ϸ�ڿ�MSDN,��
	http://msdn.microsoft.com/en-us/library/windows/hardware/ff545424(v=vs.85).aspx
	*******************************************/
	KdPrint(("[MyWDFDevice]Create device object successfully\n"));
DriverEntry_Complete:
	KdPrint(("[MyWDFDevice]DriverEntry_Complete status:[%x]\n", status));
	return status;
}

extern VOID kmdf_unload(WDFDRIVER Driver)
{
	KdPrint(("[MyWDFDevice]Doesn't need to clean up the devices, since we only have control device here\n"));
}

VOID kmdf_create(__in WDFDEVICE Device, __in WDFREQUEST Request, __in WDFFILEOBJECT object)
{
	KdPrint(("[MyWDFDevice]kmdf_create"));
	NTSTATUS status = STATUS_SUCCESS;
	PIRP irp;
	WDF_IO_QUEUE_CONFIG queue_config;
	WDF_WORKITEM_CONFIG item_config;
	WDF_OBJECT_ATTRIBUTES obj_attrs;	
	//�õ��豸��������
	PDEVICE_CONTEXT context = kmdf_context_get(object);
	if (context)
	{
		KdPrint(("[MyWDFDevice] �õ��豸��������"));
		// Initialise the new context:
		RtlZeroMemory(context, sizeof(DEVICE_CONTEXT));
		context->state = CONTEXT_STATE_OPEN;
		context->device = Device;
		context->object = object;
		context->process = NULL;

		KeInitializeSpinLock(&context->lock);

		WDF_IO_QUEUE_CONFIG_INIT(&queue_config, WdfIoQueueDispatchManual);
		status = WdfIoQueueCreate(Device, &queue_config, WDF_NO_OBJECT_ATTRIBUTES,
			&context->read_queue);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("[MyWDFDevice] kmdf_create WdfIoQueueCreate:[%x]", status));
			goto create_exit;
		}

		irp = WdfRequestWdmGetIrp(Request);
		context->process = IoGetRequestorProcess(irp);
		if (context->process == NULL)
		{
			status = STATUS_INVALID_DEVICE_REQUEST;
			KdPrint(("[MyWDFDevice] IoGetRequestorProcess:%x", status));
			goto create_exit;
		}
		ObfReferenceObject(context->process);
	}
	else
	{
		KdPrint(("[MyWDFDevice] ��ȡ������ʧ��"));
		WdfRequestComplete(Request, STATUS_CONTEXT_MISMATCH);
		return;
	}
	status = PsSetCreateProcessNotifyRoutine(CreateProcessRoutineSpy, FALSE);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[MyWDFDevice] PsSetCreateProcessNotifyRoutine failed status:(%x).\n", status));
	}
create_exit:
	// Clean-up on error:
	if (!NT_SUCCESS(status))
	{
		context->state = CONTEXT_STATE_INVALID;
		if (context->read_queue != NULL)
		{
			WdfObjectDelete(context->read_queue);
		}
		if (context->process != NULL)
		{
			ObDereferenceObject(context->process);
		}
	}
	WdfRequestComplete(Request, status);

}

VOID kmdf_close(__in  WDFFILEOBJECT object)
{
	KdPrint(("[MyWDFDevice]kmdf_close"));
	NTSTATUS status = PsSetCreateProcessNotifyRoutine(CreateProcessRoutineSpy, TRUE);
	if (NT_SUCCESS(status))
	{
		KdPrint(("[SysTest] remove process routune succ.\n"));
	}
}

VOID kmdf_ioctl(IN WDFQUEUE queue, IN WDFREQUEST request,
	IN size_t out_length, IN size_t in_length, IN ULONG code)
{
	KdPrint(("[MyWDFDevice]kmdf_ioctl"));
	PDEVICE_CONTEXT context = kmdf_context_get(request);
	NTSTATUS status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(queue);
	UNREFERENCED_PARAMETER(out_length);
	UNREFERENCED_PARAMETER(in_length);

	switch (code)
	{
	case IOCTL_RECV:
		status = kmdf_read(context,request);
		if (NT_SUCCESS(status))
		{
			return;
		}
		break;
	default:
		break;
	}
ioctl_exit:
	WdfRequestComplete(request, status);
}

VOID kmdf_destroy(IN WDFOBJECT object)
{
	KdPrint(("[MyWDFDevice]kmdf_destroy"));
}

VOID CreateProcessRoutineSpy(IN HANDLE  parentId, IN HANDLE  processId, IN BOOLEAN  isCreate)
{
	if (isCreate)
	{
		KdPrint(("[MyWDFDevice] Process Created-ProcessId:(%d) ParentId:(%d).\n", (int)parentId, (int)processId));
	}
	else
	{
		KdPrint(("[MyWDFDevice] Process Terminated-ProcessId:(%d).ParentId:(%d) .\n", (int)parentId, (int)processId));
	}
	return;
}

VOID kmdf_caller_context(IN WDFDEVICE device, IN WDFREQUEST request)
{
	KdPrint(("[MyWDFDevice]kmdf_caller_context 1"));
	PCHAR inbuf;
	size_t inbuflen;
	NTSTATUS status = STATUS_SUCCESS;
	req_context_t req_context = NULL;
	WDF_REQUEST_PARAMETERS params;
	WDF_OBJECT_ATTRIBUTES attributes;
	PCUSTOMERDATA addr = NULL;
	UINT32* addr_len_ptr = NULL;
	UINT64 addr_len = 0;
	PWINDIVERT_IOCTL ioctl;
	WDFMEMORY memobj;
	KdPrint(("[MyWDFDevice]kmdf_caller_context 2"));
	WDF_REQUEST_PARAMETERS_INIT(&params);
	WdfRequestGetParameters(request, &params);	
	if (params.Type != WdfRequestTypeDeviceControl)
	{
		KdPrint(("[MyWDFDevice]kmdf_caller_context WdfRequestGetParameters"));
		goto caller_context_exit;
	}

	KdPrint(("[MyWDFDevice]kmdf_caller_context 3"));
	// Get and verify the input buffer.
	status = WdfRequestRetrieveInputBuffer(request, 0, &inbuf, &inbuflen);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[MyWDFDevice] WdfRequestRetrieveInputBuffer:%x", status));
		goto caller_context_error;
	}
	KdPrint(("[MyWDFDevice]kmdf_caller_context 4"));

	if (inbuflen < sizeof(WINDIVERT_IOCTL))
	{
		status = STATUS_INVALID_PARAMETER;
		KdPrint(("[MyWDFDevice]input buffer not an ioctl message header:%x", status));
		goto caller_context_error;
	}
	KdPrint(("[MyWDFDevice]kmdf_caller_context 5"));

	// Probe and lock user buffers here (if required).
	WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, req_context_s);
	status = WdfObjectAllocateContext(request, &attributes, &req_context);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[MyWDFDevice]failed to allocate request context for ioctl:%x", status));
		goto caller_context_error;
	}
	KdPrint(("[MyWDFDevice]kmdf_caller_context 6"));

	switch (params.Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_RECV:
	{
		ioctl = (PWINDIVERT_IOCTL)inbuf;
		addr = (PCUSTOMERDATA)(ULONG_PTR)ioctl->recv.addr;
		addr_len_ptr = (UINT32*)(ULONG_PTR)ioctl->recv.addr_len_ptr;
		addr_len = sizeof(CUSTOMERDATA);
		if (addr_len_ptr != NULL)
		{
			status = WdfRequestProbeAndLockUserBufferForWrite(request,
				addr_len_ptr, sizeof(UINT32), &memobj);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("[MyWDFDevice]invalid address length pointer for RECV ioctl:%x", status));
				goto caller_context_error;
			}
			addr_len_ptr = (UINT32*)WdfMemoryGetBuffer(memobj, NULL);
			addr_len = *addr_len_ptr;
			if (addr_len < sizeof(CUSTOMERDATA))
			{
				status = STATUS_INVALID_PARAMETER;
				KdPrint(("[MyWDFDevice]out-of-range address length (%u) for RECVioctl:%x-%d", status, addr_len));
				goto caller_context_error;
			}
			if (addr == NULL)
			{
				status = STATUS_INVALID_PARAMETER;
				KdPrint(("[MyWDFDevice]null address for RECV ioctl:%x", status));
				goto caller_context_error;
			}
		}
		if (addr != NULL)
		{
			status = WdfRequestProbeAndLockUserBufferForWrite(request,addr,(size_t)addr_len, &memobj);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("[MyWDFDevice]invalid address for RECV ioctl:%x", status));
				goto caller_context_error;
			}
			addr = (PCUSTOMERDATA)WdfMemoryGetBuffer(memobj, NULL);
		}
	}
	break;
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		KdPrint(("[MyWDFDevice]failed to complete I/O control; invalid request:%x", status));
		goto caller_context_error;
	}

	req_context->addr = addr;
	req_context->addr_len = (UINT32)addr_len;
	req_context->addr_len_ptr = addr_len_ptr;
caller_context_exit:
	status = WdfDeviceEnqueueRequest(device, request);

caller_context_error:
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[MyWDFDevice]failed to enqueue request:%x", status));
		WdfRequestComplete(request, status);
	}
}

static NTSTATUS kmdf_read(PDEVICE_CONTEXT context,WDFREQUEST request)
{
	KLOCK_QUEUE_HANDLE lock_handle;
	NTSTATUS status = STATUS_SUCCESS;

	KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
	
	status = WdfRequestForwardToIoQueue(request,context->read_queue);
	KeReleaseInStackQueuedSpinLock(&lock_handle);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[MyWDFDevice]kmdf_read WdfRequestForwardToIoQueue:%x",status));
		return status;
	}
	return STATUS_SUCCESS;
}

static void kmdf_read_service(PDEVICE_CONTEXT context)
{
	WDFREQUEST request;
	KLOCK_QUEUE_HANDLE lock_handle;
	NTSTATUS status = STATUS_SUCCESS;
	req_context_t req_context;
	PCUSTOMERDATA addr;
	UINT32 i, addr_len, addr_len_max;
	UINT32* addr_len_ptr;

	KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
	status = WdfIoQueueRetrieveNextRequest(context->read_queue,&request);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[MyWDFDevice]kmdf_read_service WdfIoQueueRetrieveNextRequest:%x", status));
		goto _out;
	}
	req_context = kmdf_req_context_get(request);
	if (req_context == NULL)
	{
		KdPrint(("[MyWDFDevice]kmdf_read_service kmdf_req_context_get null"));
		goto _out;
	}
	addr = req_context->addr;
	if (req_context == NULL)
	{
		KdPrint(("[MyWDFDevice]kmdf_read_service kmdf_req_context_get null"));
		goto _out;
	}
	addr_len = 0;
	addr_len_max = (UINT32)req_context->addr_len;
	addr_len_ptr = req_context->addr_len_ptr;
	i = 0;

	addr[i].isCreate = FALSE;
	addr[i].parentId = 1;
	addr[i].processId = 2;
	addr_len += sizeof(CUSTOMERDATA);
	if (addr_len_ptr != NULL)
	{
		*addr_len_ptr = addr_len;
	}
	WdfRequestCompleteWithInformation(request, status, 0);
_out:
	KeReleaseInStackQueuedSpinLock(&lock_handle);
}