#include <fltKernel.h>
#include <wdf.h>
#include <wdfdriver.h>
#include <wdfrequest.h>

#define MYWDF_KDEVICE L"\\Device\\kmdfTest"//�豸���ƣ������ں�ģʽ�µ���������ʹ��
#define MYWDF_LINKNAME L"\\??\\kmdfTest"//�������ӣ������û�ģʽ�µĳ������ʹ����������豸��

typedef enum
{
	CONTEXT_STATE_OPENING = 0xA0,     // Context is opening.
	CONTEXT_STATE_OPEN = 0xB1,     // Context is open.
	CONTEXT_STATE_CLOSING = 0xC2,     // Context is closing.
	CONTEXT_STATE_CLOSED = 0xD3,     // Context is closed.
	CONTEXT_STATE_INVALID = 0xE4      // Context is invalid.
} context_state_t;

typedef struct
{
	context_state_t state;
	KSPIN_LOCK lock;                            // Context-wide lock.
	WDFDEVICE device;                           // Context's device.
	WDFFILEOBJECT object;                       // Context's parent object.
	PEPROCESS process;                          // Context's process.
	LIST_ENTRY workqueue;
	ULONGLONG work_queue_length;
	LIST_ENTRY dataqueue;
	ULONGLONG data_queue_length;
}DEVICE_CONTEXT, * PDEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, kmdf_context_get)

typedef struct
{
	INT32 processId;
	INT32 parentId;
	BOOLEAN isCreate;
}CUSTOMERDATA, * PCUSTOMERDATA;

VOID CreateProcessRoutineSpy(IN HANDLE  ParentId, IN HANDLE  ProcessId, IN BOOLEAN  Create);

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
	//WdfDeviceInitSetDeviceType(device_init, FILE_DEVICE_DEVAPI);
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
		KdPrint(("[MyWDFDevice]create device failed\n"));
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
		KdPrint(("[MyWDFDevice]Create IoQueue failed, %x\n", status));
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

	status = PsSetCreateProcessNotifyRoutine(CreateProcessRoutineSpy, FALSE);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[MyWDFDevice] PsSetCreateProcessNotifyRoutine failed status:(%x).\n", status));
		return status;
	}
DriverEntry_Complete:
	KdPrint(("[MyWDFDevice]DriverEntry_Complete status:[%x]\n", status));
	return status;
}

extern VOID kmdf_unload(WDFDRIVER Driver)
{
	KdPrint(("[MyWDFDevice]unload driver\n"));
	KdPrint(("[MyWDFDevice]Doesn't need to clean up the devices, since we only have control device here\n"));
	NTSTATUS status = PsSetCreateProcessNotifyRoutine(CreateProcessRoutineSpy, TRUE);
	if (NT_SUCCESS(status))
	{
		KdPrint(("[SysTest] remove process routune succ.\n"));
	}
}

VOID kmdf_create(__in WDFDEVICE Device, __in WDFREQUEST Request, __in WDFFILEOBJECT object)
{
	KdPrint(("[MyWDFDevice]kmdf_create"));
	//�õ��豸��������
	PDEVICE_CONTEXT context = kmdf_context_get(object);
	if (context)
	{
		RtlZeroMemory(context, sizeof(DEVICE_CONTEXT));
		KdPrint(("[MyWDFDevice] �õ��豸��������"));
	}
	else
	{
		KdPrint(("[MyWDFDevice] ��ȡ������ʧ��"));
	}
	WdfRequestComplete(Request, STATUS_SUCCESS);
}

VOID kmdf_close(__in  WDFFILEOBJECT object)
{
	KdPrint(("[MyWDFDevice]kmdf_close"));
}

VOID kmdf_ioctl(IN WDFQUEUE queue, IN WDFREQUEST request,
	IN size_t out_length, IN size_t in_length, IN ULONG code)
{
	KdPrint(("[MyWDFDevice]kmdf_ioctl"));
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
	KdPrint(("[MyWDFDevice]kmdf_caller_context"));
	WdfRequestComplete(request, STATUS_SUCCESS);
}
