#include <fltKernel.h>
#include <wdf.h>
#include <wdfdriver.h>
#include <wdfrequest.h>

#define MYWDF_KDEVICE L"\\Device\\kmdfTest"//设备名称，其他内核模式下的驱动可以使用
#define MYWDF_LINKNAME L"\\??\\kmdfTest"//符号连接，这样用户模式下的程序可以使用这个驱动设备。

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
//声明回调
EVT_WDF_DRIVER_UNLOAD kmdf_unload;
EVT_WDF_DEVICE_FILE_CREATE kmdf_create;
EVT_WDF_FILE_CLOSE kmdf_close;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL kmdf_ioctl;
EVT_WDF_OBJECT_CONTEXT_DESTROY kmdf_destroy;
EVT_WDF_IO_IN_CALLER_CONTEXT kmdf_caller_context;

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	KdPrint(("[MyWDFDevice]DriverEntry [start]\n"));

	//驱动对象相关
	WDF_DRIVER_CONFIG cfg;//驱动的配置
	WDFDRIVER drv;//wdf framework 驱动对象

	//设备对象相关
	PWDFDEVICE_INIT device_init;
	UNICODE_STRING ustring;
	WDF_FILEOBJECT_CONFIG f_cfg;
	WDFDEVICE control_device;
	WDF_OBJECT_ATTRIBUTES obj_attrs;

	//IO QUEUE相关
	WDF_IO_QUEUE_CONFIG qcfg;
	WDFQUEUE queue;
	//初始化WDF_DRIVER_CONFIG
	WDF_DRIVER_CONFIG_INIT(
		&cfg,
		WDF_NO_EVENT_CALLBACK //不提供AddDevice函数
	);
	cfg.DriverInitFlags |= WdfDriverInitNonPnpDriver;  //指定非pnp驱动
	cfg.EvtDriverUnload = kmdf_unload;  //指定卸载函数
	//创建一个framework驱动对象，在WDF程序里面，WdfDriverCreate是必须要调用的。
	//framework驱动对象是其他所有wdf对象的父对象，换句话说framework驱动对象是wdf对象树的顶点，它没有父对象了。
	status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &cfg, &drv);
	if (!NT_SUCCESS(status))
	{
		goto DriverEntry_Complete;
	}

	KdPrint(("[MyWDFDevice]Create wdf driver object successfully\n"));
	//创建一个设备
	//先要分配一块内存WDFDEVICE_INIT,这块内存在创建设备的时候会用到。
	device_init = WdfControlDeviceInitAllocate(drv, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
	if (device_init == NULL)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto DriverEntry_Complete;
	}
	//WdfDeviceInitSetDeviceType(device_init, FILE_DEVICE_DEVAPI);
	WdfDeviceInitSetIoType(device_init, WdfDeviceIoDirect);

	//创建设备的名字，内核模式下，名字类似: L"\\Device\\MyWDF_Device"
	RtlInitUnicodeString(&ustring, MYWDF_KDEVICE);
	//将设备名字存入device_init中
	status = WdfDeviceInitAssignName(device_init, &ustring);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[MyWDFDevice]WdfDeviceInitAssignName status:(%x)\n", status));
		WdfDeviceInitFree(device_init);
		goto DriverEntry_Complete;
	}
	KdPrint(("[MyWDFDevice]Device name Unicode string: %wZ (this name can only be used by other kernel mode code, like other drivers)\n", &ustring));

	//配置FILEOBJECT配置文件，设置FILECREATE,FILECLOSE回调。
	WDF_FILEOBJECT_CONFIG_INIT(&f_cfg, kmdf_create, kmdf_close, NULL);
	//在设备属性里面增加一个DEVICE_CONTEXT,跟WDF_OBJECT_ATTRIBUTES_INIT相比，WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE
	//会分配一块内存并且存入WDF_OBJECT_ATTRIBUTES里面 (object_attribs.ContextTypeInfo)。DEVICE_CONEXT是个自定义结构。
	WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&obj_attrs, DEVICE_CONTEXT);
	obj_attrs.ExecutionLevel = WdfExecutionLevelPassive;
	obj_attrs.SynchronizationScope = WdfSynchronizationScopeNone;
	obj_attrs.EvtDestroyCallback = kmdf_destroy;

	//将FILEOBJECT的设置存入device_init中
	WdfDeviceInitSetFileObjectConfig(device_init, &f_cfg, &obj_attrs);
	WdfDeviceInitSetIoInCallerContextCallback(device_init, kmdf_caller_context);

	//初始化设备属性
	WDF_OBJECT_ATTRIBUTES_INIT(&obj_attrs);
	//根据前面创建的device_init来创建一个设备. (control device)
	status = WdfDeviceCreate(&device_init, &obj_attrs, &control_device);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[MyWDFDevice]create device failed\n"));
		goto DriverEntry_Complete;
	}
	//创建IO queue
	//初始化IO QUEUE CONFIG, WdfIoQueueDispatchParallel意思是
	//The framework presents requests to the driver's request handlers as soon as the requests are available. 
	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&qcfg, WdfIoQueueDispatchParallel);
	qcfg.EvtIoRead = NULL;
	qcfg.EvtIoWrite = NULL;
	qcfg.EvtIoDeviceControl = kmdf_ioctl;

	//给设备control_device创建IO QUEUE
	WDF_OBJECT_ATTRIBUTES_INIT(&obj_attrs);
	obj_attrs.ExecutionLevel = WdfExecutionLevelPassive;
	obj_attrs.SynchronizationScope = WdfSynchronizationScopeNone;
	status = WdfIoQueueCreate(control_device, &qcfg, &obj_attrs, &queue);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[MyWDFDevice]Create IoQueue failed, %x\n", status));
		goto DriverEntry_Complete;
	}
	//创建符号连接，这样用户模式下的程序可以使用这个驱动。这个是必须的，不然用户模式下的程序不能访问这个设备。
	RtlInitUnicodeString(&ustring, MYWDF_LINKNAME);
	status = WdfDeviceCreateSymbolicLink(control_device, &ustring);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[MyWDFDevice]Failed to create Link\n"));
		goto DriverEntry_Complete;
	}

	KdPrint(("[MyWDFDevice]Create symbolic link successfully, %wZ (user mode code should use this name, like in CreateFile())\n", &ustring));

	WdfControlFinishInitializing(control_device);//创建设备完成。
	/*******************************************
	到这里，我们就成功创建了一个control device。
	control device 是不支持png和power的，而且我们也不需要手工是删除。
	因为framework会帮我们删除，看MSDN

	If your driver creates control device objects but does not create framework device objects that support PnP and power management,
	the driver does not have to delete the control device objects.

	In this case, the framework deletes the control device objects after the driver's EvtDriverUnload callback function returns.

	更多细节看MSDN,如
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
	//得到设备的上下文
	PDEVICE_CONTEXT context = kmdf_context_get(object);
	if (context)
	{
		RtlZeroMemory(context, sizeof(DEVICE_CONTEXT));
		KdPrint(("[MyWDFDevice] 得到设备的上下文"));
	}
	else
	{
		KdPrint(("[MyWDFDevice] 获取上下文失败"));
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
