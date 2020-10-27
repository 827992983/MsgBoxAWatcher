#include <ntifs.h>
#include <wdm.h>

#define DEVICE_NAME L"\\Device\\MsgBoxAWatcherDriverDev"
#define DRIVER_LINK L"\\??\\MsgBoxAWatcherDriverLnk"

// ������4KB�豸��չ�ڴ棬�������ȫ�ֱ���
// 0-3�ֽڣ���������������ַ��GDT��
// 4-7�ֽڣ��ж�����������ַ��IDT��
#define DeviceExtendSize 0x1000

// 3���� IRP_MJ_DEVICE_CONTROL �Ĳ������
#define OPER_CALL_GATE_R0 CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define OPER_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define OPER_GET_APICALLRECORD CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_BUFFERED,FILE_ANY_ACCESS)


// �ṹ����
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	UINT32 SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	UINT32 Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	UINT32 CheckSum;
	UINT32 TimeDateStamp;
	PVOID LoadedImports;
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// API���ü�¼
typedef struct _APICALLRECORD
{
	LIST_ENTRY ApiCallRecordList; // ����
	UINT32 pApiAddress; // API������ַ
	UINT32 nParam; // ��������
	UINT32 Param[32]; // �����б�
} APICALLRECORD, *PAPICALLRECORD;

// ȫ�ֱ���
PDEVICE_OBJECT g_pDevObj = NULL; // �Զ����豸�����ں�3��ͨ��
APICALLRECORD g_ApiCallRecordQueue = { 0 }; // API���ü�¼���У���Ҫֱ�Ӳ���������ʹ�ó����ṩ��API

// ��������
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING RegPath);
VOID DriverUnload(PDRIVER_OBJECT pDriver);
NTSTATUS IrpCreateProc(PDEVICE_OBJECT pDevObj, PIRP pIrp);
NTSTATUS IrpCloseProc(PDEVICE_OBJECT pDevObj, PIRP pIrp);
NTSTATUS IrpDeviceControlProc(PDEVICE_OBJECT pDevObj, PIRP pIrp);
UINT32 *GetPDE(UINT32 addr);
UINT32 *GetPTE(UINT32 addr);
USHORT SetCallGate(UINT32 pFunction, UINT32 nParam);
USHORT SetIntGate(UINT32 pFuncion);
void User32ApiSpyNaked();
void __stdcall User32ApiSpy(UINT32 ESP3, UINT32 EIP3);
void InitApiCallQueue(IN PAPICALLRECORD QueueHead);
void PushApiCallQueue(IN PAPICALLRECORD QueueHead, IN PAPICALLRECORD pApiCallRecord);
void PopApiCallQueue(IN PAPICALLRECORD QueueHead, OUT PAPICALLRECORD * pApiCallRecord);
UINT32 GetCountApiCallQueue(IN PAPICALLRECORD QueueHead);
void FreeApiCallQueue(IN PAPICALLRECORD QueueHead);

// ��ں���
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING RegPath){
	NTSTATUS status;
	ULONG uIndex = 0;
	PDEVICE_OBJECT pDeviceObj = NULL; // �豸����ָ��
	UNICODE_STRING DeviceName; // �豸����0����
	UNICODE_STRING SymbolicLinkName; // ������������3����

	// ��ʼ�����ü�¼����
	InitApiCallQueue(&g_ApiCallRecordQueue);

	// �����豸����
	RtlInitUnicodeString(&DeviceName,DEVICE_NAME);
	// �����豸	
	status = IoCreateDevice(pDriver,DeviceExtendSize,&DeviceName,FILE_DEVICE_UNKNOWN,FILE_DEVICE_SECURE_OPEN,FALSE,&pDeviceObj);
	if (status != STATUS_SUCCESS)
	{
		IoDeleteDevice(pDeviceObj);
		DbgPrint("�����豸ʧ��.\n");
		return status;
	}
	// ȫ�ֱ����������豸��չ�ڴ�
	// ��ʼ��ȫ���豸ָ��
	g_pDevObj = pDeviceObj;	
	// ��ʼ���豸��չ����
	memset(pDeviceObj->DeviceExtension,0,DeviceExtendSize);
	//DbgPrint("�����豸�ɹ�.\n");
	// ���ý������ݵķ�ʽ
	pDeviceObj->Flags |= DO_BUFFERED_IO;
	// ������������
	RtlInitUnicodeString(&SymbolicLinkName, DRIVER_LINK);
	IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);
	// ���÷ַ�����
	pDriver->MajorFunction[IRP_MJ_CREATE] = IrpCreateProc;
	pDriver->MajorFunction[IRP_MJ_CLOSE] = IrpCloseProc;
	pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceControlProc;

	// ����ж�غ���
	pDriver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}

// ж������
VOID DriverUnload(PDRIVER_OBJECT pDriver)
{
	UNICODE_STRING SymbolicLinkName;
	// ɾ��GDT�����еĵ�����
	memset((PVOID)((PUINT32)(pDriver->DeviceObject->DeviceExtension))[0],0,8);
	// ɾ��IDT���е��ж���
	memset((PVOID)(((PUINT32)(pDriver->DeviceObject->DeviceExtension))[1]),0,8);
	// �ͷŶ����ڴ�
	//DbgPrint("���г��ȣ�%d\n", GetCountApiCallQueue(&g_ApiCallRecordQueue));
	FreeApiCallQueue(&g_ApiCallRecordQueue);
	//DbgPrint("���г��ȣ�%d\n", GetCountApiCallQueue(&g_ApiCallRecordQueue));
	// ɾ���������ӣ�ɾ���豸
	RtlInitUnicodeString(&SymbolicLinkName, DRIVER_LINK);
	IoDeleteSymbolicLink(&SymbolicLinkName);
	IoDeleteDevice(pDriver->DeviceObject);
	DbgPrint("����ж�سɹ�\n");
}

// �����������������Ring3����CreateFile�᷵��1
// IRP_MJ_CREATE ������
NTSTATUS IrpCreateProc(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	//DbgPrint("Ӧ�ò������豸.\n");
	// ����״̬��������ã�Ring3����ֵ��ʧ��
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// IRP_MJ_CLOSE ������
NTSTATUS IrpCloseProc(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	//DbgPrint("Ӧ�ò�Ͽ������豸.\n");
	// ����״̬��������ã�Ring3����ֵ��ʧ��
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// IRP_MJ_DEVICE_CONTROL ������
NTSTATUS IrpDeviceControlProc(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	PIO_STACK_LOCATION pIrpStack;
	ULONG uIoControlCode;
	PVOID pIoBuffer;
	ULONG uInLength;
	ULONG uOutLength;

	// ��ȡIRP����
	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	// ��ȡ������
	uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	// ��ȡ��������ַ�����������ͬһ����
	pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
	// Ring3 �������ݵĳ���
	uInLength = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	// Ring0 �������ݵĳ���
	uOutLength = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	switch (uIoControlCode)
	{
	case OPER_CALL_GATE_R0:
		{
			UINT32 pFunction; // 3������ָ��
			UINT32 nParam; // ��������
			// ��3���������ĺ���ָ������һ��������
			pFunction = ((PUINT32)pIoBuffer)[0];
			nParam = ((PUINT32)pIoBuffer)[1];
			// ����״̬����������
			((PUSHORT)pIoBuffer)[0] = SetCallGate(pFunction, nParam); // ���ص�����ѡ����
			pIrp->IoStatus.Information = 2; // ���ظ�3����������
			status = STATUS_SUCCESS;
			break;
		}
	case OPER_HOOK:
		{
			// ���ظ�3�����жϺţ�3�������жϺ�HOOK API
			USHORT IntGateNum;
			// ������Ȩ�ж���
			IntGateNum = SetIntGate((UINT32)User32ApiSpyNaked);
			// �����жϺ�
			*(PUSHORT)pIoBuffer = IntGateNum;
			// ����״̬����������
			pIrp->IoStatus.Information = 2; // ���ظ�3����������
			status = STATUS_SUCCESS;
			break;
		}
	case OPER_GET_APICALLRECORD:
		{
			PAPICALLRECORD record = NULL;
			PopApiCallQueue(&g_ApiCallRecordQueue, &record);
			if (record == NULL)
			{
				// ����״̬����������
				pIrp->IoStatus.Information = 0; // ���ظ�3����������
				status = STATUS_SUCCESS;
			}
			else
			{
				memcpy(pIoBuffer, record, sizeof(APICALLRECORD));
				// ����״̬����������
				pIrp->IoStatus.Information = sizeof(APICALLRECORD); // ���ظ�3����������
				status = STATUS_SUCCESS;
			}
			break;
		}
	}

	// ����״̬��������ã�Ring3����ֵ��ʧ��
	pIrp->IoStatus.Status = status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// ������Ȩ�ж��ţ������жϺ�
USHORT SetIntGate(UINT32 pFuncion)
{	
	UCHAR IDT[6]; // IDT�Ĵ���
	UINT32 IdtAddr,IdtLen;
	UINT32 IntGateHi = 0,IntGateLo = 0; // �ж���������
	UINT32 *pPreIntGateAddr = (UINT32*)g_pDevObj->DeviceExtension + 1;
	UINT32 i;
	// �����ж���������
	IntGateLo = ((pFuncion & 0x0000FFFF) | 0x00080000);
	IntGateHi = ((pFuncion & 0xFFFF0000) | 0x0000EE00);
	// ����IDT������Ч��
	__asm
	{
		sidt fword ptr IDT;
	}
	IdtAddr = *(PULONG)(IDT+2);
	IdtLen = *(PUSHORT)IDT;
	// ����IDT����һ��P=0�ģ�������һ�
	if ((*pPreIntGateAddr) == 0)
	{				
		for (i = 8; i < IdtLen; i+=8)
		{
			if ((((PUINT32)(IdtAddr + i))[1] & 0x00008000) == 0)
			{
				// P=0���˴�GDT������Ч������ʹ��
				((PUINT32)(IdtAddr + i))[0] = IntGateLo;
				((PUINT32)(IdtAddr + i))[1] = IntGateHi;
				(*pPreIntGateAddr) = IdtAddr + i;				
				break;
			}
		}
	}
	else
	{
		((PUINT32)(*pPreIntGateAddr))[0] = IntGateLo;
		((PUINT32)(*pPreIntGateAddr))[1] = IntGateHi;
	}

	//DbgPrint("*pPreIntGateAddr: %p.\n", *pPreIntGateAddr);
	//DbgPrint("INT %02X\n", (USHORT)((*pPreIntGateAddr - IdtAddr) / 8));
	if (*pPreIntGateAddr == 0) return 0;
	return (USHORT)((*pPreIntGateAddr - IdtAddr) / 8);
}

// ������Ȩ�����ţ����ص�����ѡ����
USHORT SetCallGate(UINT32 pFunction, UINT32 nParam)
{	
	UINT32 CallGateHi = 0,CallGateLo = 0; // ������������
	UCHAR GDT[6]; // GDT�Ĵ���
	UINT32 GdtAddr,GdtLen;
	UINT32 i;
	UINT32 *pPreCallGateAddr = (UINT32*)g_pDevObj->DeviceExtension;

	// ���������
	CallGateHi = (pFunction & 0xFFFF0000);
	CallGateHi |= 0x0000EC00;
	CallGateHi |= nParam;
	CallGateLo = (pFunction & 0x0000FFFF);
	CallGateLo |= 0x00080000;
	// ��ȡGDT��ַ�ʹ�С
	__asm
	{
		sgdt fword ptr GDT;
	}
	GdtAddr = *(PULONG)(GDT+2);
	GdtLen = *(PUSHORT)GDT;
	// ����GDT����һ��P=0�ģ�������һ�
	if ((*pPreCallGateAddr) == 0)
	{				
		for (i = 8; i < GdtLen; i+=8)
		{
			//DbgPrint("%p\n",(PUINT32)(GdtAddr + i));
			if ((((PUINT32)(GdtAddr + i))[1] & 0x00008000) == 0)
			{
				// P=0���˴�GDT������Ч������ʹ��
				((PUINT32)(GdtAddr + i))[0] = CallGateLo;
				((PUINT32)(GdtAddr + i))[1] = CallGateHi;
				(*pPreCallGateAddr) = GdtAddr + i;
				break;
			}
		}
	}
	else
	{
		((PUINT32)(*pPreCallGateAddr))[0] = CallGateLo;
		((PUINT32)(*pPreCallGateAddr))[1] = CallGateHi;
	}
	if (*pPreCallGateAddr == 0) return 0;
	return (USHORT)((*pPreCallGateAddr) - GdtAddr);
}

// ��ȡPDE
UINT32 *GetPDE(UINT32 addr)
{
	return (UINT32 *)(0xc0600000 + ((addr >> 18) & 0x3ff8));
}

// ��ȡPTE
UINT32 *GetPTE(UINT32 addr)
{
	return (UINT32 *)(0xc0000000 + ((addr >> 9) & 0x7ffff8));
}

// User32.dll ���������Ĺ��Ӻ���
// ���÷�ʽ���޸�API����ͷ2�ֽڣ�ʹAPI���������жϣ�ͨ����Ȩ�ж��ŵ��ñ�����
void __declspec(naked) User32ApiSpyNaked()
{
	__asm
	{
		pushad; // esp - 0x20
		pushfd; // esp - 0x04

		mov eax,[esp + 0x24];		
		mov ecx,[esp + 0x24 + 0x0C];
		push eax; // EIP3
		push ecx; // ESP3
		call User32ApiSpy;

		popfd;
		popad;
		iretd;
	}
}

// �˴���Ҫ��ɵĹ�������ȡ3��EIP���ж�API��Դ����ȡ3��ESP����ȡ����������3�����Ƴ���
void __stdcall User32ApiSpy(UINT32 ESP3, UINT32 EIP3)
{
	UINT32 ApiAddress;
	// EIP3-0x02��API�ĵ�ַ
	// ESP3��3����ESP����������������
	__asm push fs;
	ApiAddress = EIP3 - 2;
	//DbgPrint("ESP3: %08x, API: %08x\n", ESP3, ApiAddress);
	// �ж�API��ַ
	if (ApiAddress == 0x77d507ea)
	{
		PAPICALLRECORD pApiCallRecord = NULL;
		// ��ӵ��ü�¼�����У����ӽ���ͨ��IRP��Ϣ��ȡ����
		pApiCallRecord = (PAPICALLRECORD)ExAllocatePool(PagedPool,sizeof(APICALLRECORD));
		pApiCallRecord->nParam = 4;
		pApiCallRecord->pApiAddress = ApiAddress;
		pApiCallRecord->Param[0] = ((PUINT32)ESP3)[1];
		pApiCallRecord->Param[1] = ((PUINT32)ESP3)[2];
		pApiCallRecord->Param[2] = ((PUINT32)ESP3)[3];
		pApiCallRecord->Param[3] = ((PUINT32)ESP3)[4];
		PushApiCallQueue(&g_ApiCallRecordQueue, (PAPICALLRECORD)pApiCallRecord);
	}
	__asm pop fs;
}

// ��ʼ������
void InitApiCallQueue(IN PAPICALLRECORD QueueHead)
{
	QueueHead->ApiCallRecordList.Flink = QueueHead->ApiCallRecordList.Blink = (PLIST_ENTRY)QueueHead;
}

// ����һ�����ü�¼����β
void PushApiCallQueue(IN PAPICALLRECORD QueueHead, IN PAPICALLRECORD pApiCallRecord)
{
	// ԭ��β����һ���ڵ�ָ���¶�β
	QueueHead->ApiCallRecordList.Blink->Flink = (PLIST_ENTRY)pApiCallRecord;
	// �¶�β����һ���ڵ�ָ��ԭ��β
	pApiCallRecord->ApiCallRecordList.Blink = QueueHead->ApiCallRecordList.Blink;
	// �¶�β����һ���ڵ�ָ�����ͷ
	pApiCallRecord->ApiCallRecordList.Flink = (PLIST_ENTRY)QueueHead;
	// ����ͷ����һ���ڵ�ָ���¶�β
	QueueHead->ApiCallRecordList.Blink = (PLIST_ENTRY)pApiCallRecord;	
}

// �Ӷ��׵���һ�����ü�¼
void PopApiCallQueue(IN PAPICALLRECORD QueueHead, OUT PAPICALLRECORD * pApiCallRecord)
{
	// ��¼Ҫ�����Ľڵ�
	*pApiCallRecord = (PAPICALLRECORD)(QueueHead->ApiCallRecordList.Flink);
	// �������Ϊ�գ�����NULL
	if (*pApiCallRecord == &g_ApiCallRecordQueue)
	{
		*pApiCallRecord = NULL;
	}
	// �ڶ����ڵ����һ���ڵ�ָ�����
	QueueHead->ApiCallRecordList.Flink->Flink->Blink = (PLIST_ENTRY)QueueHead;
	// ���׵���һ���ڵ�ָ��ڶ����ڵ�
	QueueHead->ApiCallRecordList.Flink = QueueHead->ApiCallRecordList.Flink->Flink;
}

// ������г���
UINT32 GetCountApiCallQueue(IN PAPICALLRECORD QueueHead)
{
	UINT32 cnt = 0;
	PLIST_ENTRY pList = QueueHead->ApiCallRecordList.Flink;
	while (pList != (PLIST_ENTRY)QueueHead)
	{
		pList = pList->Flink;
		cnt++;
	}
	return cnt;
}

// �ͷŶ����ڴ�
void FreeApiCallQueue(IN PAPICALLRECORD QueueHead)
{
	PAPICALLRECORD pApiCallRecord;
	while(QueueHead->ApiCallRecordList.Flink != (PLIST_ENTRY)QueueHead)
	{		
		PopApiCallQueue(QueueHead, &pApiCallRecord);
		ExFreePool(pApiCallRecord);
	}
}


