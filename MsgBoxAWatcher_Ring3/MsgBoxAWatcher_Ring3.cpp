// MsgBoxAWatcher_Ring3.cpp : �������̨Ӧ�ó������ڵ㡣
//
//1���Լ�д������أ�ж����������
//2����ҳ��֪ʶ����д����
//3��дHOOK
//4��shellcode


#include "stdafx.h"
#include <Windows.h>

#define DRIVER_NAME L"MsgBoxAWatcher_Ring0"
#define DRIVER_PATH L"MsgBoxAWatcher_Ring0.sys"
#define DRIVER_LINK L"\\\\.\\MsgBoxAWatcherDriverLnk"

#define OPER_CALL_GATE_R0 CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define OPER_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define OPER_GET_APICALLRECORD CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_BUFFERED,FILE_ANY_ACCESS)

// API���ü�¼����
typedef struct _APICALLRECORD
{
	LIST_ENTRY ApiCallRecordList; // ����
	UINT32 pApiAddress; // API������ַ
	UINT32 nParam; // ��������
	UINT32 Param[32]; // �����б�
} APICALLRECORD, *PAPICALLRECORD;

BOOL LoadDriver(PCWSTR lpszDriverName, PCWSTR lpszDriverPath);
void UnLoadDriver(PCWSTR lpszDriverName);
DWORD *GetPDE(DWORD addr);
DWORD *GetPTE(DWORD addr);
USHORT CreateCallGate(DWORD pBaseAddress, DWORD nParam);
BOOL CallInRing0(PVOID pFuncion, PDWORD pParam, DWORD nParam);
void BypassApiWriteCopyNaked();
void BypassApiWriteCopy();
BOOL HookUser32Api();
void UpdateApiCallRecord();

int _tmain(int argc, _TCHAR* argv[])
{	
	// ��������
	if (!LoadDriver(DRIVER_NAME, DRIVER_PATH))
	{
		printf("�����������ʧ��.\n");
		getchar();
		return 1;
	}
	else
	{
		printf("����������سɹ�.\n");
	}

	// ��д����
	BypassApiWriteCopy();

	// HOOK MessageBoxA
	if (HookUser32Api())
	{
		printf("HOOK MessageBoxA �ɹ������ڿ������������������ MessageBoxA.\n");		
	}
	else
	{
		printf("HOOK MessageBoxA ʧ��.\n");
	}
	// ��ȡ���ü�¼
	UpdateApiCallRecord();

	// ȡ��HOOK
	((PUSHORT)MessageBoxA)[0] = 0xff8b;
	UnLoadDriver(DRIVER_NAME);
	printf("�����ⰴ���˳�����.\n");
	getchar();
	return 0;
}

// ��������
BOOL LoadDriver(PCWSTR lpszDriverName, PCWSTR lpszDriverPath)
{
	// ��ȡ��������·��
	WCHAR szDriverFullPath[MAX_PATH] = { 0 };
	GetFullPathNameW(lpszDriverPath,MAX_PATH,szDriverFullPath,NULL);
	//printf("%s\n", szDriverFullPath);
	// �򿪷�����ƹ�����
	SC_HANDLE hServiceMgr = NULL; // SCM���������	
	hServiceMgr = OpenSCManagerW(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	if (NULL == hServiceMgr)
	{
		printf("OpenSCManagerW ʧ��, %d\n", GetLastError());
		return FALSE;
	}
	//printf("�򿪷�����ƹ������ɹ�.\n");
	// ������������
	SC_HANDLE hServiceDDK = NULL; // NT�������������
	hServiceDDK = CreateServiceW(
		hServiceMgr,
		lpszDriverName,
		lpszDriverName,
		SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_IGNORE,
		szDriverFullPath,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL);
	if (NULL == hServiceDDK)
	{
		DWORD dwErr = GetLastError();
		if (dwErr != ERROR_IO_PENDING && dwErr != ERROR_SERVICE_EXISTS)
		{
			printf("������������ʧ��, %d\n", dwErr);
			return FALSE;
		}
	}
	//printf("������������ɹ�.\n");
	// ���������Ѿ��������򿪷���
	hServiceDDK = OpenServiceW(hServiceMgr,lpszDriverName,SERVICE_ALL_ACCESS);
	if (!StartService(hServiceDDK, NULL, NULL))
	{
		DWORD dwErr = GetLastError();
		if (dwErr != ERROR_SERVICE_ALREADY_RUNNING)
		{
			printf("������������ʧ��, %d\n", dwErr);
			return FALSE;
		}
	}
	//printf("������������ɹ�.\n");
	if (hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if (hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
	return TRUE;
}

// ж������
void UnLoadDriver(PCWSTR lpszDriverName)
{
	SC_HANDLE hServiceMgr = OpenSCManagerW(0,0,SC_MANAGER_ALL_ACCESS);
	SC_HANDLE hServiceDDK = OpenServiceW(hServiceMgr,lpszDriverName,SERVICE_ALL_ACCESS);
	SERVICE_STATUS SvrStatus;
	ControlService(hServiceDDK,SERVICE_CONTROL_STOP,&SvrStatus);
	DeleteService(hServiceDDK);
	if (hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if (hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
}

// ��ȡPDE
DWORD *GetPDE(DWORD addr)
{
	return (DWORD *)(0xc0600000 + ((addr >> 18) & 0x3ff8));
}

// ��ȡPTE
DWORD *GetPTE(DWORD addr)
{
	return (DWORD *)(0xc0000000 + ((addr >> 9) & 0x7ffff8));
}

// ���������ţ���Ȩ���вΣ�
USHORT CreateCallGate(DWORD pBaseAddress, DWORD nParam)
{
	HANDLE hDevice = CreateFileW(DRIVER_LINK,GENERIC_READ|GENERIC_WRITE,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		return 0;
	}
	USHORT CallGateDescriptor; // ������ѡ����
	DWORD dwRetBytes; // ���ص��ֽ���
	DWORD InBuffer[2];
	InBuffer[0] = pBaseAddress;
	InBuffer[1] = nParam;
	DeviceIoControl(hDevice,OPER_CALL_GATE_R0,InBuffer,8,&CallGateDescriptor,sizeof(USHORT),&dwRetBytes,NULL);
	if (dwRetBytes != 2 || CallGateDescriptor == 0)
	{
		printf("���������ʧ��.\n");
		return 0;
	}
	CloseHandle(hDevice);
	return CallGateDescriptor;
}

// ��0��Ȩ�޵���ĳ���㺯����֧�ִ���
BOOL CallInRing0(PVOID pFuncion, PDWORD pParam, DWORD nParam)
{
	// ������������������
	USHORT CallGateDescriptor = CreateCallGate((DWORD)pFuncion,nParam);
	if (CallGateDescriptor == 0)
	{
		return FALSE;
	}
	// ���������������
	USHORT buff[3] = {0};
	buff[2] = CallGateDescriptor;
	// ����ѹջ
	if (nParam && pParam)
	{
		for (DWORD i = 0; i < nParam; i++)
		{
			__asm
			{
				mov eax,pParam;
				push [eax];
			}
			pParam++;
		}
	}	
	// �����ŵ���
	__asm call fword ptr [buff]; // �����ã�ʹ�õ�������Ȩ
	return TRUE;
}

// API������д��������ʵ���ǽ��������Ե�ַ��PDE��PTE�ĳɿ�д
// ����0��Ҫ��д�����ĺ�����ַ
// ����1��PDE���Ե�ַ
// ����2��PTE���Ե�ַ
void __declspec(naked) BypassApiWriteCopyNaked()
{
	__asm
	{
		pushad;
		pushfd;
	}
	__asm
	{		
		// R/W = 1, U/S = 1
		mov eax,[esp+0x24+0x8+0x0]; // ����2��PTE�ĵ�ַ
		or dword ptr [eax],0x00000006;
		mov eax,[esp+0x24+0x8+0x4]; // ����1��PDE�ĵ�ַ
		or dword ptr [eax],0x00000006;
		mov eax,[esp+0x24+0x8+0x8]; // ����0��Ҫ��д�����ĺ�����ַ
		invlpg [eax]; // ���TLB����
	}
	__asm
	{
		popfd;
		popad;
		retf 0xC;
	}
}

// ��д����
void BypassApiWriteCopy()
{
	// MessageBoxA ������ҳ��������������MessageBoxA��PTE��������Ч��
	__asm
	{
		mov eax, dword ptr ds:[MessageBoxA];
		mov eax,[eax];
	}
	// MessageBoxA��д����	
	DWORD pParam[3];
	pParam[0] = (DWORD)MessageBoxA;
	pParam[1] = (DWORD)GetPDE(pParam[0]);
	pParam[2] = (DWORD)GetPTE(pParam[0]);
	CallInRing0(BypassApiWriteCopyNaked, pParam,3);
}

// HOOK MessageBoxA
// �����Ͽ��� HOOK User32.dll ������⺯��
BOOL HookUser32Api()
{
	HANDLE hDevice = CreateFileW(DRIVER_LINK,GENERIC_READ|GENERIC_WRITE,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("���豸ʧ��.\n");
		return FALSE;
	}
	USHORT IntGateNum; // �жϺ�
	DWORD dwRetBytes; // ���ص��ֽ���

	DeviceIoControl(hDevice,OPER_HOOK,NULL,0,&IntGateNum,sizeof(USHORT),&dwRetBytes,NULL);
	if (dwRetBytes != 2 || IntGateNum == 0)
	{
		printf("�����ж���ʧ��.\n");
		return FALSE;
	}
	CloseHandle(hDevice);

	// HOOK MessageBoxA
	USHORT IntInstructions = (IntGateNum << 8);
	IntInstructions |= (USHORT)0x00CD;	
	*(PUSHORT)MessageBoxA = IntInstructions;

	return TRUE;
}

// ��������ȡ���ü�¼
void UpdateApiCallRecord()
{
	HANDLE hDevice = CreateFileW(DRIVER_LINK,GENERIC_READ|GENERIC_WRITE,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("���豸ʧ��.\n");
		return;
	}
	APICALLRECORD ApiCallRecord;
	DWORD dwRetBytes; // ���ص��ֽ���
	while (!GetAsyncKeyState('Q'))
	{
		Sleep(50);
		DeviceIoControl(hDevice,OPER_GET_APICALLRECORD,NULL,0,&ApiCallRecord,sizeof(ApiCallRecord),&dwRetBytes,NULL);
		if (dwRetBytes == 0) 
		{
			//printf("��API���ü�¼.\n");
			continue;
		}
		if (ApiCallRecord.pApiAddress == (DWORD)MessageBoxA)
		{
			printf("MessageBoxA(%x, %x, %x, %x);\n", \
				ApiCallRecord.Param[0],ApiCallRecord.Param[1],ApiCallRecord.Param[2],ApiCallRecord.Param[3]);
		}
	}
	CloseHandle(hDevice);
}


