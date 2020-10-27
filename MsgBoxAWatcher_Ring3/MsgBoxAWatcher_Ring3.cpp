// MsgBoxAWatcher_Ring3.cpp : 定义控制台应用程序的入口点。
//
//1、自己写代码加载，卸载驱动程序
//2、段页的知识；绕写拷贝
//3、写HOOK
//4、shellcode


#include "stdafx.h"
#include <Windows.h>

#define DRIVER_NAME L"MsgBoxAWatcher_Ring0"
#define DRIVER_PATH L"MsgBoxAWatcher_Ring0.sys"
#define DRIVER_LINK L"\\\\.\\MsgBoxAWatcherDriverLnk"

#define OPER_CALL_GATE_R0 CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define OPER_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define OPER_GET_APICALLRECORD CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_BUFFERED,FILE_ANY_ACCESS)

// API调用记录父类
typedef struct _APICALLRECORD
{
	LIST_ENTRY ApiCallRecordList; // 链表
	UINT32 pApiAddress; // API函数地址
	UINT32 nParam; // 参数个数
	UINT32 Param[32]; // 参数列表
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
	// 加载驱动
	if (!LoadDriver(DRIVER_NAME, DRIVER_PATH))
	{
		printf("驱动服务加载失败.\n");
		getchar();
		return 1;
	}
	else
	{
		printf("驱动服务加载成功.\n");
	}

	// 过写拷贝
	BypassApiWriteCopy();

	// HOOK MessageBoxA
	if (HookUser32Api())
	{
		printf("HOOK MessageBoxA 成功，现在可以在其他程序里调用 MessageBoxA.\n");		
	}
	else
	{
		printf("HOOK MessageBoxA 失败.\n");
	}
	// 读取调用记录
	UpdateApiCallRecord();

	// 取消HOOK
	((PUSHORT)MessageBoxA)[0] = 0xff8b;
	UnLoadDriver(DRIVER_NAME);
	printf("敲任意按键退出程序.\n");
	getchar();
	return 0;
}

// 加载驱动
BOOL LoadDriver(PCWSTR lpszDriverName, PCWSTR lpszDriverPath)
{
	// 获取驱动完整路径
	WCHAR szDriverFullPath[MAX_PATH] = { 0 };
	GetFullPathNameW(lpszDriverPath,MAX_PATH,szDriverFullPath,NULL);
	//printf("%s\n", szDriverFullPath);
	// 打开服务控制管理器
	SC_HANDLE hServiceMgr = NULL; // SCM管理器句柄	
	hServiceMgr = OpenSCManagerW(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	if (NULL == hServiceMgr)
	{
		printf("OpenSCManagerW 失败, %d\n", GetLastError());
		return FALSE;
	}
	//printf("打开服务控制管理器成功.\n");
	// 创建驱动服务
	SC_HANDLE hServiceDDK = NULL; // NT驱动程序服务句柄
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
			printf("创建驱动服务失败, %d\n", dwErr);
			return FALSE;
		}
	}
	//printf("创建驱动服务成功.\n");
	// 驱动服务已经创建，打开服务
	hServiceDDK = OpenServiceW(hServiceMgr,lpszDriverName,SERVICE_ALL_ACCESS);
	if (!StartService(hServiceDDK, NULL, NULL))
	{
		DWORD dwErr = GetLastError();
		if (dwErr != ERROR_SERVICE_ALREADY_RUNNING)
		{
			printf("运行驱动服务失败, %d\n", dwErr);
			return FALSE;
		}
	}
	//printf("运行驱动服务成功.\n");
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

// 卸载驱动
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

// 获取PDE
DWORD *GetPDE(DWORD addr)
{
	return (DWORD *)(0xc0600000 + ((addr >> 18) & 0x3ff8));
}

// 获取PTE
DWORD *GetPTE(DWORD addr)
{
	return (DWORD *)(0xc0000000 + ((addr >> 9) & 0x7ffff8));
}

// 构建调用门（提权、有参）
USHORT CreateCallGate(DWORD pBaseAddress, DWORD nParam)
{
	HANDLE hDevice = CreateFileW(DRIVER_LINK,GENERIC_READ|GENERIC_WRITE,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		return 0;
	}
	USHORT CallGateDescriptor; // 调用门选择子
	DWORD dwRetBytes; // 返回的字节数
	DWORD InBuffer[2];
	InBuffer[0] = pBaseAddress;
	InBuffer[1] = nParam;
	DeviceIoControl(hDevice,OPER_CALL_GATE_R0,InBuffer,8,&CallGateDescriptor,sizeof(USHORT),&dwRetBytes,NULL);
	if (dwRetBytes != 2 || CallGateDescriptor == 0)
	{
		printf("构造调用门失败.\n");
		return 0;
	}
	CloseHandle(hDevice);
	return CallGateDescriptor;
}

// 以0环权限调用某个裸函数，支持传参
BOOL CallInRing0(PVOID pFuncion, PDWORD pParam, DWORD nParam)
{
	// 命令驱动构建调用门
	USHORT CallGateDescriptor = CreateCallGate((DWORD)pFuncion,nParam);
	if (CallGateDescriptor == 0)
	{
		return FALSE;
	}
	// 构造调用门描述符
	USHORT buff[3] = {0};
	buff[2] = CallGateDescriptor;
	// 参数压栈
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
	// 调用门调用
	__asm call fword ptr [buff]; // 长调用，使用调用门提权
	return TRUE;
}

// API函数过写拷贝，其实就是将函数线性地址的PDE，PTE改成可写
// 参数0：要过写拷贝的函数地址
// 参数1：PDE线性地址
// 参数2：PTE线性地址
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
		mov eax,[esp+0x24+0x8+0x0]; // 参数2，PTE的地址
		or dword ptr [eax],0x00000006;
		mov eax,[esp+0x24+0x8+0x4]; // 参数1，PDE的地址
		or dword ptr [eax],0x00000006;
		mov eax,[esp+0x24+0x8+0x8]; // 参数0，要过写拷贝的函数地址
		invlpg [eax]; // 清除TLB缓存
	}
	__asm
	{
		popfd;
		popad;
		retf 0xC;
	}
}

// 过写拷贝
void BypassApiWriteCopy()
{
	// MessageBoxA 挂物理页，不这样操作，MessageBoxA的PTE可能是无效的
	__asm
	{
		mov eax, dword ptr ds:[MessageBoxA];
		mov eax,[eax];
	}
	// MessageBoxA过写拷贝	
	DWORD pParam[3];
	pParam[0] = (DWORD)MessageBoxA;
	pParam[1] = (DWORD)GetPDE(pParam[0]);
	pParam[2] = (DWORD)GetPTE(pParam[0]);
	CallInRing0(BypassApiWriteCopyNaked, pParam,3);
}

// HOOK MessageBoxA
// 理论上可以 HOOK User32.dll 里的任意函数
BOOL HookUser32Api()
{
	HANDLE hDevice = CreateFileW(DRIVER_LINK,GENERIC_READ|GENERIC_WRITE,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("打开设备失败.\n");
		return FALSE;
	}
	USHORT IntGateNum; // 中断号
	DWORD dwRetBytes; // 返回的字节数

	DeviceIoControl(hDevice,OPER_HOOK,NULL,0,&IntGateNum,sizeof(USHORT),&dwRetBytes,NULL);
	if (dwRetBytes != 2 || IntGateNum == 0)
	{
		printf("构造中断门失败.\n");
		return FALSE;
	}
	CloseHandle(hDevice);

	// HOOK MessageBoxA
	USHORT IntInstructions = (IntGateNum << 8);
	IntInstructions |= (USHORT)0x00CD;	
	*(PUSHORT)MessageBoxA = IntInstructions;

	return TRUE;
}

// 从驱动获取调用记录
void UpdateApiCallRecord()
{
	HANDLE hDevice = CreateFileW(DRIVER_LINK,GENERIC_READ|GENERIC_WRITE,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("打开设备失败.\n");
		return;
	}
	APICALLRECORD ApiCallRecord;
	DWORD dwRetBytes; // 返回的字节数
	while (!GetAsyncKeyState('Q'))
	{
		Sleep(50);
		DeviceIoControl(hDevice,OPER_GET_APICALLRECORD,NULL,0,&ApiCallRecord,sizeof(ApiCallRecord),&dwRetBytes,NULL);
		if (dwRetBytes == 0) 
		{
			//printf("无API调用记录.\n");
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


