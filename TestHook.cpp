// TestHook.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>

typedef struct _REGISTER
{
	DWORD Eax;
	DWORD Ebx;
	DWORD Ecx;
	DWORD Edx;
	DWORD Esp;
	DWORD Ebp;
	DWORD Esi;
	DWORD Edi;

}Register;

DWORD dwParaX;
DWORD dwParaY;
Register reg={0};
TCHAR szBuffer[100]={0};


DWORD g_dwIATHookFlag=0;
DWORD g_dwOldAddr;
DWORD g_dwNewAddr;
BYTE* g_pCodePatch;
DWORD g_dwBaseAddr;
BOOL g_dwHookFlag=FALSE;
DWORD g_dwlength;
DWORD g_dwRetAddr;

//保存原函数的地址
DWORD pOldFuncAddr=(DWORD)GetProcAddress(::LoadLibrary("user32.dll"),"MessageBoxA");

BOOL SetIATHook(DWORD pOldFuncAddr,DWORD pNewFuncAddr)
{
	BOOL bFlag=FALSE;
	DWORD dwImageBase=0;
	PDWORD pFuncAddr=NULL;
	PIMAGE_NT_HEADERS pNTHeader=NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor=NULL;

	//得到模块基地址
	dwImageBase=(DWORD)::GetModuleHandle(NULL);
	pNTHeader=(PIMAGE_NT_HEADERS)(dwImageBase+((PIMAGE_DOS_HEADER)dwImageBase)->e_lfanew);
	pImportDescriptor=(PIMAGE_IMPORT_DESCRIPTOR)(dwImageBase+pNTHeader->OptionalHeader.DataDirectory[1].VirtualAddress);

	//遍历IAT,如果地址为MessageBox就修改
	while(pImportDescriptor->FirstThunk!=0 && bFlag==FALSE)
	{
		printf("遍历：%s",(LPSTR)(dwImageBase+pImportDescriptor->Name));
		pFuncAddr=(PDWORD)(dwImageBase+pImportDescriptor->FirstThunk);
		while(*pFuncAddr)
		{
			if(pOldFuncAddr==*pFuncAddr)
			{
				//找到要HOOK的函数
				printf("  ==>找到函数\n");
				*pFuncAddr=pNewFuncAddr;
				bFlag=TRUE;
				break;
			}
			pFuncAddr++;
		}
		printf("\n");
		pImportDescriptor++;
	}

	return TRUE;
}

//fake函数
int WINAPI MyMessageBox(
   HWND    hWnd,
   LPCTSTR lpText,
   LPCTSTR lpCaption,
   UINT    uType
   )
{
	//定义MessageBox函数指针
	typedef int(WINAPI *FrakeMessageBox)(HWND,LPCTSTR,LPCTSTR,UINT);
	//获取参数
	printf("参数：%x  %s  %s  %x \n",hWnd,lpText,lpCaption,uType);

	//真正要执行的函数
	int ret=((FrakeMessageBox)pOldFuncAddr)(hWnd,lpText,lpCaption,uType);
	//获取返回值
	printf("返回值：%x\n",ret);
	return ret;
}

BOOL unIATHook()
{
	SetIATHook((DWORD)MyMessageBox,pOldFuncAddr);
	return TRUE;

}
void TestIATHook()
{

	SetIATHook(pOldFuncAddr,(DWORD)MyMessageBox);
	::MessageBox(0,"我的第一个HOOK","IAT Hook",MB_OK);
	//卸载IATHook
	unIATHook();
	::MessageBox(0,"console不会再Hook到","第二个弹窗",MB_OK);
	::MessageBox(0,"console不会再Hook到","第3个弹窗",MB_OK);
}


extern "C" _declspec(naked)void HookProc()
{

	//保存寄存器
	_asm
	{
		pushad
		pushfd

	}
	//获取数据
	_asm
	{
	
		mov reg.Eax,eax
		mov reg.Ebx,ebx
		mov reg.Edx,edx
		mov reg.Ecx,ecx
		mov reg.Esp,esp
		mov reg.Ebp,ebp
		mov reg.Esi,esi
		mov reg.Edi,edi

		mov EAX,DWORD PTR SS:[esp+0x28]
		mov dwParaX,EAX
		mov EAX,DWORD PTR SS:[esp+0x2C]
		mov dwParaY,EAX
	}
	sprintf(szBuffer,"EAX:%x\nECX:%x\nEDX:%x\nEBX:%x\n",reg.Eax,reg.Ecx,reg.Edx,reg.Ebx);
	MessageBox(NULL,szBuffer,"[HOOK 寄存器数据]",MB_OK);
	memset(szBuffer,0,100);
	sprintf(szBuffer,"参数x：%x\n参数y：%x\n",dwParaX,dwParaY);
	MessageBox(NULL,szBuffer,"[HOOK 参数数据]",MB_OK);

	//恢复寄存器
	_asm
	{
		popfd
		popad
	}
	_asm
	{
		push ebp
		mov ebp,esp
		sub esp,40h
	}

	//执行完毕，跳转回HOOK地址
	_asm
	{
		jmp g_dwRetAddr;
	}

}

BOOL SetInlineHook(DWORD dwBaseAddr,DWORD HookAddr,DWORD len)
{
/*
	参数说明
	1.第一个参数是要被hook的函数地址
	2.第二个参数是被hook后要执行的函数地址
	3.第三个参数是要把被Hook的函数前多少个字节进行hook
*/
	BOOL bRet =FALSE;
	//DWORD dwOldProtect;
	DWORD dwJmpCode;
	//参数校验
	if(dwBaseAddr == NULL || HookAddr==NULL)
	{
		printf("失败，函数地址错误\n");
		return FALSE;
	}
	if(len<5)
	{
		printf("失败，长度小于5\n");
		return FALSE;
	}
	//将要HOOK的内存修改为可写
	DWORD dwFlag;
	bRet=::VirtualProtectEx(::GetCurrentProcess(),(LPVOID)dwBaseAddr,len,PAGE_EXECUTE_READWRITE,&dwFlag);
	if(!bRet)
	{
		printf("失败，修改内存属性错误\n");
		return FALSE;
	}
	//创建堆内存，存储原来的硬编码
	g_pCodePatch=new BYTE[len];
	memcpy(g_pCodePatch,(LPVOID)dwBaseAddr,len);
	//跳转到HookAddr
	//要跳转的地址=E9的地址+5+E9后面的值
	//  E9后面的值=要跳转的地址-E9的地址-5
	dwJmpCode=HookAddr-dwBaseAddr-5;

	//将HOOK的内存全初始化成nop
	memset((PBYTE)dwBaseAddr,0X90,len);

	//修改要HOOK内存的硬编码
	*(PBYTE)dwBaseAddr=0XE9;      //jmp
	*(PDWORD)((PBYTE)dwBaseAddr+1)=dwJmpCode;         //jmp后面跟着的地址

	//修改hook状态
	g_dwHookFlag=TRUE;
	g_dwBaseAddr=dwBaseAddr;
	g_dwlength=len;
	g_dwRetAddr=dwBaseAddr+len;
	return TRUE;


}
BOOL UnInlineHook(){
	BOOL bRet=FALSE;
	DWORD dwOldProtect=0;
	if(!g_dwHookFlag)
	{
		printf("hook未成功，无法卸载\n");
		return FALSE;
	}
	//修改内存为可写
	DWORD dwFlag;
	bRet=::VirtualProtectEx(::GetCurrentProcess(),(PVOID)g_dwBaseAddr,g_dwlength,PAGE_EXECUTE_READWRITE,&dwFlag);
	if(!bRet)
	{
		printf("无法修改内存。\n");
		return FALSE;
	}
	//恢复原来的硬编码
	memcpy((PVOID)g_dwBaseAddr,g_pCodePatch,g_dwlength);

	//修改hook状态
	delete[] g_pCodePatch;
	g_dwHookFlag=0;
	g_dwBaseAddr=0;
	return TRUE;

}
//InlineHook函数
DWORD Plus(DWORD x,DWORD y)
{
	return x+y;

}
void TestInlineHook()
{

	//安装HOOK 0x401420
	SetInlineHook((DWORD)Plus,(DWORD)HookProc,6);
	Plus(1,10);
	printf("2+16=%d\n",Plus(2,16));
	//卸载hook
	UnInlineHook();
	printf("2+16=%d\n",Plus(2,16));
}

int main(int argc, char* argv[])
{
//	HookProc();
	Plus(1,4);
	TestInlineHook();
	return 0;
}

