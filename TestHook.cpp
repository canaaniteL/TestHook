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

//����ԭ�����ĵ�ַ
DWORD pOldFuncAddr=(DWORD)GetProcAddress(::LoadLibrary("user32.dll"),"MessageBoxA");

BOOL SetIATHook(DWORD pOldFuncAddr,DWORD pNewFuncAddr)
{
	BOOL bFlag=FALSE;
	DWORD dwImageBase=0;
	PDWORD pFuncAddr=NULL;
	PIMAGE_NT_HEADERS pNTHeader=NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor=NULL;

	//�õ�ģ�����ַ
	dwImageBase=(DWORD)::GetModuleHandle(NULL);
	pNTHeader=(PIMAGE_NT_HEADERS)(dwImageBase+((PIMAGE_DOS_HEADER)dwImageBase)->e_lfanew);
	pImportDescriptor=(PIMAGE_IMPORT_DESCRIPTOR)(dwImageBase+pNTHeader->OptionalHeader.DataDirectory[1].VirtualAddress);

	//����IAT,�����ַΪMessageBox���޸�
	while(pImportDescriptor->FirstThunk!=0 && bFlag==FALSE)
	{
		printf("������%s",(LPSTR)(dwImageBase+pImportDescriptor->Name));
		pFuncAddr=(PDWORD)(dwImageBase+pImportDescriptor->FirstThunk);
		while(*pFuncAddr)
		{
			if(pOldFuncAddr==*pFuncAddr)
			{
				//�ҵ�ҪHOOK�ĺ���
				printf("  ==>�ҵ�����\n");
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

//fake����
int WINAPI MyMessageBox(
   HWND    hWnd,
   LPCTSTR lpText,
   LPCTSTR lpCaption,
   UINT    uType
   )
{
	//����MessageBox����ָ��
	typedef int(WINAPI *FrakeMessageBox)(HWND,LPCTSTR,LPCTSTR,UINT);
	//��ȡ����
	printf("������%x  %s  %s  %x \n",hWnd,lpText,lpCaption,uType);

	//����Ҫִ�еĺ���
	int ret=((FrakeMessageBox)pOldFuncAddr)(hWnd,lpText,lpCaption,uType);
	//��ȡ����ֵ
	printf("����ֵ��%x\n",ret);
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
	::MessageBox(0,"�ҵĵ�һ��HOOK","IAT Hook",MB_OK);
	//ж��IATHook
	unIATHook();
	::MessageBox(0,"console������Hook��","�ڶ�������",MB_OK);
	::MessageBox(0,"console������Hook��","��3������",MB_OK);
}


extern "C" _declspec(naked)void HookProc()
{

	//����Ĵ���
	_asm
	{
		pushad
		pushfd

	}
	//��ȡ����
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
	MessageBox(NULL,szBuffer,"[HOOK �Ĵ�������]",MB_OK);
	memset(szBuffer,0,100);
	sprintf(szBuffer,"����x��%x\n����y��%x\n",dwParaX,dwParaY);
	MessageBox(NULL,szBuffer,"[HOOK ��������]",MB_OK);

	//�ָ��Ĵ���
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

	//ִ����ϣ���ת��HOOK��ַ
	_asm
	{
		jmp g_dwRetAddr;
	}

}

BOOL SetInlineHook(DWORD dwBaseAddr,DWORD HookAddr,DWORD len)
{
/*
	����˵��
	1.��һ��������Ҫ��hook�ĺ�����ַ
	2.�ڶ��������Ǳ�hook��Ҫִ�еĺ�����ַ
	3.������������Ҫ�ѱ�Hook�ĺ���ǰ���ٸ��ֽڽ���hook
*/
	BOOL bRet =FALSE;
	//DWORD dwOldProtect;
	DWORD dwJmpCode;
	//����У��
	if(dwBaseAddr == NULL || HookAddr==NULL)
	{
		printf("ʧ�ܣ�������ַ����\n");
		return FALSE;
	}
	if(len<5)
	{
		printf("ʧ�ܣ�����С��5\n");
		return FALSE;
	}
	//��ҪHOOK���ڴ��޸�Ϊ��д
	DWORD dwFlag;
	bRet=::VirtualProtectEx(::GetCurrentProcess(),(LPVOID)dwBaseAddr,len,PAGE_EXECUTE_READWRITE,&dwFlag);
	if(!bRet)
	{
		printf("ʧ�ܣ��޸��ڴ����Դ���\n");
		return FALSE;
	}
	//�������ڴ棬�洢ԭ����Ӳ����
	g_pCodePatch=new BYTE[len];
	memcpy(g_pCodePatch,(LPVOID)dwBaseAddr,len);
	//��ת��HookAddr
	//Ҫ��ת�ĵ�ַ=E9�ĵ�ַ+5+E9�����ֵ
	//  E9�����ֵ=Ҫ��ת�ĵ�ַ-E9�ĵ�ַ-5
	dwJmpCode=HookAddr-dwBaseAddr-5;

	//��HOOK���ڴ�ȫ��ʼ����nop
	memset((PBYTE)dwBaseAddr,0X90,len);

	//�޸�ҪHOOK�ڴ��Ӳ����
	*(PBYTE)dwBaseAddr=0XE9;      //jmp
	*(PDWORD)((PBYTE)dwBaseAddr+1)=dwJmpCode;         //jmp������ŵĵ�ַ

	//�޸�hook״̬
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
		printf("hookδ�ɹ����޷�ж��\n");
		return FALSE;
	}
	//�޸��ڴ�Ϊ��д
	DWORD dwFlag;
	bRet=::VirtualProtectEx(::GetCurrentProcess(),(PVOID)g_dwBaseAddr,g_dwlength,PAGE_EXECUTE_READWRITE,&dwFlag);
	if(!bRet)
	{
		printf("�޷��޸��ڴ档\n");
		return FALSE;
	}
	//�ָ�ԭ����Ӳ����
	memcpy((PVOID)g_dwBaseAddr,g_pCodePatch,g_dwlength);

	//�޸�hook״̬
	delete[] g_pCodePatch;
	g_dwHookFlag=0;
	g_dwBaseAddr=0;
	return TRUE;

}
//InlineHook����
DWORD Plus(DWORD x,DWORD y)
{
	return x+y;

}
void TestInlineHook()
{

	//��װHOOK 0x401420
	SetInlineHook((DWORD)Plus,(DWORD)HookProc,6);
	Plus(1,10);
	printf("2+16=%d\n",Plus(2,16));
	//ж��hook
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

