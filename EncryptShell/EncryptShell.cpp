// �ó����Ǽ��ܿ���Ŀ�Ŀǳ��򣬲��ܶ������У�������Ϊ���ܳ������Դ���ڵ�
// �ɼ��ܳ�����ÿǳ����β�����һ�����ܽڣ�Ȼ����д�����
// �ó������������û������ģ���Ϊ���������ܳ�����ӵ�����

#include "stdafx.h"
#include "PE.hpp"


int main(int argc, char* argv[])
{
	// ��ȡ������encsrc�ڵ�����
	char szCurrentPaths[MAX_PATH] = {0};
	GetModuleFileName(NULL, szCurrentPaths, MAX_PATH);	
	LPVOID pShell = NULL;
	DWORD dwShellSize = FileToMemory(szCurrentPaths, &pShell);
	LPVOID pData = NULL;
	DWORD dwDataSize = ReadEncryptedDataFromLastSection(pShell, dwShellSize, &pData);	
	printf("���ݽ������.\n");

	
	// У��PE�ļ�
	if (Is32PEFile(pData, dwDataSize) == FALSE)
	{
		printf("У��ʧ�ܣ����ǺϷ���32λPE�ļ�.");
		system("pause");
		return -1;
	}
	printf("У��PE�ļ��Ϸ�.\n");
	// ����PE�ļ�	
	LPVOID pSrcImgBuffer = NULL;
	DWORD dwSrcImgSize = FileBufferToImageBuffer(pData, &pSrcImgBuffer);
	if (dwSrcImgSize != 0)
	{
		printf("�����ڴ澵��ɹ�.\n");
	}
	else
	{
		printf("�����ڴ澵��ʧ��.\n");
		system("pause");
		return -1;
	}
	// �Թ���ʽ����һ�����ܽ��̣�ֻҪ����4GB�ռ�	
	STARTUPINFO si = {0};
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi;	
	if (NULL != CreateProcess(NULL, szCurrentPaths, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
	{
		printf("����������̳ɹ�.\n");
	}
	else
	{
		printf("�����������ʧ��.\n");
		system("pause");
		return -1;
	}
	// ��ȡ���߳�������
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, &context);
	// ��ȡ ZwUnmapViewOfSection
	HMODULE hModuleNt = LoadLibrary("ntdll.dll");
	if (NULL == hModuleNt)
	{
		printf("��ȡntdll���ʧ��.\n");
		getchar();
		return -1;
	}
	else
	{
		printf("��ȡntdll����ɹ�.\n");
	}
	typedef DWORD (WINAPI *_TZwUnmapViewOfSection)(HANDLE,PVOID);
	_TZwUnmapViewOfSection pZwUnmapViewOfSection = (_TZwUnmapViewOfSection)GetProcAddress(hModuleNt, "ZwUnmapViewOfSection");
	if (NULL == pZwUnmapViewOfSection)
	{
		printf("��ȡZwUnmapViewOfSection����ָ��ʧ��.\n");
		getchar();
		return -1;
	}
	else
	{
		printf("��ȡZwUnmapViewOfSection����ָ��ɹ�.\n");
	}
	// ���� ZwUnmapViewOfSection ж���½����ڴ澵��
	pZwUnmapViewOfSection(pi.hProcess, GetModuleHandle(NULL));
	// ��ȡԴ�����ImageBase
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pSrcImgBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	DWORD dwSrcImageBase = pOptionHeader->ImageBase;
	// �ڿ��ܽ��̵�Դ�����ImageBase������SizeOfImage��С���ڴ�	
	LPVOID pImageBase = VirtualAllocEx(
		pi.hProcess, (LPVOID)dwSrcImageBase, dwSrcImgSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if ((DWORD)pImageBase != dwSrcImageBase)
	{
		printf("VirtualAllocEx ������: 0x%X\n", GetLastError()); // 0x1e7 ��ͼ������Ч��ַ���������������Ȩ��
		TerminateThread(pi.hThread, 0);
		return -1;
	}	
	
	// ��Դ�����ڴ澵���Ƶ����ܽ���4GB��	
	if (0 == WriteProcessMemory(
		pi.hProcess, (LPVOID)dwSrcImageBase, pSrcImgBuffer, dwSrcImgSize, NULL))
	{
		printf("д��Դ�����ڴ澵��ʧ��\n");
		TerminateThread(pi.hThread, 0);
		return -1;
	}
	
	// ������ڵ�
	context.Eax = pOptionHeader->AddressOfEntryPoint + dwSrcImageBase;
	// ���� ImageBase
	WriteProcessMemory(pi.hProcess, (LPVOID)(context.Ebx + 8), &dwSrcImageBase, 4, NULL);
	// �����߳�context
	SetThreadContext(pi.hThread, &context);	
	// �ָ��߳�	
	ResumeThread(pi.hThread);
	// �ѿǳɹ�
	printf("�ѿǳɹ���Դ�����������У��������ַ��˳�\n");
	getchar();
	return 0;
}

