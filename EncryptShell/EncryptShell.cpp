// 该程序是加密壳项目的壳程序，不能独立运行，它是作为加密程序的资源存在的
// 由加密程序向该壳程序的尾部添加一个加密节，然后再写入磁盘
// 该程序独立存在是没有意义的，因为它依赖加密程序添加的数据

#include "stdafx.h"
#include "PE.hpp"


int main(int argc, char* argv[])
{
	// 读取本进程encsrc节的数据
	char szCurrentPaths[MAX_PATH] = {0};
	GetModuleFileName(NULL, szCurrentPaths, MAX_PATH);	
	LPVOID pShell = NULL;
	DWORD dwShellSize = FileToMemory(szCurrentPaths, &pShell);
	LPVOID pData = NULL;
	DWORD dwDataSize = ReadEncryptedDataFromLastSection(pShell, dwShellSize, &pData);	
	printf("数据解密完成.\n");

	
	// 校验PE文件
	if (Is32PEFile(pData, dwDataSize) == FALSE)
	{
		printf("校验失败，不是合法的32位PE文件.");
		system("pause");
		return -1;
	}
	printf("校验PE文件合法.\n");
	// 拉伸PE文件	
	LPVOID pSrcImgBuffer = NULL;
	DWORD dwSrcImgSize = FileBufferToImageBuffer(pData, &pSrcImgBuffer);
	if (dwSrcImgSize != 0)
	{
		printf("拉伸内存镜像成功.\n");
	}
	else
	{
		printf("拉伸内存镜像失败.\n");
		system("pause");
		return -1;
	}
	// 以挂起方式创建一个傀儡进程，只要它的4GB空间	
	STARTUPINFO si = {0};
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi;	
	if (NULL != CreateProcess(NULL, szCurrentPaths, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
	{
		printf("创建挂起进程成功.\n");
	}
	else
	{
		printf("创建挂起进程失败.\n");
		system("pause");
		return -1;
	}
	// 获取新线程上下文
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, &context);
	// 获取 ZwUnmapViewOfSection
	HMODULE hModuleNt = LoadLibrary("ntdll.dll");
	if (NULL == hModuleNt)
	{
		printf("获取ntdll句柄失败.\n");
		getchar();
		return -1;
	}
	else
	{
		printf("获取ntdll句柄成功.\n");
	}
	typedef DWORD (WINAPI *_TZwUnmapViewOfSection)(HANDLE,PVOID);
	_TZwUnmapViewOfSection pZwUnmapViewOfSection = (_TZwUnmapViewOfSection)GetProcAddress(hModuleNt, "ZwUnmapViewOfSection");
	if (NULL == pZwUnmapViewOfSection)
	{
		printf("获取ZwUnmapViewOfSection函数指针失败.\n");
		getchar();
		return -1;
	}
	else
	{
		printf("获取ZwUnmapViewOfSection函数指针成功.\n");
	}
	// 调用 ZwUnmapViewOfSection 卸载新进程内存镜像
	pZwUnmapViewOfSection(pi.hProcess, GetModuleHandle(NULL));
	// 获取源程序的ImageBase
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pSrcImgBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	DWORD dwSrcImageBase = pOptionHeader->ImageBase;
	// 在傀儡进程的源程序的ImageBase处申请SizeOfImage大小的内存	
	LPVOID pImageBase = VirtualAllocEx(
		pi.hProcess, (LPVOID)dwSrcImageBase, dwSrcImgSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if ((DWORD)pImageBase != dwSrcImageBase)
	{
		printf("VirtualAllocEx 错误码: 0x%X\n", GetLastError()); // 0x1e7 试图访问无效地址，解决方法：提升权限
		TerminateThread(pi.hThread, 0);
		return -1;
	}	
	
	// 将源程序内存镜像复制到傀儡进程4GB中	
	if (0 == WriteProcessMemory(
		pi.hProcess, (LPVOID)dwSrcImageBase, pSrcImgBuffer, dwSrcImgSize, NULL))
	{
		printf("写入源程序内存镜像失败\n");
		TerminateThread(pi.hThread, 0);
		return -1;
	}
	
	// 修正入口点
	context.Eax = pOptionHeader->AddressOfEntryPoint + dwSrcImageBase;
	// 修正 ImageBase
	WriteProcessMemory(pi.hProcess, (LPVOID)(context.Ebx + 8), &dwSrcImageBase, 4, NULL);
	// 设置线程context
	SetThreadContext(pi.hThread, &context);	
	// 恢复线程	
	ResumeThread(pi.hThread);
	// 脱壳成功
	printf("脱壳成功，源程序正在运行，敲任意字符退出\n");
	getchar();
	return 0;
}

