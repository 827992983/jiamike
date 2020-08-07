#ifndef PE_HPP_
#define PE_HPP_

/********************************************************************************
时间：2020年7月14日
作者：hambaga
说明：重新整理的PE工具函数，仅适用于32位程序
********************************************************************************/

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif // !_CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <WINDOWS.H>
#include <STRING.h>
#include <MALLOC.H>

DWORD FileToMemory(LPCSTR lpszFile, LPVOID *pFileBuffer);
BOOL MemoryToFile(LPVOID pMemBuffer, DWORD dwSize, LPCSTR lpszFile);
BOOL Is32PEFile(LPVOID pFileBuffer, DWORD dwSize);
DWORD FileBufferToImageBuffer(LPVOID pFileBuffer, LPVOID *pImageBuffer);
DWORD ImageBufferToFileBuffer(LPVOID pImageBuffer, LPVOID *pFileBuffer);
DWORD Align(DWORD dwOffset, DWORD dwAlign);
DWORD RvaToFoa(LPVOID pFileBuffer, DWORD dwRva);
DWORD FoaToRva(LPVOID pFileBuffer, DWORD dwFoa);
DWORD MoveNTHeaderAndSectionHeadersToDosStub(LPVOID pFileBuffer);
VOID SetNewImageBase(LPVOID pFileBuffer, DWORD dwNewImageBase);
DWORD WriteEncryptedDataToNewSection(LPVOID pFileBuffer, DWORD dwFileBufferSize, LPVOID *pNewFileBuffer, LPVOID pData, DWORD dwDataSize);
DWORD ReadEncryptedDataFromLastSection(LPVOID pFileBuffer, DWORD dwFileBufferSize, LPVOID *pData);

// 读取文件到内存中，返回读取的字节数；读取失败返回0
DWORD FileToMemory(LPCSTR lpszFile, LPVOID *pFileBuffer)
{
	FILE *pFile = NULL;
	DWORD dwFileSize = 0;
	pFile = fopen(lpszFile, "rb");
	if (pFile == NULL)
	{
		printf("打开文件失败\n");
		return 0;
	}
	fseek(pFile, 0, SEEK_END);
	dwFileSize = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);
	*pFileBuffer = malloc(dwFileSize);
	if (*pFileBuffer == NULL)
	{
		printf("分配内存失败\n");
		fclose(pFile);
		return 0;
	}
	DWORD dwRead = fread(*pFileBuffer, 1, dwFileSize, pFile);
	fclose(pFile);
	if (dwRead != dwFileSize)
	{
		free(*pFileBuffer);
		return 0;
	}
	return dwRead;
}

// 验证是否是合法的32位PE文件
BOOL Is32PEFile(LPVOID pFileBuffer, DWORD dwSize)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	if (*((PWORD)pDosHeader) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		return FALSE;
	}
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标记\n");
		return FALSE;
	}
	return TRUE;
}

// 将 FileBuffer 拉伸成 ImageBuffer 并写入到新的缓冲区
// 返回 ImageBuffer 的大小；失败返回0
DWORD FileBufferToImageBuffer(LPVOID pFileBuffer, LPVOID *pImageBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	*pImageBuffer = malloc(pOptionHeader->SizeOfImage);
	if (*pImageBuffer == NULL)
	{
		printf("分配内存失败\n");
		return 0;
	}
	memset(*pImageBuffer, 0, pOptionHeader->SizeOfImage);
	// 复制DOS头+PE头+可选PE头+节表+文件对齐
	memcpy(*pImageBuffer, pFileBuffer, pOptionHeader->SizeOfHeaders);
	// 遍历节表，复制所有节	
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		memcpy((LPVOID)((DWORD)(*pImageBuffer) + pSectionHeader[i].VirtualAddress), \
			(LPVOID)((DWORD)pFileBuffer + pSectionHeader[i].PointerToRawData), \
			pSectionHeader[i].SizeOfRawData);
	}
	return pOptionHeader->SizeOfImage;
}

// 将 ImageBuffer 变成文件对齐的 FileBuffer 写入新的缓冲区
// 返回复制的大小，失败返回0
DWORD ImageBufferToFileBuffer(LPVOID pImageBuffer, LPVOID *pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	// 最后一个节表
	PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeader + pPEHeader->NumberOfSections - 1;
	// 计算要复制的字节
	// 这一步有BUG，当最后一个节后面还有数据时（多见于控制台程序），丢失数据
	DWORD dwFileBufferSize = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;
	*pFileBuffer = malloc(dwFileBufferSize);
	if (*pFileBuffer == NULL)
	{
		printf("分配内存失败\n");
		return 0;
	}
	memset(*pFileBuffer, 0, dwFileBufferSize);
	// 复制DOS头+PE头+可选PE头+节表+文件对齐
	memcpy(*pFileBuffer, pImageBuffer, pOptionHeader->SizeOfHeaders);
	// 遍历节表，复制文件对齐后的节	
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		memcpy((LPVOID)((DWORD)(*pFileBuffer) + pSectionHeader[i].PointerToRawData), \
			(LPVOID)((DWORD)pImageBuffer + pSectionHeader[i].VirtualAddress), \
			pSectionHeader[i].SizeOfRawData);
	}
	return dwFileBufferSize;
}

// 内存数据写入文件
BOOL MemoryToFile(LPVOID pMemBuffer, DWORD dwSize, LPCSTR lpszFile)
{
	FILE *fp = NULL;
	fp = fopen(lpszFile, "wb+");
	if (fp == NULL)
	{
		printf("打开文件失败\n");
		return FALSE;
	}
	DWORD dwWritten = fwrite(pMemBuffer, 1, dwSize, fp);
	if (dwWritten != dwSize)
	{
		printf("写入了 %d 字节，不等于 %d\n", dwWritten, dwSize);
		fclose(fp);
		return FALSE;
	}
	fclose(fp);
	return TRUE;
}

// 计算对齐的函数，如偏移为900，对齐为1000h，返回1000h
DWORD Align(DWORD dwOffset, DWORD dwAlign)
{
	// 如果偏移小于对齐，向上取整
	if (dwOffset <= dwAlign) return dwAlign;
	// 如果偏移大于对齐且不能除尽，向上取整
	if (dwOffset % dwAlign)
	{
		return (dwOffset / dwAlign + 1) * dwAlign;
	}
	// 如果能除尽，直接返回offset
	return dwOffset;
}

// RVA 转 FOA
DWORD RvaToFoa(LPVOID pFileBuffer, DWORD dwRva)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(pDosHeader->e_lfanew + (DWORD)pFileBuffer + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	// RVA在文件头中或者文件对齐==内存对齐时，RVA==FOA  错！第一句是对的，第二句是错的
	if (dwRva < pOptionHeader->SizeOfHeaders)
	{
		return dwRva;
	}

	// 遍历节表，确定偏移属于哪一个节	
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		if (dwRva >= pSectionHeader[i].VirtualAddress && \
			dwRva < pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize)
		{
			int offset = dwRva - pSectionHeader[i].VirtualAddress;
			return pSectionHeader[i].PointerToRawData + offset;
		}
	}
	printf("找不到RVA %x 对应的 FOA，转换失败\n", dwRva);
	return 0;
}

// FOA 转 RVA
DWORD FoaToRva(LPVOID pFileBuffer, DWORD dwFoa)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(pDosHeader->e_lfanew + (DWORD)pFileBuffer + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	// RVA在文件头中或者文件对齐==内存对齐时，RVA==FOA  错！第一句是对的，第二句是错的
	if (dwFoa < pOptionHeader->SizeOfHeaders)
	{
		return dwFoa;
	}

	// 遍历节表，确定偏移属于哪一个节	
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		if (dwFoa >= pSectionHeader[i].PointerToRawData && \
			dwFoa < pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData)
		{
			int offset = dwFoa - pSectionHeader[i].PointerToRawData;
			return pSectionHeader[i].VirtualAddress + offset;
		}
	}
	printf("找不到FOA %x 对应的 RVA，转换失败\n", dwFoa);
	return 0;
}

// 移动NT头和节表到DOS STUB，该函数在新增节时节表空间不足的情况下调用；返回地址减小值
DWORD MoveNTHeaderAndSectionHeadersToDosStub(LPVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	LPVOID pDst = (LPVOID)((DWORD)pDosHeader + sizeof(IMAGE_DOS_HEADER)); // NT头插入点
	DWORD dwRet = (DWORD)pNTHeader - (DWORD)pDst; // 返回地址减小的值
	DWORD dwSize = 4 + sizeof(IMAGE_FILE_HEADER) + pPEHeader->SizeOfOptionalHeader + \
		sizeof(IMAGE_SECTION_HEADER) * pPEHeader->NumberOfSections; // 移动的字节数
	LPVOID pSrc = malloc(dwSize);
	if (pSrc == NULL)
	{
		printf("分配内存失败\n");
		return 0;
	}
	memcpy(pSrc, (LPVOID)pNTHeader, dwSize); // 保存要复制的数据
	memset((LPVOID)pNTHeader, 0, dwSize); // 清空原数据
	memcpy(pDst, pSrc, dwSize); // 移动数据
	free(pSrc);
	pDosHeader->e_lfanew = sizeof(IMAGE_DOS_HEADER); // 更新 e_lfanew

	return dwRet;
}

// 修改 ImageBase 并修复重定位表
VOID SetNewImageBase(LPVOID pFileBuffer, DWORD dwNewImageBase)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(pDosHeader->e_lfanew + (DWORD)pDosHeader + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	PIMAGE_BASE_RELOCATION pRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer + \
		RvaToFoa(pFileBuffer, pOptionHeader->DataDirectory[5].VirtualAddress));
	DWORD dwImageBaseDelta = dwNewImageBase - pOptionHeader->ImageBase; // 新旧ImageBase 的差值	

	// 重定位表的 VirtualAddress + 低12位偏移 = RVA
	// RVA + ImageBase 这个内存里存储了一个“指针”
	// 要修改的是这个“指针”的值，要让这个“指针”加上两个ImageBase的差值
	while (pRelocationTable->VirtualAddress || pRelocationTable->SizeOfBlock)
	{
		size_t n = (pRelocationTable->SizeOfBlock - 8) / 2; // 可能需要修改的地址数量（高4位==0011才要修改）
		PWORD pOffset = (PWORD)((DWORD)pRelocationTable + 8); // 2字节偏移的数组
		for (size_t i = 0; i < n; i++)
		{
			// 高4位等于0011才需要重定位
			if ((pOffset[i] & 0xF000) == 0x3000)
			{
				// 计算需要重定位的数据的RVA地址
				DWORD dwRva = pRelocationTable->VirtualAddress + (pOffset[i] & 0x0FFF);
				// 计算在文件中的偏移
				DWORD dwFoa = RvaToFoa(pFileBuffer, dwRva);
				// 计算在文件中的地址
				PDWORD pData = (PDWORD)((DWORD)pFileBuffer + dwFoa);
				// 重定位，即修正写死的地址				
				*pData += dwImageBaseDelta;
			}
		}

		pRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocationTable + pRelocationTable->SizeOfBlock);
	}
	// 修改 ImageBase
	pOptionHeader->ImageBase = dwNewImageBase;
}

// 将数据加密后添加到新增节中
// 返回新缓冲区的大小，失败返回0
// 这个数据节前N个字节是一串十进制字符串，表示数据大小，以NULL结束
DWORD WriteEncryptedDataToNewSection(LPVOID pFileBuffer, DWORD dwFileBufferSize, LPVOID *pNewFileBuffer, LPVOID pData, DWORD dwDataSize)
{
	// 复制一份 pFileBuffer，不要修改原来的数据
	LPVOID pFileBuffer3 = malloc(dwFileBufferSize);
	memcpy(pFileBuffer3, pFileBuffer, dwFileBufferSize);
	pFileBuffer = pFileBuffer3;
	pFileBuffer3 = NULL;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	PWORD pNumberOfSections = &(pPEHeader->NumberOfSections); // 节的数量
	PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeader + *pNumberOfSections - 1; // 最后一个节表
	PIMAGE_SECTION_HEADER pNewSectionHeader = pSectionHeader + *pNumberOfSections; // 新节表插入点
	DWORD newFileBufferSize = 0; // 新文件的大小

	// 判断最后一个节表后面是否有空闲的80字节
	if (80 > (DWORD)pFileBuffer + pOptionHeader->SizeOfHeaders - (DWORD)pNewSectionHeader)
	{
		printf("没有足够的80字节插入新节表\n");
		free(pFileBuffer);
		return 0;
	}
	// 判断空闲的80字节是否全为0，如果不是，则把整个NT头往上挪覆盖dos stub以空出空间插入节表
	for (int i = 0; i < 80; i++)
	{
		if (((PBYTE)pNewSectionHeader)[i] != 0)
		{
			DWORD dwRet = MoveNTHeaderAndSectionHeadersToDosStub(pFileBuffer);
			printf("节表空间不足，NT头和节表向低地址移动了 %d 字节\n", dwRet);
			if (dwRet < 80)
			{
				printf("移动后仍没有足够的80字节空间插入新节表\n");
				free(pFileBuffer);
				return 0;
			}
			// 更新指针
			pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
			pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
			pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
			pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
			pNumberOfSections = &(pPEHeader->NumberOfSections); // 节的数量
			pLastSectionHeader = pSectionHeader + *pNumberOfSections - 1; // 最后一个节表
			pNewSectionHeader = pSectionHeader + *pNumberOfSections; // 新节表插入点
			break;
		}
	}
	// 创建数据大小标记
	char sSizeFlag[100] = { 0 };
	sprintf(sSizeFlag, "%d", dwDataSize);
	DWORD dwFlagLen = strlen(sSizeFlag) + 1; // 拷贝长度包括NULL

	// 定义一个 IMAGE_SECTION_HEADER 结构，计算里面的属性
	IMAGE_SECTION_HEADER newSectionHeader;
	memcpy(newSectionHeader.Name, ".encsrc", 8);
	newSectionHeader.Misc.VirtualSize = Align(dwDataSize + dwFlagLen, pOptionHeader->SectionAlignment);
	newSectionHeader.VirtualAddress = pLastSectionHeader->VirtualAddress + \
		Align(pLastSectionHeader->Misc.VirtualSize, pOptionHeader->SectionAlignment);
	newSectionHeader.SizeOfRawData = Align(dwDataSize + dwFlagLen, pOptionHeader->FileAlignment);
	newSectionHeader.PointerToRawData = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;
	newSectionHeader.PointerToRelocations = 0;
	newSectionHeader.PointerToLinenumbers = 0;
	newSectionHeader.NumberOfRelocations = 0;
	newSectionHeader.NumberOfLinenumbers = 0;
	newSectionHeader.Characteristics = 0xC0000040;

	// pNewFileBuffer 分配内存，把 pFileBuffer 复制过去，后面的修改都在 pNewFileBuffer 进行	
	*pNewFileBuffer = malloc(dwFileBufferSize + newSectionHeader.SizeOfRawData);
	memcpy(*pNewFileBuffer, pFileBuffer, dwFileBufferSize);
	memset((LPVOID)((DWORD)*pNewFileBuffer + dwFileBufferSize), 0, newSectionHeader.SizeOfRawData); // 新增节数据清0

	// 更新指针，指向新内存	
	pDosHeader = (PIMAGE_DOS_HEADER)*pNewFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	pNumberOfSections = &(pPEHeader->NumberOfSections);
	pLastSectionHeader = pSectionHeader + *pNumberOfSections - 1;
	pNewSectionHeader = pSectionHeader + *pNumberOfSections;

	// 节的数量+1，SizeOfImage是内存中拉伸后的大小
	*pNumberOfSections += 1;
	pOptionHeader->SizeOfImage += Align(newSectionHeader.Misc.VirtualSize, pOptionHeader->SectionAlignment);

	// 拷贝 newSectionHeader
	memcpy(pNewSectionHeader, &newSectionHeader, sizeof(newSectionHeader));

	// 拷贝数据到新增节
	LPVOID pNewSec = (LPVOID)((DWORD)*pNewFileBuffer + (DWORD)(pSectionHeader[*pNumberOfSections - 1].PointerToRawData));
	memcpy(pNewSec, sSizeFlag, dwFlagLen);
	NaiveEncrypt(pData,dwDataSize,"hambaga",strlen("hambaga"));
	memcpy((LPVOID)((PBYTE)pNewSec + dwFlagLen), pData, dwDataSize);

	//printf("插入成功\n");
	free(pFileBuffer);
	return dwFileBufferSize + newSectionHeader.SizeOfRawData;
}

// 从最后一个节里读取数据，并解密，返回数据大小
// 最后一个节名字必须是.encsrc，开头N个字节必须是十进制数字符串，NULL结尾，表示后面的数据字节数
// *pData 输出数据内容，不包含开头大小标记
DWORD ReadEncryptedDataFromLastSection(LPVOID pFileBuffer, DWORD dwFileBufferSize, LPVOID *pData)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	PWORD pNumberOfSections = &(pPEHeader->NumberOfSections); // 节的数量
	PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeader + *pNumberOfSections - 1; // 最后一个节表
	if (memcmp(".encsrc", pLastSectionHeader->Name, 8) != 0)
	{
		printf("不是有效的加密程序\n");
		int i = 0;
		for (; i < 8; i++)
		{
			printf("%c", pLastSectionHeader->Name[i]);
		}
		puts("");
		return 0;
	}
	LPVOID pLastSection = (LPVOID)(pLastSectionHeader->PointerToRawData + (PBYTE)pFileBuffer);
	DWORD dwDataSize = -1;
	sscanf((char *)pLastSection, "%d", &dwDataSize);
	LPVOID pTemp = (PBYTE)pLastSection + strlen((char *)pLastSection) + 1;
	*pData = malloc(dwDataSize);
	memcpy(*pData, pTemp, dwDataSize);	
	return dwDataSize;
}



#endif

