#ifndef PE_HPP_
#define PE_HPP_

/********************************************************************************
ʱ�䣺2020��7��14��
���ߣ�hambaga
˵�������������PE���ߺ�������������32λ����
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

// ��ȡ�ļ����ڴ��У����ض�ȡ���ֽ�������ȡʧ�ܷ���0
DWORD FileToMemory(LPCSTR lpszFile, LPVOID *pFileBuffer)
{
	FILE *pFile = NULL;
	DWORD dwFileSize = 0;
	pFile = fopen(lpszFile, "rb");
	if (pFile == NULL)
	{
		printf("���ļ�ʧ��\n");
		return 0;
	}
	fseek(pFile, 0, SEEK_END);
	dwFileSize = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);
	*pFileBuffer = malloc(dwFileSize);
	if (*pFileBuffer == NULL)
	{
		printf("�����ڴ�ʧ��\n");
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

// ��֤�Ƿ��ǺϷ���32λPE�ļ�
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
		printf("������Ч��MZ��־\n");
		return FALSE;
	}
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("������Ч��PE���\n");
		return FALSE;
	}
	return TRUE;
}

// �� FileBuffer ����� ImageBuffer ��д�뵽�µĻ�����
// ���� ImageBuffer �Ĵ�С��ʧ�ܷ���0
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
		printf("�����ڴ�ʧ��\n");
		return 0;
	}
	memset(*pImageBuffer, 0, pOptionHeader->SizeOfImage);
	// ����DOSͷ+PEͷ+��ѡPEͷ+�ڱ�+�ļ�����
	memcpy(*pImageBuffer, pFileBuffer, pOptionHeader->SizeOfHeaders);
	// �����ڱ��������н�	
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		memcpy((LPVOID)((DWORD)(*pImageBuffer) + pSectionHeader[i].VirtualAddress), \
			(LPVOID)((DWORD)pFileBuffer + pSectionHeader[i].PointerToRawData), \
			pSectionHeader[i].SizeOfRawData);
	}
	return pOptionHeader->SizeOfImage;
}

// �� ImageBuffer ����ļ������ FileBuffer д���µĻ�����
// ���ظ��ƵĴ�С��ʧ�ܷ���0
DWORD ImageBufferToFileBuffer(LPVOID pImageBuffer, LPVOID *pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	// ���һ���ڱ�
	PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeader + pPEHeader->NumberOfSections - 1;
	// ����Ҫ���Ƶ��ֽ�
	// ��һ����BUG�������һ���ں��滹������ʱ������ڿ���̨���򣩣���ʧ����
	DWORD dwFileBufferSize = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;
	*pFileBuffer = malloc(dwFileBufferSize);
	if (*pFileBuffer == NULL)
	{
		printf("�����ڴ�ʧ��\n");
		return 0;
	}
	memset(*pFileBuffer, 0, dwFileBufferSize);
	// ����DOSͷ+PEͷ+��ѡPEͷ+�ڱ�+�ļ�����
	memcpy(*pFileBuffer, pImageBuffer, pOptionHeader->SizeOfHeaders);
	// �����ڱ������ļ������Ľ�	
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		memcpy((LPVOID)((DWORD)(*pFileBuffer) + pSectionHeader[i].PointerToRawData), \
			(LPVOID)((DWORD)pImageBuffer + pSectionHeader[i].VirtualAddress), \
			pSectionHeader[i].SizeOfRawData);
	}
	return dwFileBufferSize;
}

// �ڴ�����д���ļ�
BOOL MemoryToFile(LPVOID pMemBuffer, DWORD dwSize, LPCSTR lpszFile)
{
	FILE *fp = NULL;
	fp = fopen(lpszFile, "wb+");
	if (fp == NULL)
	{
		printf("���ļ�ʧ��\n");
		return FALSE;
	}
	DWORD dwWritten = fwrite(pMemBuffer, 1, dwSize, fp);
	if (dwWritten != dwSize)
	{
		printf("д���� %d �ֽڣ������� %d\n", dwWritten, dwSize);
		fclose(fp);
		return FALSE;
	}
	fclose(fp);
	return TRUE;
}

// �������ĺ�������ƫ��Ϊ900������Ϊ1000h������1000h
DWORD Align(DWORD dwOffset, DWORD dwAlign)
{
	// ���ƫ��С�ڶ��룬����ȡ��
	if (dwOffset <= dwAlign) return dwAlign;
	// ���ƫ�ƴ��ڶ����Ҳ��ܳ���������ȡ��
	if (dwOffset % dwAlign)
	{
		return (dwOffset / dwAlign + 1) * dwAlign;
	}
	// ����ܳ�����ֱ�ӷ���offset
	return dwOffset;
}

// RVA ת FOA
DWORD RvaToFoa(LPVOID pFileBuffer, DWORD dwRva)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(pDosHeader->e_lfanew + (DWORD)pFileBuffer + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	// RVA���ļ�ͷ�л����ļ�����==�ڴ����ʱ��RVA==FOA  ����һ���ǶԵģ��ڶ����Ǵ��
	if (dwRva < pOptionHeader->SizeOfHeaders)
	{
		return dwRva;
	}

	// �����ڱ�ȷ��ƫ��������һ����	
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		if (dwRva >= pSectionHeader[i].VirtualAddress && \
			dwRva < pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize)
		{
			int offset = dwRva - pSectionHeader[i].VirtualAddress;
			return pSectionHeader[i].PointerToRawData + offset;
		}
	}
	printf("�Ҳ���RVA %x ��Ӧ�� FOA��ת��ʧ��\n", dwRva);
	return 0;
}

// FOA ת RVA
DWORD FoaToRva(LPVOID pFileBuffer, DWORD dwFoa)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(pDosHeader->e_lfanew + (DWORD)pFileBuffer + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	// RVA���ļ�ͷ�л����ļ�����==�ڴ����ʱ��RVA==FOA  ����һ���ǶԵģ��ڶ����Ǵ��
	if (dwFoa < pOptionHeader->SizeOfHeaders)
	{
		return dwFoa;
	}

	// �����ڱ�ȷ��ƫ��������һ����	
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		if (dwFoa >= pSectionHeader[i].PointerToRawData && \
			dwFoa < pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData)
		{
			int offset = dwFoa - pSectionHeader[i].PointerToRawData;
			return pSectionHeader[i].VirtualAddress + offset;
		}
	}
	printf("�Ҳ���FOA %x ��Ӧ�� RVA��ת��ʧ��\n", dwFoa);
	return 0;
}

// �ƶ�NTͷ�ͽڱ�DOS STUB���ú�����������ʱ�ڱ�ռ䲻�������µ��ã����ص�ַ��Сֵ
DWORD MoveNTHeaderAndSectionHeadersToDosStub(LPVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	LPVOID pDst = (LPVOID)((DWORD)pDosHeader + sizeof(IMAGE_DOS_HEADER)); // NTͷ�����
	DWORD dwRet = (DWORD)pNTHeader - (DWORD)pDst; // ���ص�ַ��С��ֵ
	DWORD dwSize = 4 + sizeof(IMAGE_FILE_HEADER) + pPEHeader->SizeOfOptionalHeader + \
		sizeof(IMAGE_SECTION_HEADER) * pPEHeader->NumberOfSections; // �ƶ����ֽ���
	LPVOID pSrc = malloc(dwSize);
	if (pSrc == NULL)
	{
		printf("�����ڴ�ʧ��\n");
		return 0;
	}
	memcpy(pSrc, (LPVOID)pNTHeader, dwSize); // ����Ҫ���Ƶ�����
	memset((LPVOID)pNTHeader, 0, dwSize); // ���ԭ����
	memcpy(pDst, pSrc, dwSize); // �ƶ�����
	free(pSrc);
	pDosHeader->e_lfanew = sizeof(IMAGE_DOS_HEADER); // ���� e_lfanew

	return dwRet;
}

// �޸� ImageBase ���޸��ض�λ��
VOID SetNewImageBase(LPVOID pFileBuffer, DWORD dwNewImageBase)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(pDosHeader->e_lfanew + (DWORD)pDosHeader + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	PIMAGE_BASE_RELOCATION pRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer + \
		RvaToFoa(pFileBuffer, pOptionHeader->DataDirectory[5].VirtualAddress));
	DWORD dwImageBaseDelta = dwNewImageBase - pOptionHeader->ImageBase; // �¾�ImageBase �Ĳ�ֵ	

	// �ض�λ��� VirtualAddress + ��12λƫ�� = RVA
	// RVA + ImageBase ����ڴ���洢��һ����ָ�롱
	// Ҫ�޸ĵ��������ָ�롱��ֵ��Ҫ�������ָ�롱��������ImageBase�Ĳ�ֵ
	while (pRelocationTable->VirtualAddress || pRelocationTable->SizeOfBlock)
	{
		size_t n = (pRelocationTable->SizeOfBlock - 8) / 2; // ������Ҫ�޸ĵĵ�ַ��������4λ==0011��Ҫ�޸ģ�
		PWORD pOffset = (PWORD)((DWORD)pRelocationTable + 8); // 2�ֽ�ƫ�Ƶ�����
		for (size_t i = 0; i < n; i++)
		{
			// ��4λ����0011����Ҫ�ض�λ
			if ((pOffset[i] & 0xF000) == 0x3000)
			{
				// ������Ҫ�ض�λ�����ݵ�RVA��ַ
				DWORD dwRva = pRelocationTable->VirtualAddress + (pOffset[i] & 0x0FFF);
				// �������ļ��е�ƫ��
				DWORD dwFoa = RvaToFoa(pFileBuffer, dwRva);
				// �������ļ��еĵ�ַ
				PDWORD pData = (PDWORD)((DWORD)pFileBuffer + dwFoa);
				// �ض�λ��������д���ĵ�ַ				
				*pData += dwImageBaseDelta;
			}
		}

		pRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocationTable + pRelocationTable->SizeOfBlock);
	}
	// �޸� ImageBase
	pOptionHeader->ImageBase = dwNewImageBase;
}

// �����ݼ��ܺ���ӵ���������
// �����»������Ĵ�С��ʧ�ܷ���0
// ������ݽ�ǰN���ֽ���һ��ʮ�����ַ�������ʾ���ݴ�С����NULL����
DWORD WriteEncryptedDataToNewSection(LPVOID pFileBuffer, DWORD dwFileBufferSize, LPVOID *pNewFileBuffer, LPVOID pData, DWORD dwDataSize)
{
	// ����һ�� pFileBuffer����Ҫ�޸�ԭ��������
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
	PWORD pNumberOfSections = &(pPEHeader->NumberOfSections); // �ڵ�����
	PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeader + *pNumberOfSections - 1; // ���һ���ڱ�
	PIMAGE_SECTION_HEADER pNewSectionHeader = pSectionHeader + *pNumberOfSections; // �½ڱ�����
	DWORD newFileBufferSize = 0; // ���ļ��Ĵ�С

	// �ж����һ���ڱ�����Ƿ��п��е�80�ֽ�
	if (80 > (DWORD)pFileBuffer + pOptionHeader->SizeOfHeaders - (DWORD)pNewSectionHeader)
	{
		printf("û���㹻��80�ֽڲ����½ڱ�\n");
		free(pFileBuffer);
		return 0;
	}
	// �жϿ��е�80�ֽ��Ƿ�ȫΪ0��������ǣ��������NTͷ����Ų����dos stub�Կճ��ռ����ڱ�
	for (int i = 0; i < 80; i++)
	{
		if (((PBYTE)pNewSectionHeader)[i] != 0)
		{
			DWORD dwRet = MoveNTHeaderAndSectionHeadersToDosStub(pFileBuffer);
			printf("�ڱ�ռ䲻�㣬NTͷ�ͽڱ���͵�ַ�ƶ��� %d �ֽ�\n", dwRet);
			if (dwRet < 80)
			{
				printf("�ƶ�����û���㹻��80�ֽڿռ�����½ڱ�\n");
				free(pFileBuffer);
				return 0;
			}
			// ����ָ��
			pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
			pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
			pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
			pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
			pNumberOfSections = &(pPEHeader->NumberOfSections); // �ڵ�����
			pLastSectionHeader = pSectionHeader + *pNumberOfSections - 1; // ���һ���ڱ�
			pNewSectionHeader = pSectionHeader + *pNumberOfSections; // �½ڱ�����
			break;
		}
	}
	// �������ݴ�С���
	char sSizeFlag[100] = { 0 };
	sprintf(sSizeFlag, "%d", dwDataSize);
	DWORD dwFlagLen = strlen(sSizeFlag) + 1; // �������Ȱ���NULL

	// ����һ�� IMAGE_SECTION_HEADER �ṹ���������������
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

	// pNewFileBuffer �����ڴ棬�� pFileBuffer ���ƹ�ȥ��������޸Ķ��� pNewFileBuffer ����	
	*pNewFileBuffer = malloc(dwFileBufferSize + newSectionHeader.SizeOfRawData);
	memcpy(*pNewFileBuffer, pFileBuffer, dwFileBufferSize);
	memset((LPVOID)((DWORD)*pNewFileBuffer + dwFileBufferSize), 0, newSectionHeader.SizeOfRawData); // ������������0

	// ����ָ�룬ָ�����ڴ�	
	pDosHeader = (PIMAGE_DOS_HEADER)*pNewFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	pNumberOfSections = &(pPEHeader->NumberOfSections);
	pLastSectionHeader = pSectionHeader + *pNumberOfSections - 1;
	pNewSectionHeader = pSectionHeader + *pNumberOfSections;

	// �ڵ�����+1��SizeOfImage���ڴ��������Ĵ�С
	*pNumberOfSections += 1;
	pOptionHeader->SizeOfImage += Align(newSectionHeader.Misc.VirtualSize, pOptionHeader->SectionAlignment);

	// ���� newSectionHeader
	memcpy(pNewSectionHeader, &newSectionHeader, sizeof(newSectionHeader));

	// �������ݵ�������
	LPVOID pNewSec = (LPVOID)((DWORD)*pNewFileBuffer + (DWORD)(pSectionHeader[*pNumberOfSections - 1].PointerToRawData));
	memcpy(pNewSec, sSizeFlag, dwFlagLen);
	NaiveEncrypt(pData,dwDataSize,"hambaga",strlen("hambaga"));
	memcpy((LPVOID)((PBYTE)pNewSec + dwFlagLen), pData, dwDataSize);

	//printf("����ɹ�\n");
	free(pFileBuffer);
	return dwFileBufferSize + newSectionHeader.SizeOfRawData;
}

// �����һ�������ȡ���ݣ������ܣ��������ݴ�С
// ���һ�������ֱ�����.encsrc����ͷN���ֽڱ�����ʮ�������ַ�����NULL��β����ʾ����������ֽ���
// *pData ����������ݣ���������ͷ��С���
DWORD ReadEncryptedDataFromLastSection(LPVOID pFileBuffer, DWORD dwFileBufferSize, LPVOID *pData)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	PWORD pNumberOfSections = &(pPEHeader->NumberOfSections); // �ڵ�����
	PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeader + *pNumberOfSections - 1; // ���һ���ڱ�
	if (memcmp(".encsrc", pLastSectionHeader->Name, 8) != 0)
	{
		printf("������Ч�ļ��ܳ���\n");
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

