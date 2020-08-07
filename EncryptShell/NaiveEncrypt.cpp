#include "stdafx.h"
#include "NaiveEncrypt.h"

// �ֽ�ѭ������
unsigned char RorByte(unsigned char bData, size_t shift)
{
	unsigned char temp = bData >> (8 - shift);
	bData = bData << shift;
	bData = bData | temp;
	return bData;
}

// ���ܺ�����������Կ���Ȼ��ȡ����Ȼ������3λ
void NaiveEncrypt(void *pData, size_t byteDataLen, const void *pKey, const size_t byteKeyLen)
{
    size_t uDataIndex = 0, uKeyIndex = 0;
    for (; uDataIndex < byteDataLen; uDataIndex++)
    {
        ((char *)pData)[uDataIndex] = ((char*)pData)[uDataIndex] ^ ((char *)pKey)[uKeyIndex];
		((char *)pData)[uDataIndex] = ~((char *)pData)[uDataIndex];
		RorByte(((unsigned char *)pData)[uDataIndex], 3);
		uKeyIndex++;
        if (uKeyIndex == byteKeyLen) uKeyIndex = 0;
    }	
}

// ���ܺ�����������5λ����ȡ����������Կ���
void NaiveDecrypt(void *pData, size_t byteDataLen, const void *pKey, const size_t byteKeyLen)
{
	size_t uDataIndex = 0, uKeyIndex = 0;
	for (; uDataIndex < byteDataLen; uDataIndex++)
	{
		RorByte(((unsigned char *)pData)[uDataIndex], 5);
		((char *)pData)[uDataIndex] = ~((char *)pData)[uDataIndex];
		((char *)pData)[uDataIndex] = ((char *)pData)[uDataIndex] ^ ((char *)pKey)[uKeyIndex];
		uKeyIndex++;
		if (uKeyIndex == byteKeyLen) uKeyIndex = 0;
	}
}
