// NaiveEncrypt.h: interface for the NaiveEncrypt class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_NAIVEENCRYPT_H__13A3B3C0_1823_4B41_BC9F_2791851067D2__INCLUDED_)
#define AFX_NAIVEENCRYPT_H__13A3B3C0_1823_4B41_BC9F_2791851067D2__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

unsigned char RorByte(unsigned char bData, size_t shift);
void NaiveEncrypt(void *pData, size_t byteDataLen, const void *pKey, const size_t byteKeyLen);
void NaiveDecrypt(void *pData, size_t byteDataLen, const void *pKey, const size_t byteKeyLen);

#endif // !defined(AFX_NAIVEENCRYPT_H__13A3B3C0_1823_4B41_BC9F_2791851067D2__INCLUDED_)
