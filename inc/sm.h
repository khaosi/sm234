/**
*@file		sm.h
*@brief
*
*@Author	gaoxing
*@Version   V1.00
*@Date      4-Sep-2019
*@attention
*
*@Revision
* Copyright (C) 2019, khaosi@sina.com
* All Rights Reserved.
*/
#ifndef __SM_H__
#define __SM_H__

#include <stdio.h>

//#define DLL_ENABLE

#ifdef DLL_ENABLE
#define DLL_API _declspec(dllexport)
#else
#define DLL_API
#endif

#define BIT08				(0x00000100)
#define BIT07				(0x00000080)
#define BIT06				(0x00000040)
#define BIT05				(0x00000020)
#define BIT04				(0x00000010)
#define BIT03				(0x00000008)
#define BIT02				(0x00000004)
#define BIT01				(0x00000002)
#define BIT00				(0x00000001)

//sms4
#define SMS4_ECB_MODE		0x00
#define SMS4_CBC_MODE		0x02
#define SMS4_ENCRYPT		0x00
#define SMS4_DECRYPT		0x01

#define TRACE				printf 
#define TRACEBUF			TraceBuf    
#define TRACESTRBUF			TraceStrBuf

//TEST
void TraceBuf(unsigned char * string, unsigned int length);
void TraceStrBuf(char * str, unsigned char * ucHex, unsigned int length);
int SM4_SelfTest();
int SM2_SignVerifyTest();
int SM2_EnDeTest();
int SM3_SelfTest();
int SM2_KeyEX_SelfTest();
int SM_SelfTest(void);
void MirsysInit(void);

//API
DLL_API int AlgSmTest(int iMode);
DLL_API int AlgSm3(char * pIn, unsigned int uiLen, char * pHash, char ucMode);
DLL_API int AlgGMProprocessing(unsigned char* ID, unsigned short idLen, char *pucPublicKey, char *pucData, unsigned short uiDataLen, char *pucOut);
DLL_API int AlgSm4(char * pVi, char * pKey, char * pIn, unsigned int uiLen,  char ucMode);
DLL_API int AlgSm4OnlineMac(char *pKey, char *pIn, unsigned int uiLen, char * pOut);
DLL_API int AlgSm2Keygen(char * pSm2PriK, char * pSm2PubK);
DLL_API int AlgSm2Encrypt(char * pIn, unsigned short * pusLen, char * pOut, char * pSm2PubK);
DLL_API int AlgSm2Decrypt(char * pIn, unsigned short * pusLen, char * pOut, char * pSm2PriK);
DLL_API int AlgSm2Sign(char * pInHash, char ucLen, char * pOut, char * pSm2PriK);
DLL_API int AlgSm2Verify(char * pInHash, char * pucSign, char * pSm2PubK);

#endif


