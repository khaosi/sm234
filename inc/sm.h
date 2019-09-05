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

//TEST
int SM4_SelfTest();
int SM2_SignVerifyTest();
int SM2_EnDeTest();
int SM3_SelfTest();

int AlgSmTest(void);
//API

int AlgSm3(char * pIn, unsigned int uiLen, char * pHash, char ucMode);
int AlgSm4(char * pVi, char * pKey, char * pIn, unsigned int uiLen, char * pOut, char ucMode);
int AlgSm2Keygen(char * pSm2PriK, char * pSm2PubK);
int AlgSm2Encrypt(char * pIn, unsigned short * pusLen, char * pOut, char * pSm2PubK);
int AlgSm2Decrypt(char * pIn, unsigned short * pusLen, char * pOut, char * pSm2PriK);
int AlgSm2Sign(char * pInHash, char ucLen, char * pOut, char * pSm2PriK);
int AlgSm2Verify(char * pInHash, char * pucSign, char * pSm2PubK);

#endif


