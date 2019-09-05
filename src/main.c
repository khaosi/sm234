/**
*@file		main.c
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

#include <stdio.h>
#include "../inc/sm3.h"
#include "../inc/sm4.h"
#include "../inc/sm2.h"
#include "../inc/miracl.h"

extern BOOL AlgSmTest(void);

int main(int argc, char **argv)
{
    int iResult;

	//todo miracl需要初始化

 //   iResult = SM3_SelfTest();

 //   printf("SM3_SelfTest = %04x \r\n", iResult);

	//iResult = SM4_SelfTest();

	//printf("SM4_SelfTest = %04x \r\n", iResult);	
	//
	//
	iResult = SM2_EnDeTest();

	printf("SM2_EnDeTest = %04x \r\n", iResult);	
	//
	//
	//iResult = SM2_SignVerifyTest();

	//printf("SM2_SignVerifyTest() = %04x \r\n", iResult);

	AlgSmTest();

    printf("Press anykey to continue\r\n");

    getchar();

    return 0;
}