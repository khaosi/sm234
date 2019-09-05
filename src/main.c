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
#include "sm.h"


int main(int argc, char **argv)
{
    int iResult;

	//todo miracl需要初始化
#if 1
    iResult = SM3_SelfTest();

    TRACE("#SM3_SelfTest = %08x \r\n", iResult);

	iResult = SM4_SelfTest();

	TRACE("#SM4_SelfTest = %08x \r\n", iResult);	
	
	
	iResult = SM2_EnDeTest();

	TRACE("#SM2_EnDeTest = %08x \r\n", iResult);	
	
	
	iResult = SM2_SignVerifyTest();

	TRACE("#SM2_SignVerifyTest = %08x \r\n", iResult);
#endif

	iResult = AlgSmTest(BIT00| BIT01| BIT02| BIT03| BIT04| BIT05);
	if (0 == iResult)
	{
		TRACE("\r\n#SM Selftest Pass!!!\r\n");
	}
	else
	{
		TRACE("\r\n#SM Selftest Fail!!!\r\n");
	}

    TRACE("\r\nPress anykey to continue\r\n");

    getchar();

    return 0;
}