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

#ifndef DLL_ENABLE
int main(int argc, char **argv)
{
    int iResult;

	//todo miracl init
	MirsysInit();

	//SM_SelfTest();

	iResult = AlgSmTest(BIT00| BIT01| BIT02| BIT03| BIT04| BIT05);
	if (0 == iResult)
	{
		TRACE("\r\n# SM AlgSmTest Pass!!!\r\n");
	}
	else
	{
		TRACE("\r\n# ERR:SM AlgSmTest Fail!!!\r\n");
	}

    TRACE("\r\nPress anykey to continue\r\n");

    getchar();

    return 0;
}
#endif