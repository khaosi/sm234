#include <stdio.h>
#include "../inc/sm3.h"
#include "../inc/sm4.h"


int main(int argc, char **argv)
{
    int iResult;

    iResult = SM3_SelfTest();

    printf("SM3_SelfTest = %04x \r\n", iResult);

	iResult = SM4_SelfCheck();

	printf("SM4_SelfCheck = %04x \r\n", iResult);

    printf("Press anykey to continue\r\n");

    getchar();
    return 0;
}