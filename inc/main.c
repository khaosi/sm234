#include "stdio.h"
#include  "sm3.h"
#include  "sm4.h"


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