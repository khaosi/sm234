/**
*@file		sm.c
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

#include "../inc/sm.h" 
#include "../inc/sm2.h" 
#include "../inc/sm3.h" 
#include "../inc/sm4.h" 

#define BIT09				(0x00000200)
#define BIT08				(0x00000100)
#define BIT07				(0x00000080)
#define BIT06				(0x00000040)
#define BIT05				(0x00000020)
#define BIT04				(0x00000010)
#define BIT03				(0x00000008)
#define BIT02				(0x00000004)
#define BIT01				(0x00000002)
#define BIT00				(0x00000001)


//-----------------------------------------------------------------------------
// Function Name  : AlgSm3
// Description    : 
// Input          : 
// Output         : 
// Return         : 
// Notice         : 
//-----------------------------------------------------------------------------
BOOL AlgSm3(char* pIn, unsigned int uiLen, char* pHash, char ucMode)
{
	SM3_256(pIn, uiLen, pHash);
	return TRUE;
}

//-----------------------------------------------------------------------------
// Function Name  : AlgSm4
// Description    : 
// Input          : 
// Output         : 
// Return         : 
// Notice         : 
//-----------------------------------------------------------------------------
BOOL AlgSm4(char *pVi, char *pKey, char *pData, unsigned int uiLen, char ucMode)
{

	return TRUE;
}

//-----------------------------------------------------------------------------
// Function Name  : AlgSm2Keygen
// Description    : 
// Input          : 
// Output         : 
// Return         : 
// Notice         : 私钥靠传入
//-----------------------------------------------------------------------------
BOOL AlgSm2Keygen(char *pSm2PriK, char *pSm2PubK)
{
	char Px[SM2_NUMWORD];
	char Py[SM2_NUMWORD];
	//char PriKey[SM2_NUMWORD];

	if (0 != SM2_KeyGeneration(pSm2PriK, &Px, &Py))
	{
	
		return FALSE;
	}

	//memmove(pSm2PriK, PriKey, SM2_NUMWORD);
	memmove(pSm2PubK, Px, SM2_NUMWORD);
	memmove(pSm2PubK + SM2_NUMWORD, Py, SM2_NUMWORD);

	return TRUE;
}

//-----------------------------------------------------------------------------
// Function Name  : AlgSm2Encrypt
// Description    : 
// Input          : 
// Output         : 
// Return         : 
// Notice         : 
//-----------------------------------------------------------------------------
BOOL AlgSm2Encrypt(char *pIn, unsigned short *pusLen, char *pOut, char *pSm2PubK)
{
	//char acRandK[SM2_NUMWORD];//todo
	unsigned  char acRandK[32] = { 0x59,0x27,0x6E,0x27,0xD5,0x06,0x86,0x1A,0x16,0x68,0x0F,0x3A,0xD9,0xC0,0x2D,0xCC,0xEF,0x3C,0xC1,0xFA,0x3C,0xDB,0xE4,0xCE,0x6D,0x54,0xB8,0x0D,0xEA,0xC1,0xBC,0x21 };

	epoint *stPubKey;
	big  ks, x, y;
	char acTmp[0x200];//todo gx 库存在一定问题，这里需要大一点

	if (NULL == pOut || NULL == pSm2PubK ||*pusLen > 0x100)
	{
		return FALSE;
	}

	x = mirvar(0);
	y = mirvar(0);
	stPubKey = epoint_init();

	//initiate  SM2  curve 
	SM2_Init();

	bytes_to_big(SM2_NUMWORD, pSm2PubK, x);
	bytes_to_big(SM2_NUMWORD, pSm2PubK + 32, y);

	epoint_set(x, y, 1, stPubKey);
	//bytes_to_big(&stPubKey.X, pSm2PubK, 32);
	//bytes_to_big(&stPubKey.Y, pSm2PubK + 32, 32);
	//bgint_assign_int(&stPubKey.Z, 1);
	//stPubKey = epoint_init();
	//memmove(stPubKey->X, pSm2PubK, SM2_NUMWORD);
	//memmove(stPubKey->Y, pSm2PubK + SM2_NUMWORD, SM2_NUMWORD);
	memmove(acTmp, pIn, *pusLen);

	if (0 != SM2_Encrypt(acRandK, stPubKey, &acTmp, *pusLen, pOut))
	{
		return FALSE;
	}

	*pusLen = *pusLen + SM2_NUMWORD*3;
	memmove(pOut, acTmp, *pusLen);

	return TRUE;
}


//-----------------------------------------------------------------------------
// Function Name  : AlgSm2Decrypt
// Description    : 
// Input          : 
// Output         : 
// Return         : 
// Notice         : 
//-----------------------------------------------------------------------------
BOOL AlgSm2Decrypt(char *pIn, unsigned short *pusLen, char *pOut, char *pSm2PriK)
{
	big  dB;
	char acCipher[0x200];//todo gx 库存在一定问题，这里需要大一点
	char acPlain[0x200];//todo gx 库存在一定问题，这里需要大一点

	if (NULL == pOut || NULL == pSm2PriK || *pusLen > 0x180)
	{
		return FALSE;
	}

	dB = mirvar(0);
	//initiate  SM2  curve 
	SM2_Init();
	bytes_to_big(SM2_NUMWORD, pSm2PriK, dB);

	printf("*pusLen = %d \r\n", *pusLen);
	memmove(acCipher, pIn, *pusLen);
	if (0 != SM2_Decrypt(dB, &acCipher, *pusLen, &acPlain))
	{
		return FALSE;
	}

	*pusLen = *pusLen - SM2_NUMWORD*3;
	memmove(pOut, acPlain, *pusLen);

	return TRUE;
}

//int SM2_Sign(unsigned  char  *message, int  len, unsigned  char  ZA[], unsigned  char  rand[], unsigned char  d[], unsigned  char  R[], unsigned  char  S[]);
//int SM2_Verify(unsigned  char  *message, int  len, unsigned  char  ZA[], unsigned  char  Px[], unsigned char  Py[], unsigned  char  R[], unsigned  char  S[]);


//-----------------------------------------------------------------------------
// Function Name  : AlgSm2Sign
// Description    : 
// Input          : 
// Output         : 
// Return         : 
// Notice         : 
//-----------------------------------------------------------------------------
BOOL AlgSm2Sign(char *pIn, char ucLen, char *pOut, char *pSm2PriK)
{

	//SM2_Sign(unsigned  char  *message, int  len, unsigned  char  ZA[], unsigned  char  rand[], unsigned char  d[], unsigned  char  R[], unsigned  char  S[]);
}

//-----------------------------------------------------------------------------
// Function Name  : AlgSm2Verify
// Description    : 
// Input          : 
// Output         : 
// Return         : 
// Notice         : 
//-----------------------------------------------------------------------------
BOOL AlgSm2Verify(char *pucHash, char *pucSign, char *pSm2PubK)
{

}


//-----------------------------------------------------------------------------
// Function Name  : SAHexStrToByte
// Description    : 
// Input          : 
// Output         : 
// Return         : 
// Notice         : 
//-----------------------------------------------------------------------------
void SAHexStrToByte(const char* source, char* dest, unsigned int sourceLen)
{
	short i;
	unsigned char highByte, lowByte;

	for (i = 0; i < sourceLen; i += 2)
	{
		highByte = toupper(source[i]);
		lowByte = toupper(source[i + 1]);

		if (highByte > 0x39)
		{
			highByte -= 0x37;
		}
		else
		{
			highByte -= 0x30;
		}

		if (lowByte > 0x39)
		{
			lowByte -= 0x37;
		}
		else
		{
			lowByte -= 0x30;
		}

		dest[i / 2] = (highByte << 4) | lowByte;
	}
	
}

#define SM3_RAW	"05949C1519970E6D65383D69B9566E48014B0B31FAAE9CB3F149424C50554363"
#define SM3_RET	"354B629BE0397BAD992CF2F727464C9ED242287EB29C636CBF0385501DB3719A"

#define SM2_PRIK "349D4BA7F3D3FF906BE9F2C10DB41925039CF22FC6B8FF9D677FAF53031750C4"
#define SM2_PUBK "CB4A668E60E74E42D15FFC4205ADA1500DB946B1C3CBF3EE183AB799108A0AC4A57D290FE62A660BCC84F66CA2B12A8D976EAE23E2D0EDBEAB051748E12F1D0D"
#define SM2_PLAIN "6F9D8F5F8B9C5B2C99D328A39D39ACB43EBC1237BC37EDF9FA2072EB76D415F7398A068A4E6AB64A833F39445ED382FA80DBC93FA74B7D0F377794D3FA730263"
#define SM2_CIPHER "E44DB17360DCA5290960705CDA62E58D0132FB5B23F4003DBD3B6970ECEB5BE7D6848582ACE108EC6D2EC1CCA96698CFEDA38042A47F51B593D361569A8BAA905338BEB9052949C0CE20F572FAACD3AA4CEF251174E8623728D4DA9CAF723FF9C5D6ABFC341AD6DEAF160694808C5E4B2A387BB005769DBB5B95D62865DB0732498A2D0F23010F7FD02AC5FDD3AE1C8CBBFE05A36B6341998A7CED4311300B5F"

BOOL AlgSmTest(void)
{
	BOOL bRet;

	char Sm2PriK[SM2_NUMWORD];
	char Sm2PubK[SM2_NUMWORD + SM2_NUMWORD];
	char SM2PubkTmp[SM2_NUMWORD + SM2_NUMWORD];

	char acTmp[0x100];
	char acHash[0x20];

	char acSm2Plain[64];
	char acSm2PlainTmp[64];
	unsigned short usPlainLen;

	char acSm2Cipher[64+96];
	unsigned short usCipherLen;

	MirsysInit();

	//sm3
	SAHexStrToByte(SM3_RAW, acTmp, strlen(SM3_RAW));
	bRet = AlgSm3(&acTmp, 32, acHash, 0);
	SAHexStrToByte(SM3_RET, acTmp, strlen(SM3_RET));
	if(!bRet || 0!= memcmp(acHash, acTmp,32))
	{
		printf("AlgSm3 Fail!!! \r\n");
	}

	//sm2 generator key
	SAHexStrToByte(SM2_PRIK, Sm2PriK, strlen(SM2_PRIK));
	bRet = AlgSm2Keygen(&Sm2PriK, &Sm2PubK);
	SAHexStrToByte(SM2_PUBK, SM2PubkTmp, strlen(SM2_PUBK));
	if (!bRet || 0 != memcmp(Sm2PubK, SM2PubkTmp, 64))
	{
		printf("AlgSm2Keygen Fail!!! \r\n");
	}

	//sm2 en&de
	SAHexStrToByte(SM2_PRIK, Sm2PriK, strlen(SM2_PRIK));
	SAHexStrToByte(SM2_PUBK, Sm2PubK, strlen(SM2_PUBK));

	SAHexStrToByte(SM2_PLAIN, acSm2Plain, strlen(SM2_PLAIN));

	usPlainLen = sizeof(acSm2Plain);
	bRet = AlgSm2Encrypt(acSm2Plain, &usPlainLen, acSm2Cipher, Sm2PubK);
	if (!bRet)
	{
		printf("AlgSm2Encrypt Fail!!! \r\n");
	}	
	
	usCipherLen = usPlainLen;
	printf("usCipherLen = %d \r\n", usCipherLen);
	bRet = AlgSm2Decrypt(acSm2Cipher, &usCipherLen, acSm2PlainTmp, Sm2PriK);
	if (!bRet || 0 != memcmp(acSm2Plain, acSm2PlainTmp, usCipherLen))
	{
		printf("AlgSm2Encrypt Fail!!! \r\n");
	}

	return TRUE;
}


