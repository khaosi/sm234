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

#include "sm.h" 
#include "sm2.h" 
#include "sm3.h" 
#include "sm4.h" 



   
void TraceBuf(unsigned char *string, unsigned int length)
{
	unsigned int i = 0;

	while (i < length)
	{
		TRACE("%02x ", *(string + i));
		i++;

		if (i % 16 == 0)
		{
			TRACE("\r\n");
		}
	}

	TRACE("\r\n");
}

void TraceStrBuf(char * str, unsigned char *ucHex, unsigned int length)
{
	unsigned int i = 0;

	TRACE("%s: \r\n", str);

	while (i < length)
	{
		TRACE("%02x ", *(ucHex + i));
		i++;

		if (i % 16 == 0)
		{
			TRACE("\r\n");
		}
	}

	TRACE("\r\n");
}
#define TRACEBUF	TraceBuf    
#define TRACESTRBUF	TraceStrBuf   

//-----------------------------------------------------------------------------
// Function Name  : AlgSm3
// Description    : 
// Input          : 
// Output         : 
// Return         : 
// Notice         : 
//-----------------------------------------------------------------------------
int AlgSm3(char* pIn, unsigned int uiLen, char* pHash, char ucMode)
{
	SM3_256(pIn, uiLen, pHash);
	return TRUE;
}

//-----------------------------------------------------------------------------
// Function Name  : AlgSm3
// Description    : 
// Input          : 
// Output         : 
// Return         : 
// Notice         : 屏蔽部分是调试CBC时使用的
//-----------------------------------------------------------------------------
void sm4cbc(char *pVi, char *input, unsigned int uiLen, char *pKey, char *output, char mode)
{
	int i;
	unsigned int uiLength;
	unsigned char temp[16];

	char acVi[16];
	//char acinput[0x40];
	//char acoutput[0x40];	
	//
	//char *input = acinput;
	//char *output = acoutput;



	//memmove(acinput, pinput, uiLen);


	uiLength = uiLen;
	memmove(acVi, pVi, 16);
	if (SMS4_ENCRYPT == mode)
	{
		while (uiLength > 0)
		{

			//TRACESTRBUF("acVi", acVi, 16);
			for (i = 0; i < 16; i++)
				input[i] = (input[i] ^ acVi[i]);

			//if (uiLength == 64)
			//{
			//	TRACE("64\r\n");
			//	TRACESTRBUF("acinput1", acinput, 64);
			//}

			//if (uiLength == 48)
			//{
			//	TRACE("48\r\n");
			//	TRACESTRBUF("acinput2", acinput, 64);
			//}
			//
			//if (uiLength == 32)
			//{
			//	TRACE("32\r\n");
			//	TRACESTRBUF("acinput3", acinput, 64);
			//}

			//if (uiLength == 16)
			//{
			//	TRACE("16\r\n");
			//	TRACESTRBUF("acinput4", acinput, 64);
			//}

			SM4_Encrypt(pKey, input, output);

			//if (uiLength == 64)
			//{
			//	TRACE("64\r\n");
			//	TRACESTRBUF("output1", acoutput, 64);
			//}				
			//
			//if (uiLength == 48)
			//{
			//	TRACE("48\r\n");
			//	TRACESTRBUF("output2", acoutput, 64);
			//}			
			//
			//if (uiLength == 32)
			//{
			//	TRACE("32\r\n");
			//	TRACESTRBUF("output3", acoutput, 64);
			//}

			//if (uiLength == 16)
			//{
			//	TRACE("16\r\n");
			//	TRACESTRBUF("output4", acoutput, 64);
			//}

			memmove(acVi, output, 16);
			input += 16;
			output += 16;
			uiLength -= 16;
		}
		//memmove(poutput, acoutput, sizeof(acoutput));
	}
	else
	{
		while (uiLength > 0)
		{
			memcpy(temp, input, 16);
			SM4_Decrypt(pKey, input, output);

			for (i = 0; i < 16; i++)
				output[i] = (char)(output[i] ^ pVi[i]);

			memcpy(pVi, temp, 16);

			input += 16;
			output += 16;
			uiLength -= 16;
		}
		//memmove(poutput, acoutput, sizeof(acoutput));
	}
}


//-----------------------------------------------------------------------------
// Function Name  : AlgSm4
// Description    : 
// Input          : 
// Output         : 
// Return         : 
// Notice         : 
//-------+------+------+------+------+------+------+------+------+--------+
// Mode: |Bit7  |Bit6  |Bit5  |Bit4  |Bit3  |Bit2  |Bit1  |Bit0  |描述   |
//-------+------+------+------+------+------+------+------+------+--------+
//		 |      |      |      |      |      |      |      |0     |加密模式 |
//		 |      |      |      |      |      |      |      |1     |解密模式 |
//-------+------+------+------+------+------+------+------+------+--------+
//		 |      |      |      |      |      |      |0     |      |ECB模式 |
//		 |      |      |      |      |      |      |1     |      |CBC模式 |
//-------+------+------+------+------+------+------+------+------+--------+
//-----------------------------------------------------------------------------
int AlgSm4(char *pVi, char *pKey, char *pIn, unsigned int uiLen, char *pOut, char ucMode)
{
	char cEnDe, cEcbCbc;
	unsigned int iLength;

	//不支持填充，明文密文必须是8的倍数
	if (uiLen % 16)
	{
		return FALSE;
	}

	iLength = uiLen;

	//ECB模式和CBC模式
	if (ucMode & BIT01)
	{
		//CBC模式下，必需有初始向量传入
		if (NULL ==  pVi)
		{
			return FALSE;
		}
		cEcbCbc = 1;
	}
	else
	{
		cEcbCbc = 0;
	}

	//加解密模式
	if (ucMode & BIT00)
	{
		cEnDe = 1;//解密
	}
	else
	{
		cEnDe = 0;//加密
	}

	if (cEcbCbc == 1)
	{
		if (cEnDe)
		{
			sm4cbc(pVi, pIn, iLength, pKey, pOut, SMS4_DECRYPT);
		}
		else
		{
			sm4cbc(pVi, pIn, iLength, pKey, pOut, SMS4_ENCRYPT);
		}

	}
	else  //ecb
	{
		if (cEnDe)
		{
			while (iLength > 0)
			{
				SM4_Decrypt(pKey, pIn, pOut);
				pIn += 16;
				pOut += 16;
				iLength -= 16;
			}
		}
		else
		{
			while (iLength > 0)
			{
				SM4_Encrypt(pKey, pIn, pOut);
				pIn += 16;
				pOut += 16;
				iLength -= 16;
			}
		}
	}

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
int AlgSm2Keygen(char *pSm2PriK, char *pSm2PubK)
{
	char Px[SM2_NUMWORD];
	char Py[SM2_NUMWORD];

	if (0 != SM2_KeyGeneration(pSm2PriK, &Px, &Py))
	{
	
		return FALSE;
	}

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
int AlgSm2Encrypt(char *pIn, unsigned short *pusLen, char *pOut, char *pSm2PubK)
{
	//char acRandK[SM2_NUMWORD];//todo
	unsigned  char acRandK[32] = { 0x59,0x27,0x6E,0x27,0xD5,0x06,0x86,0x1A,0x16,0x68,0x0F,0x3A,0xD9,0xC0,0x2D,0xCC,0xEF,0x3C,0xC1,0xFA,0x3C,0xDB,0xE4,0xCE,0x6D,0x54,0xB8,0x0D,0xEA,0xC1,0xBC,0x21 };

	epoint *stPubKey;
	big  ks, x, y;
	char acInTmp[0x200];//todo gx 库存在一定问题，这里需要大一点
	char acOutTmp[0x200];//todo gx 库存在一定问题，这里需要大一点

	if (NULL == pOut || NULL == pSm2PubK ||*pusLen > 0x100)
	{
		return FALSE;
	}

	//initiate  SM2  curve 
	if (0 != SM2_Init())
	{
		return FALSE;
	}

	x = mirvar(0);
	y = mirvar(0);
	stPubKey = epoint_init();

	bytes_to_big(SM2_NUMWORD, pSm2PubK, x);
	bytes_to_big(SM2_NUMWORD, pSm2PubK + 32, y);

	epoint_set(x, y, 1, stPubKey);
	memmove(acInTmp, pIn, *pusLen);

	if (0 != SM2_Encrypt(acRandK, stPubKey, &acInTmp, *pusLen, &acOutTmp))
	{
		return FALSE;
	}
	//TRACESTRBUF("acOutTmp", acOutTmp, sizeof(acOutTmp));
	*pusLen = *pusLen + SM2_NUMWORD*3;
	memmove(pOut, acOutTmp, *pusLen);

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
int AlgSm2Decrypt(char *pIn, unsigned short *pusLen, char *pOut, char *pSm2PriK)
{
	big  dB;
	char acCipher[0x200];//todo gx 库存在一定问题，这里需要大一点
	char acPlain[0x200];//todo gx 库存在一定问题，这里需要大一点

	if (NULL == pOut || NULL == pSm2PriK || *pusLen > 0x180)
	{
		return FALSE;
	}

	//initiate  SM2  curve 
	if (0 != SM2_Init())
	{
		return FALSE;
	}

	dB = mirvar(0);

	bytes_to_big(SM2_NUMWORD, pSm2PriK, dB);
	TRACE("*pusLen = %d \r\n", *pusLen);
	memmove(acCipher, pIn, *pusLen);
	if (0 != SM2_Decrypt(dB, &acCipher, *pusLen, &acPlain))
	{
		return FALSE;
	}

	*pusLen = *pusLen - SM2_NUMWORD*3;
	memmove(pOut, acPlain, *pusLen);

	return TRUE;
}

//-----------------------------------------------------------------------------
// Function Name  : AlgSm2Sign
// Description    : 
// Input          : 
// Output         : 
// Return         : 
// Notice         : 
//-----------------------------------------------------------------------------
int AlgSm2Sign(char *pInHash, char ucLen, char *pOut, char *pSm2PriK)
{
	char acRandK[32] = { 0x59,0x27,0x6E,0x27,0xD5,0x06,0x86,0x1A,0x16,0x68,0x0F,0x3A,0xD9,0xC0,0x2D,0xCC,0xEF,0x3C,0xC1,0xFA,0x3C,0xDB,0xE4,0xCE,0x6D,0x54,0xB8,0x0D,0xEA,0xC1,0xBC,0x21 };
	char r[64], s[64];//  Signature
	char inLen;

	inLen = ucLen;

	if (0 != SM2_Sign_With_E(pInHash, acRandK, pSm2PriK, r, s))
	{
		return FALSE;
	}

	memmove(pOut, r, SM2_NUMWORD);
	memmove(pOut + SM2_NUMWORD, s, SM2_NUMWORD);
	
	return TRUE;
}

//-----------------------------------------------------------------------------
// Function Name  : AlgSm2Verify
// Description    : 
// Input          : 
// Output         : 
// Return         : 
// Notice         : 
//-----------------------------------------------------------------------------
int AlgSm2Verify(char *pInHash, char *pucSign, char *pSm2PubK)
{
	if (0 != SM2_Verify_With_E(pInHash, pSm2PubK, pSm2PubK+ SM2_NUMWORD, pucSign, pucSign + SM2_NUMWORD))
	{
		return FALSE;
	}	

	return TRUE;
}


//-----------------------------------------------------------------------------
// Function Name  : SAHexStrToByte
// Description    : 
// Input          : 
// Output         : 
// Return         : 
// Notice         : 
//-----------------------------------------------------------------------------
static int SAHexStrToByte(const char* source, char* dest, unsigned int sourceLen)
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
	return 0;
}


#define SM3_RAW	"05949C1519970E6D65383D69B9566E48014B0B31FAAE9CB3F149424C50554363"
#define SM3_RET	"354B629BE0397BAD992CF2F727464C9ED242287EB29C636CBF0385501DB3719A"

//#define SM3_RAW	"E44DB17360DCA5290960705CDA62E58D0132FB5B23F4003DBD3B6970ECEB5BE7D6848582ACE108EC6D2EC1CCA96698CFEDA38042A47F51B593D361569A8BAA905338BEB9052949C0CE20F572FAACD3AA4CEF251174E8623728D4DA9CAF723FF9C5D6ABFC341AD6DEAF160694808C5E4B2A387BB005769DBB5B95D62865DB0732498A2D0F23010F7FD02AC5FDD3AE1C8CBBFE05A36B6341998A7CED4311300B5F"
//#define SM3_RET "B861FB9C7B979F1C1FB1CCE56FDC3F50E7B1081B17F1B701446E5C9EA3D8D75C"

#define SM2_PRIK "349D4BA7F3D3FF906BE9F2C10DB41925039CF22FC6B8FF9D677FAF53031750C4"
#define SM2_PUBK "CB4A668E60E74E42D15FFC4205ADA1500DB946B1C3CBF3EE183AB799108A0AC4A57D290FE62A660BCC84F66CA2B12A8D976EAE23E2D0EDBEAB051748E12F1D0D"
#define SM2_PLAIN "89F8F6CE7CB63189E25190CE2150157073BCE2E07D9340FFEFAD73111CF20A7504B8E833C62DCA33355E6260E8BECD20CC64EFB7D49D1CBE4D783293F662EDD4"
#define SM2_CIPHER "E44DB17360DCA5290960705CDA62E58D0132FB5B23F4003DBD3B6970ECEB5BE7D6848582ACE108EC6D2EC1CCA96698CFEDA38042A47F51B593D361569A8BAA905338BEB9052949C0CE20F572FAACD3AA4CEF251174E8623728D4DA9CAF723FF9C5D6ABFC341AD6DEAF160694808C5E4B2A387BB005769DBB5B95D62865DB0732498A2D0F23010F7FD02AC5FDD3AE1C8CBBFE05A36B6341998A7CED4311300B5F"


#define SM4_KEY "FF1F1D3C6E4D30C43AB1F539E9545815"

#define SM4_ECB_PLAINT "E21CC75FAA71E38C26AD7130224305C6B1BA8EF08CA4ABDA65BC1F7CAD834D6A169E28F354819878866A6CC8F403F7417F71C348F4B857364C6443D8F50A4FDE"
#define SM4_ECB_CIPHER "8CAA02F0ABA1D37C116059C2C0F005342409FA3DBAFC55DFE6DD25171B9CFC7513856325171FB3D0B76E579994B2353A75527A19F11398232CB6DCE0096C430A"

#if 1
#define SM4_CBC_VI "89F0B9D88762670071722ECED7D5EA08"
#define SM4_CBC_PLAINT "25962B7C21FBDD436B92A060C6845BC07FC05F7B60B793AB7B404CBAAE5CC2FEEDD9E936BA049D3BEFF00320BFE619328DF246A3A35432D817FC7AB97A37E05D"
#define SM4_CBC_CIPHER "11BD132D1A6C35DE5D69DF9ABE53316FCE9D7EACEE125B0FF10FD12D1A863038D6062922984083A303237EF1857610AEDFE24BE97D6AEF50D4250A214CB14AEC"
#else
#define SM4_CBC_VI "00000000000000000000000000000000"
#define SM4_CBC_PLAINT "25962B7C21FBDD436B92A060C6845BC07FC05F7B60B793AB7B404CBAAE5CC2FEEDD9E936BA049D3BEFF00320BFE619328DF246A3A35432D817FC7AB97A37E05D"
#define SM4_CBC_CIPHER "C0A42B722EC314DDC006EE3BE9BF8BAFF60DA86F7135C32B5EED7DC9C55E8B82224B92636188959608057B15B0119F91530F8A9208FE09C576305033B345BC11"
#endif


//-----------------------------------------------------------------------------
// Function Name  : AlgSmTest
// Description    : 
// Input          : 
// Output         : 
// Return         : =0 pass ; !=0 error
// Notice         : 
//-----------------------------------------------------------------------------
int AlgSmTest(int iMode)
{
	int iRet;
	int iBack;

	char Sm2PriK[SM2_NUMWORD];
	char Sm2PubK[SM2_NUMWORD + SM2_NUMWORD];
	char SM2PubkTmp[SM2_NUMWORD + SM2_NUMWORD];

	char acTmp[0x200];
	char acHash[0x20];
	char acHashTmp[0x20];

	char acSm2Plain[64];
	char acSm2PlainTmp[64];
	unsigned short usPlainLen;

	char acSm2Cipher[64+96];
	unsigned short usCipherLen;

	char acSm2Sign[0x40];

	char acSm4Plain[0x40];
	char acSm4PlainTmp[0x40];
	char acSm4Cipher[0x40];
	char acSm4Key[0x10];
	char acSm4CbcVi[0x10];

	iBack = 0;

	MirsysInit();

	if (iMode & BIT00)
	{
		//sm3
		SAHexStrToByte(SM3_RAW, acTmp, strlen(SM3_RAW));
		iRet = AlgSm3(&acTmp, 32, acHash, 0);
		SAHexStrToByte(SM3_RET, acTmp, strlen(SM3_RET));
		if (!iRet || 0 != memcmp(acHash, acTmp, 32))
		{
			TRACE("AlgSm3 Fail!!! \r\n");
			iBack |= BIT00;
		}
		else
		{
			TRACE("AlgSm3 Pass !!! \r\n");
		}
	}

	if (iMode & BIT01)
	{
		//sm2 generator key
		SAHexStrToByte(SM2_PRIK, Sm2PriK, strlen(SM2_PRIK));
		iRet = AlgSm2Keygen(&Sm2PriK, &Sm2PubK);
		SAHexStrToByte(SM2_PUBK, SM2PubkTmp, strlen(SM2_PUBK));
		if (!iRet || 0 != memcmp(Sm2PubK, SM2PubkTmp, 64))
		{
			TRACE("AlgSm2Keygen Fail!!! \r\n");
			iBack |= BIT01;
		}
		else
		{
			TRACE("AlgSm2Keygen Pass !!! \r\n");
		}
	}

	if (iMode & BIT02)
	{
		//sm2 en&de
		SAHexStrToByte(SM2_PRIK, Sm2PriK, strlen(SM2_PRIK));
		SAHexStrToByte(SM2_PUBK, Sm2PubK, strlen(SM2_PUBK));
		SAHexStrToByte(SM2_PLAIN, acSm2Plain, strlen(SM2_PLAIN));

		usPlainLen = sizeof(acSm2Plain);
		TRACESTRBUF("Sm2PriK", Sm2PriK, sizeof(Sm2PriK));
		TRACESTRBUF("Sm2PubK", Sm2PubK, sizeof(Sm2PubK));
		TRACESTRBUF("acSm2Plain", acSm2Plain, sizeof(acSm2Plain));


		iRet = AlgSm2Encrypt(acSm2Plain, &usPlainLen, acSm2Cipher, Sm2PubK);
		if (!iRet)
		{
			TRACE("AlgSm2Encrypt Fail!!! \r\n");
			iBack |= BIT02;
		}
		else
		{
			TRACE("AlgSm2Encrypt Pass !!! \r\n");
		}

		usCipherLen = usPlainLen;
		TRACE("usCipherLen = %d \r\n", usCipherLen);
		TRACESTRBUF("acSm2Cipher", acSm2Cipher, sizeof(acSm2Cipher));


		iRet = AlgSm2Decrypt(acSm2Cipher, &usCipherLen, acSm2PlainTmp, Sm2PriK);
		TRACESTRBUF("acSm2PlainTmp", acSm2PlainTmp, sizeof(acSm2PlainTmp));
		if (!iRet || 0 != memcmp(acSm2Plain, acSm2PlainTmp, usCipherLen))
		{
			TRACE("AlgSm2Decrypt Fail!!! \r\n");
			iBack |= BIT02;
		}
		else
		{
			TRACE("AlgSm2Decrypt Pass !!! \r\n");
		}
	}

	if (iMode & BIT03)
	{
		//sm2 sign&verify
		SAHexStrToByte(SM2_PRIK, Sm2PriK, strlen(SM2_PRIK));
		SAHexStrToByte(SM2_PUBK, Sm2PubK, strlen(SM2_PUBK));
		SAHexStrToByte(SM2_PLAIN, acSm2Plain, strlen(SM2_PLAIN));
		SAHexStrToByte(SM3_RET, acHash, strlen(SM3_RET));


		iRet = AlgSm2Sign(acHash, 0, acSm2Sign, Sm2PriK);
		TRACESTRBUF("acSm2Sign", acSm2Sign, sizeof(acSm2Sign));
		if (!iRet)
		{
			TRACE("AlgSm2Sign Fail!!! \r\n");
			iBack |= BIT03;
		}
		else
		{
			TRACE("AlgSm2Sign Pass !!! \r\n");
		}

		//true sign
		iRet = AlgSm2Verify(acHash, acSm2Sign, Sm2PubK);
		if (!iRet)
		{
			TRACE("AlgSm2Verify Fail 1 !!! \r\n");
			iBack |= BIT03;
		}
		else
		{
			TRACE("AlgSm2Verify Pass 1 !!! \r\n");
		}

		//fake sign
		SAHexStrToByte(SM3_RAW, acHash, strlen(SM3_RAW));
		iRet = AlgSm2Verify(acHash, acSm2Sign, Sm2PubK);
		if (iRet)
		{
			TRACE("AlgSm2Verify Fail 2 !!! \r\n");
			iBack |= BIT03;
		}
		else
		{
			TRACE("AlgSm2Verify Pass 2 !!! \r\n");
		}
	}


	//sm4
	if (iMode & BIT04)//ecb
	{
		SAHexStrToByte(SM4_ECB_PLAINT, acSm4Plain, strlen(SM4_ECB_PLAINT));
		SAHexStrToByte(SM4_ECB_CIPHER, acSm4PlainTmp, strlen(SM4_ECB_CIPHER));
		SAHexStrToByte(SM4_KEY, acSm4Key, strlen(SM4_KEY));

		iRet = AlgSm4(NULL, acSm4Key, acSm4Plain, sizeof(acSm4Plain), acSm4Cipher, SMS4_ECB_MODE | SMS4_ENCRYPT);
		TRACESTRBUF("acSm4Cipher", acSm4Cipher, sizeof(acSm4Cipher));
		if (!iRet || 0!= memcmp(acSm4Cipher, acSm4PlainTmp, sizeof(acSm4Cipher)))
		{
			TRACE("AlgSm4 ECB EN Fail!!! \r\n");
			iBack |= BIT04;
		}
		else
		{
			TRACE("AlgSm4 ECB EN Pass !!! \r\n");
		}

		SAHexStrToByte(SM4_ECB_PLAINT, acSm4PlainTmp, strlen(SM4_ECB_PLAINT));
		memset(acSm4Plain, 0, sizeof(acSm4Plain));
		iRet = AlgSm4(NULL, acSm4Key, acSm4Cipher, sizeof(acSm4Cipher), acSm4Plain, SMS4_ECB_MODE | SMS4_DECRYPT);
		TRACESTRBUF("acSm4Plain", acSm4Plain, sizeof(acSm4Plain));
		if (!iRet || 0 != memcmp(acSm4Plain, acSm4PlainTmp, sizeof(acSm4Plain)))
		{
			TRACE("AlgSm4 ECB DE Fail!!! \r\n");
			iBack |= BIT04;
		}
		else
		{
			TRACE("AlgSm4 ECB DE Pass !!! \r\n");
		}
	}

	if (iMode & BIT05)
	{
		//cbc
		SAHexStrToByte(SM4_CBC_PLAINT, acSm4Plain, strlen(SM4_CBC_PLAINT));
		SAHexStrToByte(SM4_KEY, acSm4Key, strlen(SM4_KEY));
		SAHexStrToByte(SM4_CBC_VI, acSm4CbcVi, strlen(SM4_CBC_VI));
		SAHexStrToByte(SM4_CBC_CIPHER, acSm4PlainTmp, strlen(SM4_CBC_CIPHER));


		iRet = AlgSm4(acSm4CbcVi, acSm4Key, acSm4Plain, sizeof(acSm4Plain), acSm4Cipher, SMS4_CBC_MODE | SMS4_ENCRYPT);
		TRACESTRBUF("acSm4Cipher", acSm4Cipher, sizeof(acSm4Cipher));
		if (!iRet || 0 != memcmp(acSm4Cipher, acSm4PlainTmp, sizeof(acSm4Cipher)))
		{
			TRACE("AlgSm4 CBC EN Fail!!! \r\n");
			iBack |= BIT05;
		}
		else
		{
			TRACE("AlgSm4 CBC EN Pass !!! \r\n");
		}

		SAHexStrToByte(SM4_CBC_PLAINT, acSm4PlainTmp, strlen(SM4_CBC_PLAINT));
		memset(acSm4Plain, 0, sizeof(acSm4Plain));
		iRet = AlgSm4(acSm4CbcVi, acSm4Key, acSm4Cipher, sizeof(acSm4Cipher), acSm4Plain, SMS4_CBC_MODE | SMS4_DECRYPT);
		TRACESTRBUF("acSm4Plain", acSm4Plain, sizeof(acSm4Plain));
		if (!iRet || 0 != memcmp(acSm4PlainTmp, acSm4Plain, sizeof(acSm4PlainTmp)))
		{
			TRACE("AlgSm4 CBC DE Fail!!! \r\n");
			iBack |= BIT05;
		}
		else
		{
			TRACE("AlgSm4 CBC DE Pass !!! \r\n");
		}
	}

	return iBack;
}


