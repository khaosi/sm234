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

//-----------------------------------------------------------------------------
// Function Name  : TraceBuf
// Description    : 
// Input          : 
// Output         : 
// Return         : 
// Notice         : 
//-----------------------------------------------------------------------------
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

//-----------------------------------------------------------------------------
// Function Name  : TraceStrBuf
// Description    : 
// Input          : 
// Output         : 
// Return         : 
// Notice         : 
//-----------------------------------------------------------------------------
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



//-----------------------------------------------------------------------------
// Function Name  : MacFillData
// Description    : 
// Input          : 
// Output         : 
// Return         : 
// Notice         : 
//-----------------------------------------------------------------------------
static unsigned short MacFillData(char *pBuf, unsigned short BufLen)
{
	pBuf[BufLen] = 0x80;

	memset(pBuf + BufLen + 0x01, 0x00, 0x10 - ((BufLen % 0x10) + 0x01));

	return BufLen + 0x10 - (BufLen % 0x10);
}

//-----------------------------------------------------------------------------
// Function Name  : Bcd2Asc
// Description    : 
// Input          : 
// Output         : 
// Return         : 
// Notice         : 
//-----------------------------------------------------------------------------
short Bcd2Asc(unsigned char *pucBcd, char *pcAsc, unsigned short usLen)
{
	unsigned short i;
	unsigned char ucTmp;

	for (i = 0; i < usLen; i++)
	{
		ucTmp = pucBcd[i] >> 4;
		pcAsc[i * 2] = (ucTmp > 9) ? (ucTmp - 10 + 'A') : (ucTmp + '0');
		ucTmp = pucBcd[i] & 0xF;
		pcAsc[i * 2 + 1] = (ucTmp > 9) ? (ucTmp - 10 + 'A') : (ucTmp + '0');
	}
	return 1;
}

//-----------------------------------------------------------------------------
// Function Name  : HexStrToByte
// Description    : 
// Input          : 
// Output         : 
// Return         : 
// Notice         : 
//-----------------------------------------------------------------------------
int HexStrToByte(const char* source, char* dest, unsigned int sourceLen)
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

//-----------------------------------------------------------------------------
// Function Name  : Sm4CBC
// Description    : 
// Input          : 
// Output         : 
// Return         : 
// Notice         : 
//-----------------------------------------------------------------------------
static void Sm4CBC(char *pVi, char *pKey, char *pData, unsigned int uiLen, char cMode)
{
	unsigned int i;
	unsigned char temp[16];
	char acVi[16];

	memmove(acVi, pVi, 16);
	if (SMS4_ENCRYPT == cMode)
	{
		while (uiLen > 0)
		{
			for (i = 0; i < 16; i++)
				pData[i] = (pData[i] ^ acVi[i]);

			SM4_Encrypt(pKey, pData, pData);

			memmove(acVi, pData, 16);
			pData += 16;
			uiLen -= 16;
		}
	}
	else
	{
		while (uiLen > 0)
		{
			memmove(temp, pData, 16);
			SM4_Decrypt(pKey, pData, pData);

			for (i = 0; i < 16; i++)
				pData[i] = (char)(pData[i] ^ acVi[i]);

			memmove(acVi, temp, 16);
			pData += 16;
			uiLen -= 16;
		}
	}
}

//-----------------------------------------------------------------------------
// Function Name  : Sm4ECB
// Description    : 
// Input          : 
// Output         : 
// Return         : 
// Notice         : 
//-----------------------------------------------------------------------------
static void Sm4ECB(char *pKey, char *pData, unsigned int uiLen, char cMode)
{

	if (SMS4_DECRYPT == cMode)
	{
		while (uiLen > 0)
		{
			SM4_Decrypt(pKey, pData, pData);
			pData += 16;
			uiLen -= 16;
		}
	}
	else
	{
		while (uiLen > 0)
		{
			SM4_Encrypt(pKey, pData, pData);
			pData += 16;
			uiLen -= 16;
		}
	}

}

//-----------------------------------------------------------------------------
// Function Name  : AlgSm3
// Description    : 
// Input          : 
// Output         : 
// Return         : 
// Notice         : 
//-----------------------------------------------------------------------------
DLL_API int AlgSm3(char* pIn, unsigned int uiLen, char* pHash, char ucMode)
{
	SM3_256(pIn, uiLen, pHash);
	return TRUE;
}

//----------------------------------------------------------------------------- 
// 名称：AlgGMProprocessing
// 功能：使用SM3做杂凑值运算得到32字节杂凑值
// 参数：u32 *pdwBuf      - 数据处理缓冲区
//       u8 *pucPublicKey - SM2公钥
//       u8 *pucData      - 待签名消息
//       u16 uiDataLen    - 待签名消息长度
//       pucOut           - 输出杂凑值
// 返回：TRUE
// 说明：按照SM2密码算法规范文档，在函数内部实现了预处理1和预处理2的流程，输入
//       的结果就是预处理2后的结果值
//----------------------------------------------------------------------------- 
DLL_API int AlgGMProprocessing(unsigned char* ID, unsigned short idLen, char *pucPublicKey, char *pucData, unsigned short uiDataLen, char *pucOut)
{
	unsigned char i = 0;
	unsigned char Sm3Buff[32];
	unsigned char smtmp[1024] = { 0 };
	unsigned char ucCalZa[256] = { 0 };

	const unsigned char Ep[128] =
	{
		//椭圆参数,128B
		0xFF,0xFF,0xFF,0xFE, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF, 0x00,0x00,0x00,0x00, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFC,
		0x28,0xE9,0xFA,0x9E, 0x9D,0x9F,0x5E,0x34, 0x4D,0x5A,0x9E,0x4B, 0xCF,0x65,0x09,0xA7,
		0xF3,0x97,0x89,0xF5, 0x15,0xAB,0x8F,0x92, 0xDD,0xBC,0xBD,0x41, 0x4D,0x94,0x0E,0x93,
		0x32,0xC4,0xAE,0x2C, 0x1F,0x19,0x81,0x19, 0x5F,0x99,0x04,0x46, 0x6A,0x39,0xC9,0x94,
		0x8F,0xE3,0x0B,0xBF, 0xF2,0x66,0x0B,0xE1, 0x71,0x5A,0x45,0x89, 0x33,0x4C,0x74,0xC7,
		0xBC,0x37,0x36,0xA2, 0xF4,0xF6,0x77,0x9C, 0x59,0xBD,0xCE,0xE3, 0x6B,0x69,0x21,0x53,
		0xD0,0xA9,0x87,0x7C, 0xC6,0x2A,0x47,0x40, 0x02,0xDF,0x32,0xE5, 0x21,0x39,0xF0,0xA0,
	};

	//TRACE("uiDataLen = %d", uiDataLen);
	//TRACESTRBUF("pucData:", pucData, uiDataLen);

	ucCalZa[0] = (idLen * 8) >> 8;
	ucCalZa[1] = (idLen * 8) & 0xFF;

	for (i = 0; i < idLen; i++)
	{
		ucCalZa[2 + i] = ID[i];
	}

	memcpy(&ucCalZa[2 + i], Ep, 128);

	//TRACESTRBUF("=ucCalZa:\r\n", ucCalZa, 2 + idLen + 128);

	// 连接
	memcpy(smtmp, ucCalZa, sizeof(ucCalZa));
	memcpy(smtmp + 2 + idLen + 128, pucPublicKey, 64);

	//TRACESTRBUF("=pucPublicKey", pucPublicKey, 64);

	//int AlgSm3(char* pIn, unsigned int uiLen, char* pHash, char ucMode)
	if (!AlgSm3(smtmp, 2 + idLen + 128 + 64, Sm3Buff, 0x00))
	{
		return FALSE;
	}

	//TRACE("AlgSm3-1 resault\n");
	//TRACEBUF(Sm3Buff, 32);

	memcpy(smtmp, Sm3Buff, sizeof(Sm3Buff));
	memcpy(smtmp + sizeof(Sm3Buff), pucData, uiDataLen);

	//TRACE("AlgSm3-2 len=0x%x\n", sizeof(Sm3Buff) + uiDataLen);
	//TRACEBUF(smtmp, sizeof(Sm3Buff) + uiDataLen);
	if (!AlgSm3(smtmp, sizeof(Sm3Buff) + uiDataLen, Sm3Buff, 0x00))
	{
		return FALSE;
	}

	//TRACE("=AlgSm3-3 need sign data:\r\n");
	//TRACEBUF(Sm3Buff, 32);
	memcpy(pucOut, Sm3Buff, sizeof(Sm3Buff));
	return TRUE;
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
DLL_API int AlgSm4(char *pVi, char *pKey, char *pIn, unsigned int uiLen, char ucMode)
{
	char cDeCryph, cCbc;

	//need padding
	if (uiLen % 16)
	{
		return FALSE;
	}

	//cbc/ecb
	if (ucMode & BIT01)
	{
		//cbc vi
		if (NULL ==  pVi)
		{
			return FALSE;
		}
		cCbc = 1;
	}
	else
	{
		cCbc = 0;
	}

	//de/encrypt
	if (ucMode & BIT00)
	{
		cDeCryph = 1;//decrypt
	}
	else
	{
		cDeCryph = 0;//encrypt
	}

	if (cCbc == 1)
	{
		if (cDeCryph)//
		{
			Sm4CBC(pVi, pKey, pIn, uiLen, SMS4_DECRYPT);
		}
		else
		{
			Sm4CBC(pVi, pKey, pIn, uiLen, SMS4_ENCRYPT);
		}

	}
	else  //ecb
	{
		if (cDeCryph)
		{
			Sm4ECB(pKey, pIn, uiLen,  SMS4_DECRYPT);
		}
		else
		{
			Sm4ECB(pKey, pIn, uiLen,  SMS4_ENCRYPT);
		}
	}

	return TRUE;
}

//-----------------------------------------------------------------------------
// Function Name  : AlgSm4Mac
// Description    : 
// Input          : 
// Output         : 
// Return         : 
// Notice         : 
//-----------------------------------------------------------------------------
DLL_API int AlgSm4OnlineMac(char *pKey, char *pIn, unsigned int uiLen, char * pOut)
{
	char Vi[16];

	//need padding
	if (uiLen % 16)
	{
		return FALSE;
	}

	memset(Vi, 0x00, sizeof(Vi));
	//TRACESTRBUF("vi", Vi, 16);

	AlgSm4(Vi, pKey, pIn, uiLen, SMS4_CBC_MODE | SMS4_ENCRYPT);
	//TRACESTRBUF("Cipher",pIn, pIn);

	memcpy(pOut, pIn+uiLen-16, 8);
	//TRACESTRBUF("Mac",pOut, 8);

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
DLL_API int AlgSm2Keygen(char *pSm2PriK, char *pSm2PubK)
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
DLL_API int AlgSm2Encrypt(char *pIn, unsigned short *pusLen, char *pOut, char *pSm2PubK)
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
DLL_API int AlgSm2Decrypt(char *pIn, unsigned short *pusLen, char *pOut, char *pSm2PriK)
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
	//TRACE("*pusLen = %d \r\n", *pusLen);
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
DLL_API int AlgSm2Sign(char *pInHash, char ucLen, char *pOut, char *pSm2PriK)
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
DLL_API int AlgSm2Verify(char *pInHash, char *pucSign, char *pSm2PubK)
{
	if (0 != SM2_Verify_With_E(pInHash, pSm2PubK, pSm2PubK+ SM2_NUMWORD, pucSign, pucSign + SM2_NUMWORD))
	{
		return FALSE;
	}	

	return TRUE;
}

//-----------------------------------------------------------------------------
//.dP"Y8 888888 88     888888     888888 888888 .dP"Y8 888888
//`Ybo." 88__   88     88__         88   88__   `Ybo."   88
//o.`Y8b 88""   88.o 88""         88   88""   o.`Y8b   88
//8bodP' 888888 88ood8 88           88   888888 8bodP'   88
//-----------------------------------------------------------------------------
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
#define SM4_ONLINE_MAC "530F8A9208FE09C5"
#else
#define SM4_CBC_VI "00000000000000000000000000000000"
#define SM4_CBC_PLAINT "25962B7C21FBDD436B92A060C6845BC07FC05F7B60B793AB7B404CBAAE5CC2FEEDD9E936BA049D3BEFF00320BFE619328DF246A3A35432D817FC7AB97A37E05D"
#define SM4_CBC_CIPHER "C0A42B722EC314DDC006EE3BE9BF8BAFF60DA86F7135C32B5EED7DC9C55E8B82224B92636188959608057B15B0119F91530F8A9208FE09C576305033B345BC11"
#define SM4_ONLINE_MAC "530F8A9208FE09C5"
#endif

//-----------------------------------------------------------------------------
// Function Name  : AlgSmTest
// Description    : 
// Input          : 
// Output         : 
// Return         : =0 pass ; !=0 error
// Notice         : 
//-----------------------------------------------------------------------------
DLL_API int AlgSmTest(int iMode)
{
	int iRet, iBack;

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
	char acSm4Tmp[0x40];
	char acSm4Key[0x10];
	char acSm4CbcVi[0x10];
	char acSm4Mac[0x08];

	iBack = 0;
	iRet = FALSE;

	MirsysInit();

	if (iMode & BIT00)
	{
		//sm3
		HexStrToByte(SM3_RAW, acTmp, strlen(SM3_RAW));
		iRet = AlgSm3(&acTmp, 32, acHash, 0);
		HexStrToByte(SM3_RET, acTmp, strlen(SM3_RET));
		if (!iRet || 0 != memcmp(acHash, acTmp, 32))
		{
			TRACE("# AlgSm3 Fail!!! \r\n");
			iBack |= BIT00;
		}
	}

	if (iMode & BIT01)
	{
		//sm2 generator key
		HexStrToByte(SM2_PRIK, Sm2PriK, strlen(SM2_PRIK));
		iRet = AlgSm2Keygen(&Sm2PriK, &Sm2PubK);
		HexStrToByte(SM2_PUBK, SM2PubkTmp, strlen(SM2_PUBK));
		if (!iRet || 0 != memcmp(Sm2PubK, SM2PubkTmp, 64))
		{
			TRACE("# AlgSm2Keygen Fail!!! \r\n");
			iBack |= BIT01;
		}
	}

	if (iMode & BIT02)
	{
		//sm2 en&de
		HexStrToByte(SM2_PRIK, Sm2PriK, strlen(SM2_PRIK));
		HexStrToByte(SM2_PUBK, Sm2PubK, strlen(SM2_PUBK));
		HexStrToByte(SM2_PLAIN, acSm2Plain, strlen(SM2_PLAIN));

		usPlainLen = sizeof(acSm2Plain);
		//TRACESTRBUF("Sm2PriK", Sm2PriK, sizeof(Sm2PriK));
		//TRACESTRBUF("Sm2PubK", Sm2PubK, sizeof(Sm2PubK));
		//TRACESTRBUF("acSm2Plain", acSm2Plain, sizeof(acSm2Plain));

		iRet = AlgSm2Encrypt(acSm2Plain, &usPlainLen, acSm2Cipher, Sm2PubK);
		if (!iRet)
		{
			TRACE("# AlgSm2Encrypt Fail!!! \r\n");
			iBack |= BIT02;
		}

		usCipherLen = usPlainLen;
		//TRACE("usCipherLen = %d \r\n", usCipherLen);
		//TRACESTRBUF("acSm2Cipher", acSm2Cipher, sizeof(acSm2Cipher));

		iRet = AlgSm2Decrypt(acSm2Cipher, &usCipherLen, acSm2PlainTmp, Sm2PriK);
		//TRACESTRBUF("acSm2PlainTmp", acSm2PlainTmp, sizeof(acSm2PlainTmp));
		if (!iRet || 0 != memcmp(acSm2Plain, acSm2PlainTmp, usCipherLen))
		{
			TRACE("# AlgSm2Decrypt Fail!!! \r\n");
			iBack |= BIT02;
		}

	}

	if (iMode & BIT03)
	{
		//sm2 sign&verify
		HexStrToByte(SM2_PRIK, Sm2PriK, strlen(SM2_PRIK));
		HexStrToByte(SM2_PUBK, Sm2PubK, strlen(SM2_PUBK));
		HexStrToByte(SM2_PLAIN, acSm2Plain, strlen(SM2_PLAIN));
		HexStrToByte(SM3_RET, acHash, strlen(SM3_RET));


		iRet = AlgSm2Sign(acHash, 0, acSm2Sign, Sm2PriK);
		//TRACESTRBUF("acSm2Sign", acSm2Sign, sizeof(acSm2Sign));
		if (!iRet)
		{
			TRACE("# AlgSm2Sign Fail!!! \r\n");
			iBack |= BIT03;
		}


		//true sign
		iRet = AlgSm2Verify(acHash, acSm2Sign, Sm2PubK);
		if (!iRet)
		{
			TRACE("# AlgSm2Verify Fail 1 !!! \r\n");
			iBack |= BIT03;
		}

		//fake sign
		HexStrToByte(SM3_RAW, acHash, strlen(SM3_RAW));
		iRet = AlgSm2Verify(acHash, acSm2Sign, Sm2PubK);
		if (iRet)
		{
			TRACE("# AlgSm2Verify Fail 2 !!! \r\n");
			iBack |= BIT03;
		}
	}

	//sm4
	if (iMode & BIT04)//ecb
	{
		HexStrToByte(SM4_ECB_PLAINT, acSm4Plain, strlen(SM4_ECB_PLAINT));
		HexStrToByte(SM4_ECB_CIPHER, acSm4Tmp, strlen(SM4_ECB_CIPHER));
		HexStrToByte(SM4_KEY, acSm4Key, strlen(SM4_KEY));

		iRet = AlgSm4(NULL, acSm4Key, acSm4Plain, sizeof(acSm4Plain), SMS4_ECB_MODE | SMS4_ENCRYPT);
		//TRACESTRBUF("acSm4Cipher", acSm4Plain, sizeof(acSm4Plain));
		if (!iRet || 0!= memcmp(acSm4Plain, acSm4Tmp, sizeof(acSm4Plain)))
		{
			TRACE("# AlgSm4 ECB EN Fail!!! \r\n");
			iBack |= BIT04;
		}

		HexStrToByte(SM4_ECB_PLAINT, acSm4Tmp, strlen(SM4_ECB_PLAINT));
		//TRACESTRBUF("acSm4Cipher", acSm4Plain, sizeof(acSm4Plain));
		iRet = AlgSm4(NULL, acSm4Key, acSm4Plain, sizeof(acSm4Plain), SMS4_ECB_MODE | SMS4_DECRYPT);
		//TRACESTRBUF("acSm4Plain", acSm4Plain, sizeof(acSm4Plain));
		if (!iRet || 0 != memcmp(acSm4Plain, acSm4Tmp, sizeof(acSm4Plain)))
		{
			TRACE("# AlgSm4 ECB DE Fail!!! \r\n");
			iBack |= BIT04;
		}

	}

	if (iMode & BIT05)
	{
		//cbc
		HexStrToByte(SM4_CBC_PLAINT, acSm4Plain, strlen(SM4_CBC_PLAINT));
		HexStrToByte(SM4_KEY, acSm4Key, strlen(SM4_KEY));
		HexStrToByte(SM4_CBC_VI, acSm4CbcVi, strlen(SM4_CBC_VI));
		HexStrToByte(SM4_CBC_CIPHER, acSm4Tmp, strlen(SM4_CBC_CIPHER));

		iRet = AlgSm4(acSm4CbcVi, acSm4Key, acSm4Plain, sizeof(acSm4Plain), SMS4_CBC_MODE | SMS4_ENCRYPT);
		//TRACESTRBUF("acSm4Cipher", acSm4Plain, sizeof(acSm4Plain));
		if (!iRet || 0 != memcmp(acSm4Plain, acSm4Tmp, sizeof(acSm4Plain)))
		{
			TRACE("AlgSm4 CBC EN Fail!!! \r\n");
			iBack |= BIT05;
		}

		HexStrToByte(SM4_CBC_PLAINT, acSm4Tmp, strlen(SM4_CBC_PLAINT));
		//TRACESTRBUF("acSm4Cipher", acSm4Plain, sizeof(acSm4Plain));
		iRet = AlgSm4(acSm4CbcVi, acSm4Key, acSm4Plain, sizeof(acSm4Plain), SMS4_CBC_MODE | SMS4_DECRYPT);
		//TRACESTRBUF("acSm4Plain", acSm4Plain, sizeof(acSm4Plain));
		if (!iRet || 0 != memcmp(acSm4Tmp, acSm4Plain, sizeof(acSm4Tmp)))
		{
			TRACE("AlgSm4 CBC DE Fail!!! \r\n");
			iBack |= BIT05;
		}

		HexStrToByte(SM4_ONLINE_MAC, acSm4Tmp, strlen(SM4_ONLINE_MAC));
		HexStrToByte(SM4_CBC_PLAINT, acSm4Plain, strlen(SM4_CBC_PLAINT));
		HexStrToByte(SM4_KEY, acSm4Key, strlen(SM4_KEY));
		iRet = AlgSm4OnlineMac(acSm4Key, acSm4Plain, sizeof(acSm4Plain), acSm4Mac);
		if (!iRet || 0 != memcmp(acSm4Mac, acSm4Tmp, sizeof(acSm4Mac)))
		{
			TRACE("AlgSm4 ONLINE MAC Fail!!! \r\n");
			iBack |= BIT05;
		}
	}

	ERR:

	//TRACE("AlgSmTest = [0x%08x]\r\n", iBack);

	return iBack;
}

//-----------------------------------------------------------------------------
// Function Name  : SM_SelfTest
// Description    : 
// Input          : 
// Output         : 
// Return         : 
// Notice         : 原生接口测试
//-----------------------------------------------------------------------------
int SM_SelfTest(void)
{
	int iResult;

	iResult = SM3_SelfTest();
	TRACE("#SM3_SelfTest = %08x \r\n", iResult);

	iResult = SM4_SelfTest();
	TRACE("#SM4_SelfTest = %08x \r\n", iResult);

	iResult = SM2_EnDeTest();
	TRACE("#SM2_EnDeTest = %08x \r\n", iResult);

	iResult = SM2_SignVerifyTest();
	TRACE("#SM2_SignVerifyTest = %08x \r\n", iResult);

	iResult = SM2_KeyEX_SelfTest();
	TRACE("#SM2_KeyEX_SelfTest = %08x \r\n", iResult);

	return iResult;
}

