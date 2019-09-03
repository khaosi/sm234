/************************************************************************ 
File  name:	SM2_ENC.h
Version:	SM2_ENC_V1.1
Date:	Sep  27,2016
Description:    implementation  of  SM2  encryption  algorithm  and  decryption  algorithm Function  List:
1.	SM2_init	//initiate  SM2  curve
2.	SM2_ENC	//SM2  encryption,  calls  SM3_KDF
3.	SM2_DEC	//SM2  decryption,  calls SM2_KDF,Test_null,Test_Point,SM3_init,SM3_process,SM3_done
4.	SM2_ENC_SelfTest	//test whether the calculation is correct by comparing the  result  with  the  standard  data
5.	Test_Point	//test  if  the  given  point  is  on  SM2  curve
6.	Test_Pubkey	//test  if  the  given  public  key  is  valid
7.	Test_Null	//test  if  the  geiven  array  is  all  zero 8.SM2_KeyGeneration	 //calculate  a  pubKey  out  of  a  given  priKey 9.SM3_init	 //init  SM3  state
10.	SM3_process	//compress  the  the  message
11.	SM3_done	//compress  the  rest  message  and  output  the  hash  value
12.	SM3_KDF	//key  deviding  function  base  on  SM3,  generates  key
stream
Notes:
This  SM2  implementation  source  code  can  be  used  for  academic,  non-profit  making  or non-commercial  use  only.
This  SM2  implementation  is  created  on  MIRACL.  SM2  implementation  source  code  provider  does not provide MIRACL library, MIRACL license or any permission to use MIRACL library. Any commercial use  of  MIRACL  requires  a  license  which  may  be  obtained  from  Shamus  Software  Ltd.
**************************************************************************/
#define  ECC_WORDSIZE 	        8
#define  SM2_NUMBITS 	        256
#define	 SM2_NUMWORD	        (SM2_NUMBITS/ECC_WORDSIZE)    //32

#define  ERR_INFINITY_POINT	    0x00000001
#define  ERR_NOT_VALID_ELEMENT	0x00000002
#define  ERR_NOT_VALID_POINT	0x00000003
#define  ERR_ORDER	            0x00000004
#define  ERR_ARRAY_NULL	        0x00000005
#define  ERR_C3_MATCH	        0x00000006
#define  ERR_ECURVE_INIT	    0x00000007
#define  ERR_SELFTEST_KG	    0x00000008
#define  ERR_SELFTEST_ENC	    0x00000009
#define  ERR_SELFTEST_DEC	    0x0000000A
 

int  Test_Point(epoint*  point); 
int  Test_PubKey(epoint  *pubKey);
int  Test_Null(unsigned  char  array[],int  len); 
int  SM2_Init();
int  SM2_KeyGeneration(big  priKey,epoint  *pubKey);
int  SM2_Encrypt(unsigned  char*  randK,epoint  *pubKey,unsigned  char  M[],int  klen,unsigned  char C[]);
int  SM2_Decrypt(big  dB,unsigned  char  C[],int  Clen,unsigned  char  M[]);

int  SM2_ENC_SelfTest();
 
