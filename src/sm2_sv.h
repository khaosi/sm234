/************************************************************************ 
File  name:	SM2_sv.h
Version:	SM2_sv_V1.0
Date:	Sep  27,2016
Description:    implementation  of  SM2  signature  algorithm  and  verification  algorithm Function  List:
1.	SM2_Init	//initiate  SM2  curve
2.	Test_Point	//test  if  the  given  point  is  on  SM2  curve
3.	Test_PubKey	//test  if  the  given  public  key  is  valid
4.	Test_Zero	//test  if  the  big  x  equals  zero
5.	Test_n	//test  if  the  big  x  equals  n
6.	Test_Range	//test  if  the  big  x  belong  to  the  range[1,n-1]
7.	SM2_KeyGeneration	//generate  public  key
8.	SM2_Sign	//SM2  signature  algorithm
9.	SM2_Verify	//SM2  verification
10.	SM2_SelfCheck()	//SM2  slef-check
11.	SM3_256()	//this  function  can  be  found  in  SM3.c  and  SM3.h

Notes:
This  SM2  implementation  source  code  can  be  used  for  academic,  non-profit  making  or non-commercial  use  only.
This  SM2  implementation  is  created  on  MIRACL.  SM2  implementation  source  code  provider  does not provide MIRACL library, MIRACL license or any permission to use MIRACL library. Any commercial use  of  MIRACL  requires  a  license  which  may  be  obtained  from  Shamus  Software  Ltd.
**************************************************************************/


#include <string.h> 
#include <malloc.h> 
#include "miracl.h"


#define	SM2_WORDSIZE			8	
#define	SM2_NUMBITS				256
#define	SM2_NUMWORD				(SM2_NUMBITS/SM2_WORDSIZE)     //32

#define ERR_ECURVE_INIT			0x00000001
#define ERR_INFINITY_POINT		0x00000002
#define ERR_NOT_VALID_POINT		0x00000003
#define ERR_ORDER				0x00000004 
#define ERR_NOT_VALID_ELEMENT	0x00000005 
#define ERR_GENERATE_R			0x00000006
#define ERR_GENERATE_S			0x00000007
 
#define ERR_OUTRANGE_R			0x00000008
#define ERR_OUTRANGE_S			0x00000009
#define ERR_GENERATE_T			0x0000000A
#define ERR_PUBKEY_INIT			0x0000000B
#define ERR_DATA_MEMCMP			0x0000000C



int  SM2VC_Init();
int  Test_Point(epoint*  point); 
int  Test_PubKey(epoint  *pubKey); 
int  Test_Zero(big  x);
int  Test_n(big  x);  
int  Test_Range(big  x);
int  SM2_KeyGeneration(unsigned  char  PriKey[],unsigned  char  Px[],unsigned  char  Py[]);

int  SM2_Sign(unsigned  char  *message,int  len,unsigned  char  ZA[],unsigned  char  rand[],unsigned char  d[],unsigned  char  R[],unsigned  char  S[]);
int  SM2_Verify(unsigned  char  *message,int  len,unsigned  char  ZA[],unsigned  char  Px[],unsigned char  Py[],unsigned  char  R[],unsigned  char  S[]);
int  SM2_SelfCheck();
 
