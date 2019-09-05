/************************************************************************ 
File  name:	SM2.c
Version:	SM2_V1.1
Date:	Sep  27,2016
Description:    implementation  of  SM2  encryption  algorithm  and  decryption  algorithm Function  List:
1.	SM2_init	//initiate  SM2  curve
2.	SM2_ENC	//SM2  encryption,  calls  SM3_KDF
3.	SM2_DEC	//SM2  decryption,  calls SM2_KDF,Test_null,Test_Point,SM3_init,SM3_process,SM3_done
4.	SM2_ENC_SelfTest	//test  whether  the  calculation  is  correct  by  comparing  the  result with  the  standard  data
5.	Test_Point	//test  if  the  given  point  is  on  SM2  curve 6.Test_Pubkey	//test  if  the  given  public  key  is  valid 7.Test_Null	//test  if  the  geiven  array  is  all  zero 8.SM2_KeyGeneration	//calculate  a  pubKey  out  of  a  given  priKey 9.SM3_init	//init  SM3  state
10.	SM3_process	//compress  the  the  message
11.	SM3_done	//compress  the  rest  message  and  output  the  hash  value 12.SM3_KDF	//key  deviding  function  base  on  SM3,  generates  key  stream
Notes:
This  SM2  implementation  source  code  can  be  used  for  academic,  non-profit  making  or non-commercial  use  only.
This  SM2  implementation  is  created  on  MIRACL.  SM2  implementation  source  code  provider  does not  provide    MIRACL  library,  MIRACL  license  or  any  permission  to  use  MIRACL  library.  Any commercial  use  of  MIRACL  requires  a  license  which  may  be  obtained  from  Shamus  Software  Ltd.
**************************************************************************/
#include "../inc/miracl.h" 
#include "../inc/mirdef.h" 
#include "../inc/sm2.h" 
#include "../inc/kdf.h"

unsigned char SM2_p[32] = { 0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
unsigned char SM2_a[32] = { 0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC };
unsigned char SM2_b[32] = { 0x28,0xE9,0xFA,0x9E,0x9D,0x9F,0x5E,0x34,0x4D,0x5A,0x9E,0x4B,0xCF,0x65,0x09,0xA7,0xF3,0x97,0x89,0xF5,0x15,0xAB,0x8F,0x92,0xDD,0xBC,0xBD,0x41,0x4D,0x94,0x0E,0x93 };
unsigned char SM2_n[32] = { 0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x72,0x03,0xDF,0x6B,0x21,0xC6,0x05,0x2B,0x53,0xBB,0xF4,0x09,0x39,0xD5,0x41,0x23 };
unsigned char SM2_Gx[32] = { 0x32,0xC4,0xAE,0x2C,0x1F,0x19,0x81,0x19,0x5F,0x99,0x04,0x46,0x6A,0x39,0xC9,0x94,0x8F,0xE3,0x0B,0xBF,0xF2,0x66,0x0B,0xE1,0x71,0x5A,0x45,0x89,0x33,0x4C,0x74,0xC7 };
unsigned char SM2_Gy[32] = { 0xBC,0x37,0x36,0xA2,0xF4,0xF6,0x77,0x9C,0x59,0xBD,0xCE,0xE3,0x6B,0x69,0x21,0x53,0xD0,0xA9,0x87,0x7C,0xC6,0x2A,0x47,0x40,0x02,0xDF,0x32,0xE5,0x21,0x39,0xF0,0xA0 };
unsigned char SM2_h[32] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01 };

big  para_p, para_a, para_b, para_n, para_Gx, para_Gy, para_h;
epoint  *G, *nG;
miracl  *mip;

//-----------------------------------------------------------------------------
// Function Name  : SAHexStrToByte
// Description    : 
// Input          : 
// Output         : 
// Return         : 
// Notice         : 
//-----------------------------------------------------------------------------
void MirsysInit(void)
{
	static sFlag = 0;
	if (!sFlag)
	{
		mip = mirsys(10000, 16);
		mip->IOBASE = 16;
		sFlag = 1;
	}

}

/**************************************************************** 
 * Function:	Test_Point
Description:	test  if  the  given  point  is  on  SM2  curve Calls:
Called  By:	SM2_Decrypt,  Test_PubKey Input:	 point
Output:	null
Return:	0:  sucess
3:  not  a  valid  point  on  curve
 
Others:
****************************************************************/ 
int  Test_Point(epoint*  point)
{
    big  x,y,x_3,tmp;
    x=mirvar(0); 
    y=mirvar(0); 
    x_3=mirvar(0); 
    tmp=mirvar(0);

    //test if y^2=x^3+ax+b 
    epoint_get(point, x, y);
    power(x, 3, para_p, x_3);	//x_3=x^3  mod  p 
    multiply(x, para_a,x);	//x=a*x
    divide(x, para_p, tmp);	//x=a*x  mod  p ,  tmp=a*x/p 
    add(x_3, x, x);	//x=x^3+ax
    add(x, para_b, x);	//x=x^3+ax+b
    divide(x, para_p, tmp);	//x=x^3+ax+b  mod  p
    power(y, 2, para_p, y);	//y=y^2  mod  p 
    
    if(compare(x,y)!=0)
        return  ERR_NOT_VALID_POINT; 
    else
        return 0;
}

/**************************************************************** 
 * Function:	SM2_TestPubKey
Description:	test  if  the  given  point  is  valid Calls:
Called  By:	SM2_Decrypt
Input:	pubKey	//a  point
Output:	null
Return:	0:  sucess
1:  a  point  at  infinity
2:  X  or  Y  coordinate  is  beyond  Fq 3:  not  a  valid  point  on  curve
4:  not  a  point  of  order  n
Others:
****************************************************************/ 
int Test_PubKey(epoint  *pubKey)
{
 
    big  x,y,x_3,tmp; 
    epoint  *nP; 
    x=mirvar(0); 
    y=mirvar(0); 
    x_3=mirvar(0); 
    tmp=mirvar(0);

    nP=epoint_init();

    //test  if  the  pubKey  is  the  point  at  infinity
    if  (point_at_infinity(pubKey))//  if  pubKey  is  point  at  infinity,  return  error; 
        return  ERR_INFINITY_POINT;

    //test  if  x<p	and    y<p    both  hold 
	epoint_get(pubKey,x,y);
    if((compare(x,para_p)!=-1) || (compare(y,para_p)!=-1)) 
        return  ERR_NOT_VALID_ELEMENT;

    if(Test_Point(pubKey)!=0) 
        return  ERR_NOT_VALID_POINT;

    //test  if  the  order  of  pubKey  is  equal  to  n 
    ecurve_mult(para_n,pubKey,nP);	//  nP=[n]P
    if  (!point_at_infinity(nP))	//  if  np  is  point  NOT  at  infinity,  return  error;
        return  ERR_ORDER;

    return 0;
}

/**************************************************************** 
 * Function:	Test_Null
Description:	test  if  the  given  array  is  all  zero Calls:
Called  By:	SM2_Encrypt
Input:	array[len]
len	//byte  len  of  the  array
Output:	null
Return:	0:  the  given  array  is  not  all  zero
1:  the  given  array  is  all  zero

Others:
****************************************************************/ 
int Test_Null(unsigned  char  array[],int  len)
{
 
    int  i=0; 
    for(i=0;i<len;i++)
    {
        if (array[i]!=0x00)
            return 0;
    }
    return 1;
}

/****************************************************************
 * Function:	Test_Zero
Description:	test  if  the  big  x  is  zero Calls:
Called  By:	SM2_Sign
Input:	pubKey	//a  point
Output:	null
Return:	0:  x!=0
1: x==0
Others:
****************************************************************/
int Test_Zero(big x)
{
	big  zero;
	zero = mirvar(0);
	if (compare(x, zero) == 0)
		return 1;
	else
		return 0;

}

/****************************************************************
 * Function:	Test_n
Description:	test  if  the  big  x  is  order  n Calls:
Called  By:	SM2_Sign
Input:	big  x	//a  miracl  data  type
Output:	null
Return:	0:  sucess
1:  x==n,fail
Others:
****************************************************************/
int Test_n(big  x)
{
	//	bytes_to_big(32,SM2_n,n);
	if (compare(x, para_n) == 0)
		return 1;
	else
		return 0;
}

/****************************************************************
 * Function:	Test_Range
Description:	test  if  the  big  x  belong  to  the  range[1,n-1] Calls:
Called  By:	SM2_Verify
Input:	big  x	///a  miracl  data  type
Output:	null
Return:	0:  sucess
1:  fail
Others:
****************************************************************/
int Test_Range(big x)
{
	big  one, decr_n;

	one = mirvar(0);
	decr_n = mirvar(0);

	convert(1, one);
	decr(para_n, 1, decr_n);

	if ((compare(x, one) < 0) | (compare(x, decr_n) > 0))
		return 1;
	return 0;
}

/**************************************************************** 
 * Function:	SM2_Init
Description:	Initiate  SM2  curve Calls:	MIRACL  functions Called  By:
Input:	null
Output:	null
Return:	0:  sucess;
7:  paremeter  error;
4:  the  given  point  G  is  not  a  point  of  order  n
Others:
****************************************************************/ 
int SM2_Init()
{
    //epoint  *nG;
    para_p=mirvar(0);
    para_a=mirvar(0);
    para_b=mirvar(0); 
    para_n=mirvar(0); 
    para_Gx=mirvar(0); 
    para_Gy=mirvar(0); 
    para_h=mirvar(0); 
    G=epoint_init(); 
    nG=epoint_init();

    bytes_to_big(SM2_NUMWORD,SM2_p,para_p);
    bytes_to_big(SM2_NUMWORD,SM2_a,para_a); 
    bytes_to_big(SM2_NUMWORD,SM2_b,para_b); 
    bytes_to_big(SM2_NUMWORD,SM2_n,para_n); 
    bytes_to_big(SM2_NUMWORD,SM2_Gx,para_Gx); 
    bytes_to_big(SM2_NUMWORD,SM2_Gy,para_Gy); 
    bytes_to_big(SM2_NUMWORD,SM2_h,para_h);

    ecurve_init(para_a,para_b,para_p,MR_PROJECTIVE);//Initialises  GF(p)  elliptic  curve.
    //MR_PROJECTIVE specifying projective coordinates

    if(!epoint_set(para_Gx,para_Gy,0,G))//initialise  point  G
    {
        return ERR_ECURVE_INIT;
    }

    ecurve_mult(para_n,G,nG);
    if(!point_at_infinity(nG))	//test  if  the  order  of  the  point  is  n
    {
        return ERR_ORDER;
    }
    return 0;
}

/****************************************************************
 * Function:	SM2_KeyGeneration
Description:	calculate  a  pubKey  out  of  a  given  priKey Calls:	SM2_TestPubKey
Called  By:
Input:	priKey	//  a  big  number  lies  in[1,n-2] Output:	pubKey	//  pubKey=[priKey]G
Return:	0:  sucess
1:  fail

Others:
****************************************************************/
int  SM2_KeyGenerationByPriKey(big  priKey, epoint  *pubKey)
{
	int  i = 0;
	big  x, y;

	x = mirvar(0);
	y = mirvar(0);

	ecurve_mult(priKey, G, pubKey);//通过大数和基点产生公钥 epoint_get(pubKey,x,y);

	if (Test_PubKey(pubKey) != 0)
		return 1;
	else
		return 0;
}

/****************************************************************
 * Function:	SM2_KeyGeneration
Description:	calculate  a  pubKey  out  of  a  given  priKey Calls:	SM2_SelfCheck()
Called  By:	SM2_Init()
Input:	priKey	//  a  big  number  lies  in[1,n-2] Output:	pubKey	//  pubKey=[priKey]G
Return:	0:  sucess
2:  a  point  at  infinity
5:  X  or  Y  coordinate  is  beyond  Fq 3:  not  a  valid  point  on  curve
4:  not  a  point  of  order  n
Others:
****************************************************************/
int SM2_KeyGeneration(unsigned  char  PriKey[], unsigned  char  Px[], unsigned  char  Py[])
{
	int  i = 0;
	big  d, PAx, PAy;
	epoint  *PA;

	SM2_Init();
	PA = epoint_init();

	d = mirvar(0);
	PAx = mirvar(0);
	PAy = mirvar(0);

	bytes_to_big(SM2_NUMWORD, PriKey, d);

	ecurve_mult(d, G, PA);
	epoint_get(PA, PAx, PAy);


	big_to_bytes(SM2_NUMWORD, PAx, Px, TRUE);
	big_to_bytes(SM2_NUMWORD, PAy, Py, TRUE);


	i = Test_PubKey(PA);
	if (i)
		return i;
	else
		return 0;

}

/**************************************************************** 
 * Function:	SM2_Encrypt
Description:	SM2  encryption
Calls:	SM2_KDF,Test_null,Test_Point,SM3_init,SM3_process,SM3_done Called  By:
Input:	randK[SM2_NUMWORD]	//  a  random  number  K  lies  in  [1,n-1] pubKey	 //  public  key  of  the  cipher  receiver
M[klen]	//  original  message
klen	//  byte  len  of  original  message Output:	C[klen+SM2_NUMWORD*3]  //  cipher  C1||C3||C2
Return:	0:  sucess
1:  S  is  point  at  infinity
5: the KDF output is all zero

Others:
****************************************************************/
int SM2_Encrypt(unsigned  char* randK, epoint *pubKey, unsigned  char  M[],int  klen,unsigned  char C[])
{

    big  C1x,C1y,x2,y2,rand; 
    epoint  *C1,*kP,*S;
    int  i=0;
    unsigned  char  x2y2[SM2_NUMWORD*2]={0}; 
    SM3_STATE  md;
    C1x=mirvar(0);
    C1y=mirvar(0); 
    x2=mirvar(0); 
    y2=mirvar(0); 
    rand=mirvar(0); 
    C1=epoint_init(); 
    kP=epoint_init(); 
    S=epoint_init();

    //Step2.    calculate  C1=[k]G=(rGx,rGy) 
    bytes_to_big(SM2_NUMWORD,randK,rand); 
    ecurve_mult(rand,G,C1);	//C1=[k]G 
    
    epoint_get(C1,C1x,C1y); 
    big_to_bytes(SM2_NUMWORD,C1x,C,1); 
    big_to_bytes(SM2_NUMWORD,C1y,C+SM2_NUMWORD,1);

    //Step3.    test  if  S=[h]pubKey  if  the  point  at  infinity 
    ecurve_mult(para_h,pubKey,S);  
    if(point_at_infinity(S))//  if  S  is  point  at  infinity,  return  error; 
        return  ERR_INFINITY_POINT;

    //Step4.    calculate  [k]PB=(x2,y2) 
    ecurve_mult(rand,pubKey,kP);	//kP=[k]P 
	epoint_get(kP,x2,y2);

    //Step5.    KDF(x2||y2,klen) 
    big_to_bytes(SM2_NUMWORD,x2,x2y2,1); 
    big_to_bytes(SM2_NUMWORD,y2,x2y2+SM2_NUMWORD,1); 
    SM3_KDF(x2y2  ,SM2_NUMWORD*2,  klen,C+SM2_NUMWORD*3);
    if(Test_Null(C+SM2_NUMWORD*3,klen)!=0) 
        return  ERR_ARRAY_NULL;

    //Step6.    C2=M^t 
    for(i=0;i<klen;i++)
    {
        C[SM2_NUMWORD*3+i]=M[i]^C[SM2_NUMWORD*3+i];
    }

    //Step7.    C3=hash(x2,M,y2) 
    SM3_init(&md); 
    SM3_process(&md,x2y2,SM2_NUMWORD); 
    SM3_process(&md,M,klen);
    SM3_process(&md,x2y2+SM2_NUMWORD,SM2_NUMWORD); 
    SM3_done(&md,C+SM2_NUMWORD*2);

    return 0;
}

/**************************************************************** 
 * Function:	SM2_Decrypt
Description:	SM2  decryption
Calls:	SM2_KDF,Test_Point,SM3_init,SM3_process,SM3_done Called  By:
Input:	dB	//  a  big  number  lies  in  [1,n-2] pubKey	 //  [dB]G
C[Clen]	//  cipher  C1||C3||C2
Clen	//  byte  len  of  cipher Output:	 M[Clen-SM2_NUMWORD*3]  //  decrypted  data Return:	0:  sucess
1:  S  is  a  point  at  finity 3:  C1  is  not  a  valid  point
 
5: KDF output is all zero 6:  C3  does  not  match

Others:
****************************************************************/ 
int SM2_Decrypt(big  dB,unsigned  char  C[],int  Clen,unsigned  char  M[])
{
    SM3_STATE  md;
    int  i=0;
    unsigned  char  x2y2[SM2_NUMWORD*2]={0}; 
    unsigned  char  hash[SM2_NUMWORD]={0}; 
    big  C1x,C1y,x2,y2;
    epoint  *C1,*S,*dBC1; 
    C1x=mirvar(0); 
    C1y=mirvar(0); 
    x2=mirvar(0); 
    y2=mirvar(0); 
    C1=epoint_init(); 
    S=epoint_init(); 
    dBC1=epoint_init();

    //Step1.    test  if  C1  fits  the  curve 
    bytes_to_big(SM2_NUMWORD,C,C1x); 
    bytes_to_big(SM2_NUMWORD,C+SM2_NUMWORD,C1y); 
    epoint_set(C1x,C1y,0,C1);
    i=Test_Point(C1); 

    if(i!=0)
        return i;

    //Step2.    S=[h]C1  and  test  if  S  is  the  point  at  infinity 
    ecurve_mult(para_h,C1,S);
    if(point_at_infinity(S))//  if  S  is  point  at  infinity,  return  error; 
        return  ERR_INFINITY_POINT;

    //Step3.    [dB]C1=(x2,y2)
    ecurve_mult(dB,C1,dBC1); 
    epoint_get(dBC1,x2,y2); 
    big_to_bytes(SM2_NUMWORD,x2,x2y2,1);
    big_to_bytes(SM2_NUMWORD,y2,x2y2+SM2_NUMWORD,1);

    //Step4.    t=KDF(x2||y2,klen) 
    SM3_KDF(x2y2,SM2_NUMWORD*2,Clen-SM2_NUMWORD*3,M);
    if(Test_Null(M,Clen-SM2_NUMWORD*3)!=0)   
        return  ERR_ARRAY_NULL;

    //Step5.    M=C2^t
    for(i=0;i<Clen-SM2_NUMWORD*3;i++) M[i]=M[i]^C[SM2_NUMWORD*3+i];

    //Step6.  hash(x2,m,y2) 
    SM3_init(&md); 
    SM3_process(&md,x2y2,SM2_NUMWORD);
    SM3_process(&md,M,Clen-SM2_NUMWORD*3); 
    SM3_process(&md,x2y2+SM2_NUMWORD,SM2_NUMWORD); 
    SM3_done(&md,hash); 
    if(memcmp(hash,C+SM2_NUMWORD*2,SM2_NUMWORD)!=0)
        return  ERR_C3_MATCH;
    else
        return 0;
}



/****************************************************************
 * Function:	SM2_Sign
Description:	SM2  signature  algorithm
Calls:	SM2_Init(),Test_Zero(),Test_n(),  SM3_256() Called  By:	SM2_SelfCheck()
Input:	message	//the  message  to  be  signed
len	//the  length  of  message
ZA	//  ZA=Hash(ENTLA||  IDA||  a||  b||  Gx  ||  Gy  ||  xA||  yA) rand	//a  random  number  K  lies  in  [1,n-1]
d	//the  private  key

Output:	R,S	//signature  result Return:	0:  sucess
1:  parameter  initialization  error;
4:  the  given  point  G  is  not  a  point  of  order  n 6:  the  signed  r  equals  0  or  r+rand  equals  n
7    the  signed  s  equals  0
Others:
****************************************************************/
int SM2_Sign(unsigned  char  *message, int  len, unsigned  char  ZA[], unsigned  char  rand[], unsigned char  d[], unsigned  char  R[], unsigned  char  S[])
{
	unsigned char  hash[SM3_len / 8];
	int M_len = len + SM3_len / 8;
	unsigned char *M = NULL;
	int i;

	big  dA, r, s, e, k, KGx, KGy;
	big  rem, rk, z1, z2;
	epoint  *KG;

	i = SM2_Init();
	if (i)
		return i;

	//initiate 
	dA = mirvar(0);
	e = mirvar(0);
	k = mirvar(0);
	KGx = mirvar(0);
	KGy = mirvar(0);
	r = mirvar(0);
	s = mirvar(0);
	rem = mirvar(0);
	rk = mirvar(0);
	z1 = mirvar(0);
	z2 = mirvar(0);

	bytes_to_big(SM2_NUMWORD, d, dA);//cinstr(dA, d);
	KG = epoint_init();

	//step1,set  M=ZA||M
	M = (char  *)malloc(sizeof(char)*(M_len + 1));
	memcpy(M, ZA, SM3_len / 8);
	memcpy(M + SM3_len / 8, message, len);

	//step2,generate  e=H(M) 
	SM3_256(M, M_len, hash);
	bytes_to_big(SM3_len / 8, hash, e);

	//step3:generate  k 
	bytes_to_big(SM3_len / 8, rand, k);

	//step4:calculate  kG 
	ecurve_mult(k, G, KG);

	//step5:calculate  r 
	epoint_get(KG, KGx, KGy);
	add(e, KGx, r);
	divide(r, para_n, rem);

	//judge  r=0  or  n+k=n? 
	add(r, k, rk);
	if (Test_Zero(r) | Test_n(rk))
		return  ERR_GENERATE_R;

	//step6:generate  s
	incr(dA, 1, z1);

	xgcd(z1, para_n, z1, z1, z1);
	multiply(r, dA, z2);
	divide(z2, para_n, rem);
	subtract(k, z2, z2);
	add(z2, para_n, z2);
	multiply(z1, z2, s);
	divide(s, para_n, rem);

	//judge  s=0? 
	if (Test_Zero(s))
		return ERR_GENERATE_S;

	big_to_bytes(SM2_NUMWORD, r, R, TRUE);
	big_to_bytes(SM2_NUMWORD, s, S, TRUE);

	free(M);
	return 0;
}

/****************************************************************
 * Function:	SM2_Verify
Description:	SM2  verification  algorithm
Calls:	SM2_Init(),Test_Range(),  Test_Zero(),SM3_256() Called  By:	SM2_SelfCheck()
Input:	message	//the  message  to  be  signed
len	//the  length  of  message
ZA	//ZA=Hash(ENTLA||  IDA||  a||  b||  Gx  ||  Gy  ||  xA||  yA) Px,Py	//the  public  key
R,S	//signature  result

Output:
Return:	0:  sucess
1:  parameter  initialization  error;
4:  the  given  point  G  is  not  a  point  of  order  n B:  public  key  error
8:  the  signed  R  out  of  range  [1,n-1] 9:  the  signed  S  out  of  range  [1,n-1] A:  the  intermediate  data  t  equals  0 C:  verification  fail
Others:
****************************************************************/
int SM2_Verify(unsigned  char  *message, int  len, unsigned  char  ZA[], unsigned  char  Px[], unsigned char  Py[], unsigned  char  R[], unsigned  char  S[])
{
	unsigned char  hash[SM3_len / 8];
	int M_len = len + SM3_len / 8;
	unsigned char *M = NULL;
	int i;

	big  PAx, PAy, r, s, e, t, rem, x1, y1;
	big  RR;
	epoint  *PA, *sG, *tPA;

	i = SM2_Init();
	if (i)
		return i;

	PAx = mirvar(0);
	PAy = mirvar(0);
	r = mirvar(0);
	s = mirvar(0);
	e = mirvar(0);
	t = mirvar(0);
	x1 = mirvar(0);
	y1 = mirvar(0);
	rem = mirvar(0);
	RR = mirvar(0);

	PA = epoint_init();
	sG = epoint_init();
	tPA = epoint_init();

	bytes_to_big(SM2_NUMWORD, Px, PAx);
	bytes_to_big(SM2_NUMWORD, Py, PAy);

	bytes_to_big(SM2_NUMWORD, R, r);
	bytes_to_big(SM2_NUMWORD, S, s);

	if (!epoint_set(PAx, PAy, 0, PA))//initialise  public  key
	{
		return  ERR_PUBKEY_INIT;
	}

	//step1:  test  if  r  belong  to  [1,n-1] 
	if (Test_Range(r))
		return  ERR_OUTRANGE_R;

	//step2:  test  if  s  belong  to  [1,n-1]

	if (Test_Range(s))
		return  ERR_OUTRANGE_S;

	//step3,generate  M
	M = (char  *)malloc(sizeof(char)*(M_len + 1));
	memcpy(M, ZA, SM3_len / 8);
	memcpy(M + SM3_len / 8, message, len);

	//step4,generate  e=H(M) 
	SM3_256(M, M_len, hash);
	bytes_to_big(SM3_len / 8, hash, e);

	//step5:generate  t 
	add(r, s, t);
	divide(t, para_n, rem);

	if (Test_Zero(t))
		return  ERR_GENERATE_T;

	//step  6:  generate(x1,y1) 
	ecurve_mult(s, G, sG);
	ecurve_mult(t, PA, tPA);
	ecurve_add(sG, tPA);
	epoint_get(tPA, x1, y1);

	//step7:generate  RR 
	add(e, x1, RR);
	divide(RR, para_n, rem);

	free(M);
	if (compare(RR, r) == 0)
		return 0;
	else
		return  ERR_DATA_MEMCMP;
}


/**************************************************************** 
 * Function:	SM2_ENC_SelfTest
Description:	test  whether  the  SM2  calculation  is  correct  by  comparing  the  result  with  the standard data
Calls:	SM2_init,SM2_ENC,SM2_DEC Called  By:
Input:	NULL
Output:	NULL
Return:	0:  sucess
1:  S  is  a  point  at  finity
2:  X  or  Y  coordinate  is  beyond  Fq 3:  not  a  valid  point  on  curve
4:  the  given  point  G  is  not  a  point  of  order  n 5: KDF output is all zero
6:  C3  does  not  match
8:  public  key  generation  error 9:  SM2  encryption  error
a:  SM2  decryption  error

Others:
****************************************************************/ 
int SM2_EnDeTest()
{
    int  tmp=0,i=0;
    
    unsigned  char  Cipher[0x80]={0}; //119
    unsigned  char  M[0x20]={0};//19
    unsigned  char  kGxy[SM2_NUMWORD*2]={0}; 
    big  ks,x,y;
    epoint  *kG;

    //standard data 
    unsigned  char std_priKey[32]={0x39,0x45,0x20,0x8F,0x7B,0x21,0x44,0xB1,0x3F,0x36,0xE3,0x8A,0xC6,0xD3,0x9F,0x95,0x88,0x93,0x93,0x69,0x28,0x60,0xB5,0x1A,0x42,0xFB,0x81,0xEF,0x4D,0xF7,0xC5,0xB8};
    unsigned  char std_pubKey[64]={0x09,0xF9,0xDF,0x31,0x1E,0x54,0x21,0xA1,0x50,0xDD,0x7D,0x16,0x1E,0x4B,0xC5,0xC6,\
    0x72,0x17,0x9F,0xAD,0x18,0x33,0xFC,0x07,0x6B,0xB0,0x8F,0xF3,0x56,0xF3,0x50,0x20,\
    0xCC,0xEA,0x49,0x0C,0xE2,0x67,0x75,0xA5,0x2D,0xC6,0xEA,0x71,0x8C,0xC1,0xAA,0x60,\
    0x0A,0xED,0x05,0xFB,0xF3,0x5E,0x08,0x4A,0x66,0x32,0xF6,0x07,0x2D,0xA9,0xAD,0x13};

    unsigned  char std_rand[32]={0x59,0x27,0x6E,0x27,0xD5,0x06,0x86,0x1A,0x16,0x68,0x0F,0x3A,0xD9,0xC0,0x2D,0xCC,0xEF,0x3C,0xC1,0xFA,0x3C,0xDB,0xE4,0xCE,0x6D,0x54,0xB8,0x0D,0xEA,0xC1,0xBC,0x21};
    unsigned  char std_Message[19]={0x65,0x6E,0x63,0x72,0x79,0x70,0x74,0x69,0x6F,0x6E,0x20,0x73,0x74,0x61,0x6E,0x64,0x61,0x72,0x64};
    unsigned  char std_Cipher[115]={0x04,0xEB,0xFC,0x71,0x8E,0x8D,0x17,0x98,0x62,0x04,0x32,0x26,0x8E,0x77,0xFE, 0xB6,\
    0x41,0x5E,0x2E,0xDE,0x0E,0x07,0x3C,0x0F,0x4F,0x64,0x0E,0xCD,0x2E,0x14,0x9A,0x73,\
    0xE8,0x58,0xF9,0xD8,0x1E,0x54,0x30,0xA5,0x7B,0x36,0xDA,0xAB,0x8F,0x95,0x0A,0x3C,\
    0x64,0xE6,0xEE,0x6A,0x63,0x09,0x4D,0x99,0x28,0x3A,0xFF,0x76,0x7E,0x12,0x4D,0xF0,\
    0x59,0x98,0x3C,0x18,0xF8,0x09,0xE2,0x62,0x92,0x3C,0x53,0xAE,0xC2,0x95,0xD3,0x03,\
    0x83,0xB5,0x4E,0x39,0xD6,0x09,0xD1,0x60,0xAF,0xCB,0x19,0x08,0xD0,0xBD,0x87,0x66,\
    0x21,0x88,0x6C,0xA9,0x89,0xCA,0x9C,0x7D,0x58,0x08,0x73,0x07,0xCA,0x93,0x09,0x2D,0x65,0x1E,0xFA};

    //mip=  mirsys(1000,  16); 
    //mip->IOBASE=16;
	MirsysInit();

    x=mirvar(0); 
    y=mirvar(0); 
    ks=mirvar(0); 
    kG=epoint_init();
    bytes_to_big(32,std_priKey,ks);    //ks  is  the  standard  private  key

    //initiate  SM2  curve 
    SM2_Init();

    //generate  key  pair 
    tmp=SM2_KeyGenerationByPriKey(ks,kG); 
    if(tmp!=0)
        return  tmp;  
    epoint_get(kG,x,y);
    big_to_bytes(SM2_NUMWORD,x,kGxy,1);
    big_to_bytes(SM2_NUMWORD,y,kGxy+SM2_NUMWORD,1); 
    if(memcmp(kGxy,std_pubKey,SM2_NUMWORD*2)!=0)
        return  ERR_SELFTEST_KG;

    //encrypt  data  and  compare  the  result  with  the  standard  data 
    tmp=SM2_Encrypt(std_rand,kG,std_Message,19,Cipher); 
    if(tmp!=0)
        return  tmp;     
    if(memcmp(Cipher,std_Cipher,19+SM2_NUMWORD*3)!=0)
        return  ERR_SELFTEST_ENC;

    //decrypt  cipher  and  compare  the  result  with  the  standard  data 
	tmp=SM2_Decrypt(ks,Cipher,115,M);
    if(tmp!=0)
        return  tmp; 
    if(memcmp(M,std_Message,19)!=0)
        return  ERR_SELFTEST_DEC;
    return 0;
}

/****************************************************************
 * Function:	SM2_SelfCheck
Description:	SM2  self  check
Calls:	SM2_Init(),  SM2_KeyGeneration,SM2_Sign,  SM2_Verify,SM3_256() Called  By:
Input: Output:

Return:	0:  sucess
1:  paremeter  initialization  error 2:  a  point  at  infinity
5:  X  or  Y  coordinate  is  beyond  Fq 3:  not  a  valid  point  on  curve
4:  not  a  point  of  order  n B:  public  key  error
8:  the  signed  R  out  of  range  [1,n-1] 9:  the  signed  S  out  of  range  [1,n-1] A:  the  intermediate  data  t  equals  0 C:  verification  fail
Others:
****************************************************************/
int SM2_SignVerifyTest()
{
	//the  private  key
	unsigned char dA[32] = { 0x39,0x45,0x20,0x8f,0x7b,0x21,0x44,0xb1,0x3f,0x36,0xe3,0x8a,0xc6,0xd3,0x9f,0x95,0x88,0x93,0x93,0x69,0x28,0x60,0xb5,0x1a,0x42,0xfb,0x81,0xef,0x4d,0xf7,0xc5,0xb8 };
	unsigned char rand[32] = { 0x59,0x27,0x6E,0x27,0xD5,0x06,0x86,0x1A,0x16,0x68,0x0F,0x3A,0xD9,0xC0,0x2D, 0xCC,0xEF,0x3C,0xC1,0xFA,0x3C,0xDB,0xE4,0xCE,0x6D,0x54,0xB8,0x0D,0xEA,0xC1,0xBC,0x21 };
	//the  public  key
	//unsigned  char xA[32]={0x09,0xf9,0xdf,0x31,0x1e,0x54,0x21,0xa1,0x50,0xdd,0x7d,0x16,0x1e,0x4b,0xc5, 0xc6,0x72,0x17,0x9f,0xad,0x18,0x33,0xfc,0x07,0x6b,0xb0,0x8f,0xf3,0x56,0xf3,0x50,0x20};
	//unsigned  char yA[32]={0xcc,0xea,0x49,0x0c,0xe2,0x67,0x75,0xa5,0x2d,0xc6,0xea,0x71,0x8c,0xc1,0xaa, 0x60,0x0a,0xed,0x05,0xfb,0xf3,0x5e,0x08,0x4a,0x66,0x32,0xf6,0x07,0x2d,0xa9,0xad,0x13};

	unsigned char xA[32], yA[32];
	unsigned char r[64], s[64];//  Signature

	unsigned char IDA[16] = { 0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38 };//ASCII  code  of  userA's  identification
	int IDA_len = 16;
	unsigned char ENTLA[2] = { 0x00,0x80 };//the  length  of  userA's  identification,presentation  in ASCII  code
	unsigned char message[32];// = "message  digest";//the  message  to  be  signed 
	int  len;// = strlen(message);//the  length  of  message
	unsigned char ZA[SM3_len / 8];//ZA=Hash(ENTLA||  IDA||  a||  b||  Gx  ||  Gy  ||  xA||  yA) 
	unsigned char Msg[210];  //210=IDA_len+2+SM2_NUMWORD*6

	int temp;

	//miracl *mip = mirsys(10000, 16);
	//mip->IOBASE = 16;
	MirsysInit();

	len = 32;
	memcpy(message, dA, 32);

	temp = SM2_KeyGeneration(dA, xA, yA);
	if (temp)
		return temp;

	//  ENTLA||  IDA||  a||  b||  Gx  ||  Gy  ||  xA||  yA 
	memcpy(Msg, ENTLA, 2);
	memcpy(Msg + 2, IDA, IDA_len);
	memcpy(Msg + 2 + IDA_len, SM2_a, SM2_NUMWORD);
	memcpy(Msg + 2 + IDA_len + SM2_NUMWORD, SM2_b, SM2_NUMWORD);
	memcpy(Msg + 2 + IDA_len + SM2_NUMWORD * 2, SM2_Gx, SM2_NUMWORD);
	memcpy(Msg + 2 + IDA_len + SM2_NUMWORD * 3, SM2_Gy, SM2_NUMWORD);
	memcpy(Msg + 2 + IDA_len + SM2_NUMWORD * 4, xA, SM2_NUMWORD);
	memcpy(Msg + 2 + IDA_len + SM2_NUMWORD * 5, yA, SM2_NUMWORD);
	SM3_256(Msg, 210, ZA);

	temp = SM2_Sign(message, len, ZA, rand, dA, r, s);
	if (temp)
		return temp;

	temp = SM2_Verify(message, len, ZA, xA, yA, r, s);
	if (temp)
		return temp;

	return 0;
}