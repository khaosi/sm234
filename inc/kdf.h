/************************************************************************
FileName:KDF.h
Version:
KDF_V1.1
Date:
Sep 24,2016
Description:
This  headfile  provides  KDF  function  needed  in  SM2  algorithm Function  List:
1.SM3_256	//calls  SM3_init、SM3_process  and  SM3_done  to  calculate  hash  value 2.SM3_init	//init  the  SM3  state
3.SM3_process	//compress  the  the  first  len/64  blocks  of  the  message 4.SM3_done	//compress  the  rest  message  and  output  the  hash  value
5.SM3_compress	//called  by  SM3_process  and  SM3_done,  compress  a  single  block  of  message 6.BiToW	//called  by  SM3_compress,to  calculate  W  from  Bi
7.	WToW1	//called  by  SM3_compress,  calculate  W'  from  W
8.	CF	//called  by  SM3_compress,  to  calculate  CF  function.
9.	BigEndian	//called  by  SM3_compress  and  SM3_done.GM/T  0004-2012  requires  to  use big-endian.
 

change the
 
//if  CPU  uses  little-endian,  BigEndian  function  is  a  necessary  call  to

//little-endian  format  into  big-endian  format.
 
10.	SM3_KDF	//calls  SM3_init、SM3_process  and  SM3_done  to  generate  key  stream
History:
1.  Date:	Sep  18,2016
Author:  Mao  Yingying,  Huo  Lili
Modification:  Adding  notes  to  all  the  functions
************************************************************************/

#include  <string.h>
#include "sm3.h"

extern void  BiToWj(unsigned  long  Bi[],  unsigned  long  Wj[]); 
extern void  WjToWj1(unsigned  long  Wj[],  unsigned  long  Wj1[]);
extern void  CF(unsigned  long  Wj[],  unsigned  long  Wj1[],  unsigned  long  V[]);
extern void  BigEndian(unsigned  char  src[],  unsigned  int  bytelen,  unsigned  char  des[]); 
extern void  SM3_init(SM3_STATE  *md);
extern void  SM3_compress(SM3_STATE  *  md);
extern void  SM3_process(SM3_STATE  *  md,  unsigned  char  buf[],  int  len); 
extern void  SM3_done(SM3_STATE  *md,  unsigned  char  *hash);
extern void  SM3_256(unsigned  char  buf[],  int  len,  unsigned  char  hash[]);
extern void  SM3_KDF(unsigned  char  *Z  ,unsigned  short  zlen,unsigned  short  klen,unsigned  char  *K);

 
