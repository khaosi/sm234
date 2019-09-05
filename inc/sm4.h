/************************************************************ 
FileName:sm4.h
Version:SM4_V1.0
Date:Sep 13,2016
Description:
This headfile provide macro defination, parameter definition and function declaration needed in  SM4  algorithm  implement.
Function  List:
1.	SM4_KeySchedule  //Generate  the  required  round  keys
2.	SM4_Encrypt	//Encryption  function
3.	SM4_Decrypt	//Decryption  function
4.	SM4_SelfCheck	//Self-check History:
Date:Sep  13,2016
Author:Mao  Yingying,Huo  Lili
Modification:  1)add  notes  to  all  the  functions
2)add  SM4_SelfCheck  function
************************************************************/
#ifndef __SM4_H__
#define __SM4_H__

#include<stdio.h>

//rotate n bits to the left in a 32bit buffer

#define SM4_Rotl32(buf,  n)  (((buf)<<n)|((buf)>>(32-n)))

void SM4_KeySchedule(unsigned  char  MK[],    unsigned  int  rk[]);
void SM4_Encrypt(unsigned  char  MK[],unsigned  char  PlainText[],unsigned  char  CipherText[]);
void SM4_Decrypt(unsigned  char  MK[],unsigned  char  CipherText[],  unsigned  char  PlainText[]);
int  SM4_SelfTest();

#endif
