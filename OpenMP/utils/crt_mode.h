#include "aes.h"

enum aes_version{
  AES128,
  AES192,
  AES256
};



void ctr_enc(char* plain, char* key,unsigned char iv[16],unsigned char* sub_keys,int rounds,uint8_t* encripted,enum aes_version v);
void ctr_dec(char* plain, char* key,unsigned char iv[16],unsigned char* sub_keys,int rounds,uint8_t* encripted,enum aes_version v);
