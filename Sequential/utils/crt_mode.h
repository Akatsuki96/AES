#include "aes.h"


int ctr_enc(unsigned char* plain, unsigned char* key,unsigned char iv[16],unsigned char* sub_keys,int rounds,uint8_t* encripted);
void ctr_dec(char* encoded, char* key,unsigned char iv[16],unsigned char* sub_keys,int rounds,uint8_t* decripted,int size);
