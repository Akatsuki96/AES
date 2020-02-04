#include "aes.h"


int ctr_enc(int rank, int nprocs,unsigned char* plain, unsigned char* key,unsigned char iv[16],unsigned char* sub_keys,int rounds,uint8_t* encripted,int size);
void ctr_dec(int rank, int nprocs,char* encoded, char* key,unsigned char iv[16],unsigned char* sub_keys,int rounds,uint8_t* decripted,int size);
