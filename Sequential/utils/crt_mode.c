#include "crt_mode.h"
#include "assert.h"

void update_iv(uint8_t iv[16],int counter){
  snprintf(iv,16,"%d",atoi(iv)+counter);
  printf("[--] New IV: ");
  for(int i = 0; i < 16; i++)
    printf("%02x",iv[i]);
  printf("\n");
}

void xor_string(unsigned char* str1, unsigned char* str2, unsigned char* result){
  for(int i = 0; i < 16; i++){
    result[i] = str1[i] ^ str2[i];
  }
}

void build_counters(unsigned char iv[16], int num_blocks,unsigned char (*counters)[16]){
  for(int i = 0; i < num_blocks; i++){
    for(int j = 0; j < 16; j++) counters[i][j] = iv[j];
    for(int j = 15; j > 0; j--){
      if(iv[j] == 255){iv[j]=0; continue;}
      iv[j]++;
      break;
    }
  }
}

void build_blocks(unsigned char* plain, int num_blocks, unsigned char (*blocks)[16]){
  for(int i = 0; i < num_blocks; i++){
    strncpy(&blocks[i][0],&plain[i*16],16);
  }
}

void print_counters(unsigned char (*counters)[16],int num_blocks){
  for(int i = 0; i < num_blocks; i++){
    printf("[--] Counter %d: ", i);
    for(int j = 0; j < 16; j++)
      printf("%02x",counters[i][j]);
    printf("\n");
  }
}


void print_blocks(unsigned char (*blocks)[16],int num_blocks){
  for(int i = 0; i < num_blocks; i++){
    printf("[--] Block %d: ", i);
    for(int j = 0; j < 16; j++)
      printf("%02x [%c]|",blocks[i][j],blocks[i][j]);
    printf("\n");
  }
}

void ctr_enc(char* plain, char* key,unsigned char iv[16],unsigned char* sub_keys,int rounds,uint8_t* encripted,enum aes_version v){
  int text_length = strlen(plain);
  int num_blocks = (text_length / 16)+((text_length % 16)!=0);
  unsigned char counters[num_blocks][16];
  unsigned char blocks[num_blocks][16];

  if(sub_keys==NULL)
    build_subkeys(key,sub_keys,16,rounds+1);

  build_counters(&iv[0],num_blocks,&counters[0]);
  build_blocks(&plain[0],num_blocks,&blocks[0]);
  #ifdef DEBUG
  print_counters(&counters[0],num_blocks);
  print_blocks(&blocks[0],num_blocks);
  #endif
  for(int i = 0; i < num_blocks; i++){
    uint8_t block[16];
    aes128_encript(&counters[i][0],key,sub_keys,block);
    xor_string(&block[0],&blocks[i][0],&encripted[i*16]);
  }
  encripted[16*num_blocks] = 0x0;
}


void ctr_dec(char* encoded, char* key,unsigned char iv[16],unsigned char* sub_keys,int rounds,uint8_t* decripted,enum aes_version v){
  int text_length = strlen(encoded);
  int num_blocks = (text_length / 16);
  unsigned char counters[num_blocks][16];
  unsigned char blocks[num_blocks][16];
  if(sub_keys==NULL)
    build_subkeys(key,sub_keys,16,rounds+1);

  build_counters(iv,num_blocks,&counters[0]);
  build_blocks(encoded,num_blocks,&blocks[0]);
  #ifdef DEBUG
  print_counters(&counters[0],num_blocks);
  print_blocks(&blocks[0],num_blocks);
  #endif
  for(int i = 0; i < num_blocks; i++){
    uint8_t block[16];
    aes128_encript(&counters[i][0],key,sub_keys,block);
    xor_string(&block[0],&blocks[i][0],&decripted[i*16]);
  }
  decripted[16*num_blocks] = 0x0;
}
