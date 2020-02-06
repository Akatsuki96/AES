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
  //  printf("BL: %02x PL: %02x X: %02x\n",str1[i],str2[i],str1[i]^str2[i]);
    result[i] = str1[i] ^ str2[i];
  //  printf("ST[%d]: %02x\n",i,result[i]);
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

void build_blocks(unsigned char* plain, int num_blocks, unsigned char (*blocks)[16],int size){
  for(int i = 0; i < num_blocks; i++){
    for(int j = 0; j < 16 ; j++){
      blocks[i][j]=plain[i*16+j];
    }
    //strncpy(&blocks[i][0],&plain[i*16],16);
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

int ctr_enc(unsigned char* plain, unsigned char* key,unsigned char iv[16],unsigned char* sub_keys,int rounds,uint8_t* encripted,int text_length){
  int num_blocks = (text_length / 16)+((text_length % 16)!=0);
  unsigned char counters[num_blocks][16];
  unsigned char blocks[num_blocks][16];

  for(int i = 0; i < text_length; i++)
    encripted[i] = 0;

  if(sub_keys==NULL)
    build_subkeys(key,sub_keys,16,rounds+1);

  build_counters(&iv[0],num_blocks,&counters[0]);
  build_blocks(plain,num_blocks,blocks,text_length);
  for(int i = 0; i < num_blocks; i++){
    uint8_t block[16];
    aes128_encript(&counters[i][0],key,sub_keys,block);
    xor_string(block,blocks[i],&encripted[i*16]);
    encripted[i*16+16]=0x0;
  }
  encripted[(num_blocks)*16] = 0x0;
  return num_blocks;
}

int encoded_len(char* encoded){
  int count = 0;
  while(encoded[count]!=0x0 && encoded[count+1]!=0x0)
    count+=16;
  return count;
}

void ctr_dec(char* encoded, char* key,unsigned char iv[16],unsigned char* sub_keys,int rounds,uint8_t* decripted,int size){
  int text_length = size;//encoded_len(encoded);
  for(int i = 0; i < text_length; i++)
    decripted[i] = 0;

  int num_blocks = (text_length / 16);
  unsigned char counters[num_blocks][16];
  unsigned char blocks[num_blocks][16];
  if(sub_keys==NULL) build_subkeys(key,sub_keys,16,rounds+1);

  build_counters(iv,num_blocks,&counters[0]);
  build_blocks(encoded,num_blocks,&blocks[0],text_length);
  for(int i = 0; i < num_blocks; i++){
    uint8_t block[16];
    aes128_encript(&counters[i][0],key,sub_keys,block);
    xor_string(&block[0],&blocks[i][0],&decripted[i*16]);
  }
  decripted[16*num_blocks] = 0x0;
}
