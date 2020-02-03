//#include "../utils/aes.h"
#include "../utils/crt_mode.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#ifndef SIZE
#define SIZE 20000
#endif
#define ROUNDS 10
#define CODELEN 16


int main(int argc, char** argv){

  if(argc < 2){
    printf("[xx] Usage: ./aes_test file\nFile must contain the string to encript and decript!\n");
    return 1;
  }
  unsigned char encripted[SIZE+1];
  unsigned char decripted[SIZE+1];
  unsigned char sub_keys[ROUNDS][CODELEN];

  unsigned char plain[SIZE+1];
  int fd = open(argv[1],O_RDWR);
  if(fd < 0){
    printf("[xx] Error: couldn't open the file!\n");
   return 1;
  }
  int read_bytes = read(fd,&plain[0],SIZE);
  if(read_bytes<0){
    printf("[xx] Error: couldn't read the file!\n");
   return 1;
  }
  close(fd);
  unsigned char* key = "K1ng_G30rg3_rul3";
  unsigned char iv[16]={0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};
  build_subkeys(key,&sub_keys[0][0],16,ROUNDS+1);
  printf("[--] Plain Text: %s\n",plain);
  ctr_enc(plain,key,&iv[0],&sub_keys[0][0],10,&encripted[0],AES128);
  printf("[--] CTR encripted: %s\n",encripted);
  unsigned char iv2[16]={0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};
  ctr_dec(encripted,key,&iv2[0],&sub_keys[0][0],10,&decripted[0],AES128);
  printf("[--] CTR Decripted: %s\n",decripted);
  assert(strcmp(plain,decripted)==0);
  return 0;
}
