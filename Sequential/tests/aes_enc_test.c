//#include "../utils/aes.h"
#include "../utils/crt_mode.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#ifndef SIZE
#define SIZE 309999
#endif
#define ROUNDS 10
#define CODELEN 16

int bytencmp(unsigned char* str1, unsigned char* str2, size_t len){
  for(int i = 0; i < len; i++)
    if(str1[i] != str2[i]) return str1[i] - str2[i];
  return 0;
}

int main(int argc, char** argv){
  if(argc < 2){
    printf("[xx] Usage: ./aes_test file\nFile must contain the string to encript and decript!\n");
    return 1;
  }
  unsigned char encripted[SIZE];
  unsigned char sub_keys[ROUNDS+1][CODELEN];

  unsigned char plain[SIZE];
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
  int size = ctr_enc(plain,key,&iv[0],&sub_keys[0][0],10,&encripted[0],strlen(plain));
  //printf("[--] CTR encripted: %s\n",encripted);
  return 0;
}
