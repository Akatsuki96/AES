//#include "../utils/aes.h"
#include "../utils/crt_mode.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#ifndef SIZE
#define SIZE 3009999
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
  unsigned char* encripted = new unsigned char[SIZE];
  unsigned char* decripted = new unsigned char[SIZE];
  unsigned char* sub_keys = new unsigned char[(ROUNDS+1)*CODELEN];
  unsigned char* plain = new unsigned char[SIZE];
  int fd = open(argv[1],O_RDWR);
  if(fd < 0){
    printf("[xx] Error: couldn't open the file!\n");
   return 1;
  }
  int read_bytes = read(fd,plain,SIZE);
  if(read_bytes<0){
    printf("[xx] Error: couldn't read the file!\n");
   return 1;
  }
  close(fd);
  unsigned char key[]="K1ng_G30rg3_rul3";//{'K','1','n','g','_','G','3','0','r','g','3','_','r','u','l','3'};//{'K'1ng_G30rg3_rul3"};
  //strncpy(key,"K1ng_G30rg3_rul3",16);
  build_subkeys(&key[0],sub_keys,16,ROUNDS+1);
  #ifdef DEBUG
  printf("[--] Plain Text: %s\n",plain);
  #endif
  int size = ctr_exec(plain,encripted,sub_keys,10,read_bytes);
  #ifdef DEBUG
  printf("[--] CTR encripted: %s\n",encripted);
  #endif
  ctr_exec(encripted,decripted,sub_keys,10,size*16);
  #ifdef DEBUG
  printf("[--] CTR Decripted: %s\n",decripted);
  assert(bytencmp(plain,decripted,read_bytes)==0);
  #endif
//  free(key);
  return 0;
}
