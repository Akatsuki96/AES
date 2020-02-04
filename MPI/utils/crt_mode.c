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

int ctr_enc(int rank, int nprocs,unsigned char* plain, unsigned char* key,unsigned char iv[16],unsigned char* sub_keys,int rounds,uint8_t* encripted,int text_length){
  int num_blocks = (text_length / 16)+((text_length % 16)!=0);
  unsigned char counters[num_blocks][16];
  unsigned char blocks[num_blocks][16];

  int thread_nblock = num_blocks / nprocs;
  unsigned char process_counters[thread_nblock][16];
  unsigned char partial_blocks[thread_nblock][16];
  unsigned char recv_blocks[num_blocks][16];


  if(sub_keys==NULL) build_subkeys(key,sub_keys,16,rounds+1);

  if(rank == 0){

    // master node init counters and blocks
    build_counters(&iv[0],num_blocks,&counters[0]);
    build_blocks(plain,num_blocks,blocks,text_length);
  }
  MPI_Scatter(&counters[0][0],thread_nblock*16,MPI_CHAR,&process_counters[0][0],thread_nblock*16,MPI_CHAR,0,MPI_COMM_WORLD);
  //}else{
  for(int i = 0; i < thread_nblock; i++){
//    uint8_t block[16];
    aes128_encript(&process_counters[i][0],key,sub_keys,partial_blocks[i]);
  //    xor_string(block,blocks[i],&encripted[i*16]);
  //    encripted[i*16+16]=0x0;
  }
  if(rank !=0){
    MPI_Gather(&partial_blocks[0],thread_nblock*16,MPI_CHAR,NULL,thread_nblock*16,MPI_CHAR,0,MPI_COMM_WORLD);
  }else{
  //}
    MPI_Gather(&partial_blocks[0],thread_nblock*16,MPI_CHAR,&recv_blocks[0],thread_nblock*16,MPI_CHAR,0,MPI_COMM_WORLD);
    for(int i = 0; i < num_blocks; i++){
      xor_string(recv_blocks[i],blocks[i],&encripted[i*16]);
      encripted[i*16+16]=0x0;
    }
    encripted[(num_blocks)*16] = 0x0;
    printf("[--] CTR encripted: %s\n",encripted);
  }
//  MPI_Finalize();

  return num_blocks;
}

int encoded_len(char* encoded){
  int count = 0;
  while(encoded[count]!=0x0 && encoded[count+1]!=0x0)
    count+=16;
  return count;
}

void ctr_dec(int rank, int nprocs,char* encoded, char* key,unsigned char iv[16],unsigned char* sub_keys,int rounds,uint8_t* decripted,int text_length){
  int num_blocks = (text_length / 16);
  unsigned char counters[num_blocks][16];
  unsigned char blocks[num_blocks][16];

//  MPI_Init_thread( &argc, &argv, MPI_THREAD_FUNNELED, &provided);

// 	MPI_Comm_size (MPI_COMM_WORLD, &nprocs);
  //MPI_Comm_rank (MPI_COMM_WORLD, &rank);

  int thread_nblock = num_blocks / nprocs;
  unsigned char process_counters[thread_nblock][16];
  unsigned char partial_blocks[thread_nblock][16];
  unsigned char recv_blocks[num_blocks][16];


  if(sub_keys==NULL) build_subkeys(key,sub_keys,16,rounds+1);

  if(rank == 0){
    // master node init counters and blocks
    build_counters(&iv[0],num_blocks,&counters[0]);
    build_blocks(encoded,num_blocks,blocks,text_length);
  }
  MPI_Scatter(&counters[0][0],thread_nblock*16,MPI_CHAR,&process_counters[0][0],thread_nblock*16,MPI_CHAR,0,MPI_COMM_WORLD);
  //}else{
  for(int i = 0; i < thread_nblock; i++){
//    uint8_t block[16];
    aes128_encript(&process_counters[i][0],key,sub_keys,partial_blocks[i]);
  //    xor_string(block,blocks[i],&encripted[i*16]);
  //    encripted[i*16+16]=0x0;
  }
  if(rank!=0){
    MPI_Gather(&partial_blocks[0],thread_nblock*16,MPI_CHAR,NULL,thread_nblock*16,MPI_CHAR,0,MPI_COMM_WORLD);
  }else{
    MPI_Gather(&partial_blocks[0],thread_nblock*16,MPI_CHAR,&recv_blocks[0],thread_nblock*16,MPI_CHAR,0,MPI_COMM_WORLD);

    for(int i = 0; i < num_blocks; i++){
      xor_string(recv_blocks[i],blocks[i],&decripted[i*16]);
      decripted[i*16+16]=0x0;
    }
    decripted[(num_blocks)*16] = 0x0;
    printf("[--] CTR Decripted: %s\n",decripted);
  }
}
