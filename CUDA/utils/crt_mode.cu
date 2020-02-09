#include "crt_mode.h"
#include "assert.h"

/*
void update_iv(unsigned char* iv[16],int counter){
  snprintf(iv,16,"%d",atoi(iv)+counter);
  printf("[--] New IV: ");
  for(int i = 0; i < 16; i++)
    printf("%02x",iv[i]);
  printf("\n");
}*/

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

int ctr_exec(unsigned char* plain, unsigned char* result, unsigned char* sub_keys, int rounds,int text_length){
  int num_blocks = (text_length / 16)+((text_length % 16)!=0);
	int tpb = 1024;

	if(sub_keys == NULL){
		printf("[xx] Error: you must pass the subkeys set!\n");
		exit(1);
	}

	// map message in gpu
	unsigned char* dev_plain;
	cudaMalloc((void**)&dev_plain,text_length*sizeof(unsigned char));
	cudaMemcpy(dev_plain,plain,text_length*sizeof(unsigned char),cudaMemcpyHostToDevice);

	// map result zone in gpu
	unsigned char *dev_result;
	cudaMalloc((void **)&dev_result, text_length * sizeof(unsigned char));
	cudaMemcpy(dev_result, plain, text_length * sizeof(unsigned char), cudaMemcpyHostToDevice);

	// map sbox on gpu
	unsigned char *dev_sbox;
	cudaMalloc((void **)&dev_sbox, 256 * sizeof(unsigned char));
	cudaMemcpy(dev_sbox, sbox, 256 * sizeof(unsigned char), cudaMemcpyHostToDevice);

	//map subkeys on gpu
	unsigned char *dev_keys;
	cudaMalloc((void **)&dev_keys, 10 * 16 * sizeof(unsigned char));
	cudaMemcpy(dev_keys, sub_keys, 10 * 16 * sizeof(unsigned char), cudaMemcpyHostToDevice);

	//execute aes
	int blck = ceil(num_blocks/tpb)==0?1:ceil(num_blocks/tpb);
  aes_encript<<<num_blocks , tpb>>>(dev_plain, dev_result, dev_sbox, dev_keys, text_length);

	//map result to main memory
	cudaMemcpy(result, dev_result, text_length * sizeof(unsigned char), cudaMemcpyDeviceToHost);
	result[text_length]=0x0;
//	printf("[--] RES: %s\n",result);
	//free cuda
	cudaFree(dev_result);
	cudaFree(dev_plain);
	cudaFree(dev_keys);
	cudaFree(dev_sbox);

	return num_blocks;
}
