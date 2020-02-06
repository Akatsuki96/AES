#include "aes.h"


void print_matrix(unsigned char* mat, int rowsize){
  for(int i = 0; i < rowsize; i++){
    printf("| ");
    for(int j = 0; j < rowsize; j++){
      printf(" %x |",mat[i*rowsize+j]);
    }
    printf("\n");
  }
}

void build_matrix(unsigned char* str,unsigned char mat[][4],int rowsize){
  for(int i = 0; i < rowsize; i++)
    for(int j = 0; j < rowsize; j++){
      mat[i][j] = str[i*rowsize+j];
    }
}

void sub_bytes(unsigned char* mat, int totsize){
  for(int i = 0; i < totsize; i++)
    mat[i] = get_sbox_value(mat[i]);
}

void inv_sub_bytes(unsigned char* mat, int totsize){
  for(int i = 0; i < totsize; i++)
    mat[i] = get_rsbox_value(mat[i]);
}


void left_shift_rows(unsigned char* mat, int rowsize, int totsize){
  int k,tmp;
  for(int i = 1; i < rowsize; i++){
    for(int j = 0; j < i; j++){
      tmp = mat[i*rowsize];
      for(k = 0; k < rowsize-1; k++)
        mat[i*rowsize+k] = mat[i*rowsize+k+1];
      mat[i*rowsize+k] = tmp;
    }
  }
}

void right_shift_rows(unsigned char* mat, int rowsize){
  int to_shift = 0;
  int act = rowsize;
  int k,tmp;
  for(int i = 1; i < rowsize; i++){
    for(int j = 0; j < i; j++){
      tmp = mat[i*rowsize+rowsize-1];
      for(int k = rowsize-1; k > 0; k--)
        mat[i*rowsize+k] = mat[i*rowsize+k-1];
      mat[i*rowsize] = tmp;
    }
  }
}

void mix_column128(unsigned char* text_mat, int totsize){
  unsigned char b0, b1, b2, b3;
  unsigned char result[totsize];
  int i;
	for (i = 0; i < 4; i ++){
		b0 = text_mat[i];
		b1 = text_mat[i + 4];
		b2 = text_mat[i + 8];
		b3 = text_mat[i + 12];
		result[i] = mul[b0][0] ^ (mul[b1][0]^b1) ^ b2 ^ b3;
		result[i + 4] = b0 ^ mul[b1][0] ^ (mul[b2][0]^b2) ^ b3;
		result[i + 8] = b0 ^ b1 ^ mul[b2][0] ^ (mul[b3][0]^b3);
		result[i + 12] = (mul[b0][0]^b0) ^ b1 ^ b2 ^ mul[b3][0];
	}
  for(i = 0; i < totsize; i++)
    text_mat[i]=result[i];
}

void inv_mix_column128(unsigned char* text_mat){
  unsigned char b0, b1, b2, b3;
  unsigned char result[16];
  int i;
	for (i = 0; i < 4; i ++){
		b0 = text_mat[i];
		b1 = text_mat[i + 4];
		b2 = text_mat[i + 8];
		b3 = text_mat[i + 12];
		result[i] = mul[b0][5] ^ mul[b1][3] ^ mul[b2][4] ^ mul[b3][2];
		result[i + 4] = mul[b0][2] ^ mul[b1][5] ^ mul[b2][3] ^ mul[b3][4];
		result[i + 8] = mul[b0][4] ^ mul[b1][2] ^ mul[b2][5] ^ mul[b3][3];
		result[i + 12] = mul[b0][3] ^ mul[b1][4] ^ mul[b2][2] ^ mul[b3][5];
	}
  for(i = 0; i < 16; i++)
    text_mat[i]=result[i];
}


void build_subkeys(unsigned char* key,unsigned char* sub_keys, int totsize,int rounds){
  for(int i = 0; i < rounds; i++){
    if(i == 0){
      for(int j = 0; j < totsize; j++){
        sub_keys[j] = (key[j] == 0x0)?0x0:key[j];
      }
    }else{
      sub_keys[i*totsize] = (sub_keys[(i-1)*totsize]^(get_sbox_value(sub_keys[(i-1)*totsize+13]) ^rc[i-1]));
      sub_keys[i*totsize+1] = (sub_keys[(i-1)*totsize+1]^get_sbox_value(sub_keys[(i-1)*totsize+14]));
      sub_keys[i*totsize+2] = (sub_keys[(i-1)*totsize+2]^get_sbox_value(sub_keys[(i-1)*totsize+15]));
      sub_keys[i*totsize+3] = (sub_keys[(i-1)*totsize+3]^get_sbox_value(sub_keys[(i-1)*totsize+12]));

      for(int j = 4; j < totsize; j+=4){
        sub_keys[i*totsize+j] = (sub_keys[(i*totsize)+j-4]^sub_keys[((i-1)*totsize)+j]);
        sub_keys[i*totsize+(j+1)] = (sub_keys[(i*totsize)+j-3]^sub_keys[((i-1)*totsize)+j+1]);
        sub_keys[i*totsize+(j+2)] = (sub_keys[(i*totsize)+j-2]^sub_keys[((i-1)*totsize)+j+2]);
        sub_keys[i*totsize+(j+3)] = (sub_keys[(i*totsize)+j-1]^sub_keys[((i-1)*totsize)+j+3]);
      }
    }
  }
}

void xor_key(char* text, char* key, int rowsize){
  for(int i = 0; i < rowsize; i++)
    for(int j = 0; j < rowsize; j++)
      text[i*rowsize+j] = text[i*rowsize+j] ^ key[i*rowsize+j];
}


void aes_encript(unsigned char* text, unsigned char* key,unsigned char* sub_keys, char* encripted,int rounds,int rowsize){
  int tot_size = rowsize * rowsize;
  unsigned char text_mat[rowsize][rowsize];
  build_matrix(&text[0],text_mat,rowsize);
  xor_key(&text_mat[0][0],sub_keys,rowsize);
  for(int r = 0; r < rounds-1; r++){
    sub_bytes(&text_mat[0][0],tot_size);
    left_shift_rows(&text_mat[0][0],rowsize,tot_size);
    mix_column128(&text_mat[0][0],tot_size);
    xor_key(&text_mat[0][0],&sub_keys[r*(rounds+1)+1],rowsize);
  }
  sub_bytes(&text_mat[0][0],tot_size);
  left_shift_rows(&text_mat[0][0],rowsize,tot_size);
  xor_key(&text_mat[0][0],&sub_keys[rounds*(rounds+1)],rowsize);
  for(int i = 0; i < rowsize; i++)
    for(int j = 0; j < rowsize; j++)
      encripted[i*rowsize+j] = text_mat[i][j];
}

void aes_decript(char* text, char* key,unsigned char* sub_keys,
    unsigned char* decripted,int rounds,int rowsize){
  int tot_size = rowsize * rowsize;
  unsigned char text_mat[rowsize][rowsize];
  build_matrix(text,text_mat,rowsize);
  xor_key(&text_mat[0][0],&sub_keys[rounds*(rounds+1)],rowsize);
  right_shift_rows(&text_mat[0][0],rowsize);
  inv_sub_bytes(&text_mat[0][0],tot_size);

  for(int r = rounds-1; r > 0; --r){
    xor_key(&text_mat[0][0],&sub_keys[r*(rounds+1)],rowsize);
    inv_mix_column128(&text_mat[0][0]);
    right_shift_rows(&text_mat[0][0],rowsize);
    inv_sub_bytes(&text_mat[0][0],tot_size);
  }
  xor_key(&text_mat[0][0],sub_keys,rowsize);
  for(int i = 0; i < rowsize; i++)
    for(int j = 0; j < rowsize; j++)
      decripted[i*rowsize+j] = text_mat[i][j];
}



void aes128_encript(unsigned char* to_enc, unsigned char* key,unsigned char* sub_keys, char* encripted){
  aes_encript(to_enc,key,sub_keys,encripted,10,4);
}


void aes128_decript(unsigned char* to_dec, char* key,unsigned char* sub_keys,unsigned char* decripted){
  aes_decript(to_dec,key,sub_keys,decripted,10,4);
}
