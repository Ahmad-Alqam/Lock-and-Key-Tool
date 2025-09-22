#ifndef DES_H
#define DES_H

// Hex/binary conversions
unsigned long long hexa_to_bin(const char *hexstr, int bits[64]);
unsigned long long bin_to_hex(int bits[], int nbits);
void bytes_to_bits(unsigned char *in, int bits[64]);
void bits_to_bytes(int bits[64], unsigned char *out);
// Key schedule functions
void parity_bit_drop(int key_bits[64], int key56[56]);
void split_key56(int key56[56], int C[28], int D[28]);
void left_circular_shift(int arr[28], int shifts);
void compression_permutation(int CD[56], int round_key[48]);
void generate_round_keys(int C[28], int D[28], int round_keys[16][48]);

// Encryption functions
void initial_permutation(int in64[64], int ip_out[64]);
void split_permuted_text(int ip_out[64], int L0[32], int R0[32]);
void expand_right(int R[32], int ER[48]);
void xor_bits(const int *a, const int *b, int n, int *out);
void sbox_layer(int in48[48], int out32[32]);
void p_permutation(int in32[32], int out32[32]);
void final_permutation(int in64[64], int fp_out[64]);
void reverse_round_keys(int enc_keys[16][48], int revesed_keys[16][48]);
void DES_encrypt(int plaintext[64], int round_keys[16][48], int ciphertext[64]);
void DES_decrypt(int ciphertext[64], int round_keys[16][48], int plaintext[64]);

#endif

