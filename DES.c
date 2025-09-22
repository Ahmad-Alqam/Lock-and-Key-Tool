#include <stdio.h>
#include <stdlib.h>

//step 1 hexa to binary conversion
unsigned long long hexa_to_bin(const char *hexstr, int bits[64]) {
    const char *p = hexstr;
    if (p[0]=='0' && (p[1]=='x' || p[1]=='X')) {
        p += 2;
    }
    unsigned long long value = 0ULL;
    while (*p) {
        char c = *p++;
        int v;
        if (c>='0' && c<='9') {
             v = c - '0';
        }
        else if (c>='a' && c<='f') {
            v = 10 + (c - 'a');
        } 
        else if (c>='A' && c<='F') {
            v = 10 + (c - 'A');
        } 
        else {
            continue; // skip non-hex
        }  
        value = (value << 4) | (unsigned)v;
    }
    for (int i = 63; i >= 0; --i) {     // expand to bits MSB-first
        bits[i] = (int)(value & 1ULL);
        value >>= 1;
    }
    return 0ULL;
}

//binary to hexadecimal
unsigned long long bin_to_hex(int bits[], int nbits) {
    unsigned long long value = 0;

    // pack bits into integer
    for (int i = 0; i < nbits; i++) {
        value = (value << 1) | bits[i];
    }
    return value;
}

// Convert 8 bytes to 64 bits (MSB first)
void bytes_to_bits(unsigned char *in, int bits[64]) {
    for(int i = 0; i < 8; i++){
        for(int j = 0; j < 8; j++){
            bits[i*8 + j] = (in[i] >> (7-j)) & 1;
        }
    }
}

// Convert 64 bits to 8 bytes (MSB first)
void bits_to_bytes(int bits[64], unsigned char *out){
    for(int i = 0; i < 8; i++){
        out[i] = 0;
        for(int j = 0; j < 8; j++){
            out[i] |= bits[i*8 + j] << (7-j);
        }
    }
}

//step 2 parity bit drop (64-bit -> 56 bits_
void parity_bit_drop(int key_bits[64], int key56[56]) {
    int table[56] = {
        57,49,41,33,25,17,9,
        1,58,50,42,34,26,18,
        10,2,59,51,43,35,27,
        19,11,3,60,52,44,36,
        63,55,47,39,31,23,15,
        7,62,54,46,38,30,22,
        14,6,61,53,45,37,29,
        21,13,5,28,20,12,4
    };

    for (int i = 0; i < 56; i++) {
        key56[i] = key_bits[table[i] - 1]; 
    }
}

//step 3
void split_key56(int key56[56], int C[28], int D[28]) {
    for (int i = 0; i < 28; i++) {
        C[i] = key56[i];       // left 28 bits
        D[i] = key56[i + 28];  // right 28 bits
    }
}

//step 4
// Left circular shift for 28-bit half
void left_circular_shift(int arr[28], int shifts) {
    int temp[28];
    for (int i = 0; i < 28; i++) {
        temp[i] = arr[(i + shifts) % 28];
    }
    for (int i = 0; i < 28; i++) {
        arr[i] = temp[i];
    }
}

// Apply Compression Permutation (PC-2) -> 48-bit key
void compression_permutation(int CD[56], int round_key[48]) {
    int key_Compression[48] = {
        14,17,11,24,1,5,
        3,28,15,6,21,10,
        23,19,12,4,26,8,
        16,7,27,20,13,2,
        41,52,31,37,47,55,
        30,40,51,45,33,48,
        44,49,39,56,34,53,
        46,42,50,36,29,32
    };
    for (int i = 0; i < 48; i++) {
        round_key[i] = CD[key_Compression[i] - 1];
    }
}

void generate_round_keys(int C[28], int D[28], int round_keys[16][48]) {
    int shift_table[16] = {
        1,1,2,2,2,2,2,2,
        1,2,2,2,2,2,2,1
    };

    for (int round = 0; round < 16; round++) {
        //perform left circular shifts
        left_circular_shift(C, shift_table[round]);
        left_circular_shift(D, shift_table[round]);

        //combine halves 
        int CD[56];
        for (int i = 0; i < 28; i++) {
            CD[i] = C[i];
            CD[i + 28] = D[i];
        }

        //compression permutation to 48-bit round key
        compression_permutation(CD, round_keys[round]);
    }
}
    //-----Encrption-----
void initial_permutation(int in64[64], int ip_out[64]) {
    int IP[64] = {
        58,50,42,34,26,18,10,2,
        60,52,44,36,28,20,12,4,
        62,54,46,38,30,22,14,6,
        64,56,48,40,32,24,16,8,
        57,49,41,33,25,17,9,1,
        59,51,43,35,27,19,11,3,
        61,53,45,37,29,21,13,5,
        63,55,47,39,31,23,15,7
    };
    for (int i = 0; i < 64; i++) {
        ip_out[i] = in64[IP[i] - 1];  // table is 1-based
    }
}

//step 3: splitting
void split_permuted_text(int ip_out[64], int L0[32], int R0[32]) {
    for (int i = 0; i < 32; i++) {
        L0[i] = ip_out[i];        // left half
        R0[i] = ip_out[i + 32];   // right half
    }
}

//step 4: expansion
void expand_right(int R[32], int ER[48]) {
    int E[48] = {
        32, 1, 2, 3, 4, 5,  4, 5, 6, 7, 8, 9,
         8, 9,10,11,12,13, 12,13,14,15,16,17,
        16,17,18,19,20,21, 20,21,22,23,24,25,
        24,25,26,27,28,29, 28,29,30,31,32, 1
    };
    for (int i = 0; i < 48; i++) {
        ER[i] = R[E[i] - 1]; // table is 1-based
    }
}

//XOR
void xor_bits(const int *a, const int *b, int n, int *out) {
    for (int i = 0; i < n; i++) {
        out[i] = (a[i] ^ b[i]) & 1;
    }
}
//S-boxes
int SBOX[8][4][16] = {
    { {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
      {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
      {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
      {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13} },
    { {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
      {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
      {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
      {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9} },
    { {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
      {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
      {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
      {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12} },
    { {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
      {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
      {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
      {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14} },
    { {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
      {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
      {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
      {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3} },
    { {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
      {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
      {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
      {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13} },
    { {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
      {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
      {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
      {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12} },
    { {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
      {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
      {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
      {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11} }
};

// --- S-box layer: 48 bits -> 32 bits ---
void sbox_layer(int in48[48], int out32[32]) {
    for (int i = 0; i < 8; i++) {
        // take 6 bits for box i
        int b0 = in48[i*6 + 0];
        int b1 = in48[i*6 + 1];
        int b2 = in48[i*6 + 2];
        int b3 = in48[i*6 + 3];
        int b4 = in48[i*6 + 4];
        int b5 = in48[i*6 + 5];

        int row = b0*2 + b5;                  // b1b6
        int col = b1*8 + b2*4 + b3*2 + b4;    // b2..b5

        int val = SBOX[i][row][col];          // 0..15

        // write 4 bits (MSB->LSB) without shifts
        int v = val;
        out32[i*4 + 0] = (v >= 8) ? 1 : 0; v %= 8;
        out32[i*4 + 1] = (v >= 4) ? 1 : 0; v %= 4;
        out32[i*4 + 2] = (v >= 2) ? 1 : 0; v %= 2;
        out32[i*4 + 3] = v;
    }
}

// --- P permutation: 32 -> 32 ---
void p_permutation(int in32[32], int out32[32]) {
    int P[32] = {
        16,7,20,21, 29,12,28,17,
         1,15,23,26, 5,18,31,10,
         2,8,24,14, 32,27,3,9,
        19,13,30,6, 22,11,4,25
    };
    for (int i = 0; i < 32; i++) {
        out32[i] = in32[P[i] - 1];
    }
}

// Final permutation (IP^-1): 64 -> 64
void final_permutation(int in64[64], int fp_out[64]) {
    int FP[64] = {
        40,8,48,16,56,24,64,32,
        39,7,47,15,55,23,63,31,
        38,6,46,14,54,22,62,30,
        37,5,45,13,53,21,61,29,
        36,4,44,12,52,20,60,28,
        35,3,43,11,51,19,59,27,
        34,2,42,10,50,18,58,26,
        33,1,41,9,49,17,57,25
    };
    for (int i = 0; i < 64; i++) {
        fp_out[i] = in64[FP[i] - 1];
    }
}

//reverse round keys
void reverse_round_keys(int enc_keys[16][48], int revesed_keys[16][48]) {
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 48; j++) {
            revesed_keys[i][j] = enc_keys[15 - i][j];
        }
    }
}

// 16-round DES encryption
void DES_encrypt(int plaintext[64], int round_keys[16][48], int ciphertext[64]) {
    int L[32], R[32], tempR[32];

    // Initial permutation
    int permuted[64];
    initial_permutation(plaintext, permuted);
    split_permuted_text(permuted, L, R);

    for (int round = 0; round < 16; round++) {
        int ER[48], xorR[48], sboxOut[32], pOut[32];

        expand_right(R, ER);
        xor_bits(ER, round_keys[round], 48, xorR);
        sbox_layer(xorR, sboxOut);
        p_permutation(sboxOut, pOut);

        for (int i = 0; i < 32; i++) {
            tempR[i] = L[i] ^ pOut[i];
            L[i] = R[i];
        }
        for (int i = 0; i < 32; i++) R[i] = tempR[i];
    }

    // Pre-output (swap L and R)
    int preout[64];
    for (int i = 0; i < 32; i++) {
        preout[i] = R[i];
        preout[i + 32] = L[i];
    }

    // Apply final permutation to get ciphertext
    final_permutation(preout, ciphertext);
}


// Decryption: use reversed keys
void DES_decrypt(int ciphertext[64], int round_keys[16][48], int plaintext[64]) {
    int reversed_keys[16][48];
    reverse_round_keys(round_keys, reversed_keys);
    DES_encrypt(ciphertext, reversed_keys, plaintext);
}

