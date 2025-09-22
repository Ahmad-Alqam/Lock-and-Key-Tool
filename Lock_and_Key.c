#include <stdio.h>
#include <stdbool.h>
#include <math.h>
#include <string.h>
#include <openssl/sha.h> //to apply built-in sha-256
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <stdlib.h>
#include <limits.h>  
#define PY_SCRIPT_PATH "/home/ahmad/Cryptography/image_encryption.py"
#include "DES.h"
#define DES_BLOCK_SIZE 8

void printMenu() {
    printf("\n-----Lock & Key-----\n");
    printf("1. Confidentiality Only\n");
    printf("2. Authentication Only\n");
    printf("3. Confidentiality & Authentication\n");
    printf("4. RSA Cryptanalysis (Short Message Attack)\n");
    printf("5. Image Encryption\n");
    printf("0. Exit\n");
}

void print_int128(__int128 value) {
    if (value == 0) {
        putchar('0');
        return;
    }
    if (value < 0) {
        putchar('-');
        value = -value;
    }
    char buffer[64];
    int i = 0;
    while (value > 0) {
        buffer[i++] = '0' + (value % 10);
        value /= 10;
    }
    while (i--) {
        putchar(buffer[i]);
    }
}

bool isPrime(long long number){
    if(number < 2) {
        return false;
    }

    for(long long i = 2; i <= sqrt(number); i++){
        if(number % i == 0){
            return false;
        }
    }
    return true;
}

// returns 1 if OK and fills p_out,q_out; otherwise 0.
int factor_n_two_primes(__int128 n, long long *p_out, long long *q_out) {
    if (n < 6) return 0; // smallest semiprime is 2*3
    for (long long p = 2; (__int128)p * p <= n; ++p) {
        if (n % p == 0) {
            __int128 q128 = n / p;
            if (q128 <= LLONG_MAX) {
                long long q = (long long)q128;
                if (isPrime(p) && isPrime(q) && (__int128)p * q == n) {
                    *p_out = p; *q_out = q;
                    return 1;
                }
            }
        }
    }
    return 0;
}

__int128 GCD(__int128 e, __int128 phi_n){
 __int128 q, r1 = e, r2 = phi_n, r;
    while (r2 > 0){
        q = r1 / r2;

        r = r1 - q * r2;
        r1 = r2;
        r2 = r;
    }
    return r1;
}

__int128 phi(__int128 number) {
    __int128 result = number;
    for (__int128 i = 2; i * i <= number; i++) {
        if (number % i == 0) {
            while (number % i == 0) {
                number /= i;
            }
            result -= result / i;
        }
    }
    if (number > 1) {
        result -= result / number;
    }
    return result;
}

__int128 square_and_multiply(__int128 base, __int128 exponent, __int128 modulus){
    if (modulus == 1) {
    	return 0;
    }

    __int128 result = 1 % modulus;
    __int128 b = ((base % modulus) + modulus) % modulus; //reduce base

    while (exponent > 0){
        if (exponent % 2 == 1){
            __int128 t = (__int128)result * b;
            result = (t % modulus);
        }
        __int128 s = (__int128)b * b;
        b = (s % modulus);

        exponent /= 2;  
    }
    return result;
}

//compute the bit length
__int128 size(__int128 n) {
    __int128 maxSize = 0;
    while(n > 0) {
        n /= 2;
        maxSize++;
    }
    return maxSize;
}

//compute the max size of the block to encrypt such that block < n
__int128 block_size(__int128 n) {
    if (n <= 1) {
        return 0;
    }
    __int128 bits = size(n);     //bit-length of n
    __int128 k = bits / 8;     //1 byte = 8 bits [floor(bits / 8)]
    if (k < 1) {
        k = 1;
    }

    //ensure 256^k < n 
    __int128 t = 1;
    for (__int128 i = 0; i < k; ++i) { //compute t = 256^k
        t *= 256;   
    }
    while (!(t < n) && k > 0) { //shrink until 256^k < n
        t /= 256; 
        k--; 
    }  
    return k;
}

__int128 MSGtoASCII(const char *msg, long long start, long long size) {
    __int128 x = 0;
    for (long long i = 0; i < size; i++) {
        x *= 256;
        x += ((__int128)msg[start + i]) & 255;
    }
    return x;
}

void ASCIItoMSG(char *msg, long long start, long long size, __int128 x) {
    for (long long i = size - 1; i >= 0; i--) {
        long long b = x % 256;  // 0..255
        x /= 256;
        msg[start + i] = (char)b;
    }
}

__int128 RSA_ENC(__int128 P, __int128 e, __int128 n) {
    return square_and_multiply(P, e, n);
}

__int128 RSA_DEC(__int128 C, __int128 d, __int128 n) {
    return square_and_multiply(C, d, n);
}

void num_to_letters(__int128 x, char *output) {
    char tmp[256];  //temporary array to store letters
    int n = 0;      //# of letters in the temporary array

    //start with the LSB then move to the next bit
    if (x == 0) {   
        tmp[n++] = 'A';                // 0 -> A
    } else {
        while (x > 0) {
            int d = (int)(x % 26);     //stays between 0..25
            tmp[n++] = (char)('A' + d); //convert the number to letter
            x /= 26;        //move to the next bit
        }
        // reverse temp to have the right order  tmp[0] = tmp[n - 1], tmp[1] = tmp[n - 2] and so on
        for (int i = 0, j = n - 1; i < j; ) {
            char t = tmp[i];
            tmp[i++] = tmp[j];
            tmp[j--] = t;
        }
    }
    
    //print (temp) the cipher value in letters
    __int128 packed = MSGtoASCII(tmp, 0, n);
    ASCIItoMSG(output, 0, n, packed);
    output[n] = '\0';
}

__int128 base26_to_i128(const char *s) {
    __int128 x = 0;
    for (int i = 0; s[i] != '\0'; i++) { //loop iterates until reach '\0'
        char c = s[i];  //read current character
        if (c >= 'A' && c <= 'Z') {
            x = x * 26 + (c - 'A');
        }
    }
    return x;
}

__int128 extendedEUCinv(__int128 n, __int128 m){
    if (m <= 1) {
        return -1;  
    }

    // Normalize n into [0, m-1]
    n %= m;
    if (n < 0) {
        n += m;
    }
    __int128 r1 = n, r2 = m;               
    __int128 t1 = 1, t2 = 0;               
    while (r2 > 0){
        __int128 q = r1 / r2;
        __int128 r = r1 - q * r2;  

        r1 = r2;
        r2 = r;

        __int128 t = t1 - q * t2;         
        t1 = t2;
        t2 = t;
    }

    if (r1 != 1) {
        return -1;                
    }
    __int128 MI = t1 % m;                  
    if (MI < 0) {
        MI += m;
    }
    return MI;
}

//convert 32-byte digest to integer mod n 
__int128 digest_to_int128(const unsigned char *dgst, __int128 n) {
    __int128 x = 0;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        x = (x * 256 + dgst[i]) % n;
    }
    return x;
}

void print_hex(const unsigned char *p, int len){
    for (int i = 0; i < len; i++) {
        printf("%02x", p[i]);
    }
}

//remove the trailing from a string
void chomp(char *s) {
    size_t n = strlen(s);
    if (n && s[n-1] == '\n') {
        s[n-1] = '\0';
    }
}

//remove the quotes 
void strip_wrapping_quotes(char *s) {
    size_t n = strlen(s);
    if (n >= 2 && ((s[0] == '"' && s[n-1] == '"') || (s[0] == '\'' && s[n-1] == '\''))) {
        // Schar_as_integerft characters left by 1
        for (size_t i = 1; i < n - 1; i++) {
            s[i - 1] = s[i];
        }
        // Null terminate
        s[n - 2] = '\0';
    }
}

//read the input from the user 
int read_line(const char *prompt, char *buf, size_t bufsz) {
    printf("%s", prompt);
    if (!fgets(buf, bufsz, stdin)) {
        return 0;
    }
    chomp(buf);
    return 1;
}

//validate the key is 16-digit hexadecimal 
int isHexa(const char *s) {
    const char *p = s;
    if (p[0]=='0' && (p[1]=='x' || p[1]=='X')) p += 2;
    int len = 0;
    for (; *p; ++p, ++len) {
        if (!isxdigit((unsigned char)*p)){
            return 0;
        }
    }
    return len == 16;
}

// Convert a pasted Windows UNC for WSL like:
//   \\wsl.localhost\Ubuntu-24.04\home\ahmad\Cryptography\image.jpg
// -> /home/ahmad/Cryptography/image.jpg
void normalize_wsl_path(char *path_inout) {
    strip_wrapping_quotes(path_inout);

    const char *prefix = "\\\\wsl.localhost\\";
    size_t prelen = strlen(prefix);
    if (strncmp(path_inout, prefix, prelen) == 0) {
        // Skip the distro name after the prefix
        const char *p = path_inout + prelen;            // points to "Ubuntu-24.04\home\ahmad\..."
        const char *back = strchr(p, '\\');             // first '\' after distro
        if (back) {
            const char *rest = back + 1;                // "home\ahmad\Cryptography\image.jpg"
            char buf[1024]; size_t j = 0;
            buf[j++] = '/';
            for (const char *q = rest; *q && j < sizeof(buf)-1; ++q) {
                buf[j++] = (*q == '\\') ? '/' : *q;
            }
            buf[j] = '\0';
            strncpy(path_inout, buf, 1023);
            path_inout[1023] = '\0';
            return;
        }
    }

    // Otherwise, just strip quotes; if it contains backslashes but not a Windows drive (C:\),
    // replace backslashes with forward slashes (safe for Linux paths that got backslashes).
    if (!(isalpha((unsigned char)path_inout[0]) && path_inout[1]==':' &&
          (path_inout[2]=='\\' || path_inout[2]=='/'))) {
        for (char *q = path_inout; *q; ++q) if (*q=='\\') *q = '/';
    }
}

static int hexa_to_integer(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1;
}

// CBC Decryption
long long Decrypt_CBC_CTS(const char *cipher_hex, const char *key_hex, const char *iv_hex, unsigned char *plaintext_out, long long plaintext_max)
{
    unsigned char Cipher_bytes[8192];
    int cipherbytes_length = 0, char_as_integer = -1;   //char_as_integer is empty at first
    for (const char *p = cipher_hex; *p; ++p) { //loop through each character in the ciphertext
        if (*p==' ' || *p=='\t' || *p=='\n' || *p=='\r') {
            continue;
        }
        int v = hexa_to_integer(*p);
        if (v < 0) {
            continue;
        }
        if (char_as_integer < 0) {
            char_as_integer = v;
        }
        else {
            if (cipherbytes_length >= (int)sizeof(Cipher_bytes)) {
                return -1;
            }
            Cipher_bytes[cipherbytes_length++] = (unsigned char)((char_as_integer<<4) | v);
            char_as_integer = -1;
        }
    }
    if (char_as_integer >= 0) { //if hex count is odd 
        return -1; 
    }
    if (cipherbytes_length <= 0 || cipherbytes_length > plaintext_max) { //empty ciphertext or larger than the destination buffer
        return -1;  
    }

    // DES keys and IV
    int key_bits[64], key56[56], Ck[28], Dk[28], round_keys[16][48];
    hexa_to_bin(key_hex, key_bits);     // key to binary
    parity_bit_drop(key_bits, key56);   // 64-bit -> 56-bit
    split_key56(key56, Ck, Dk);         // 56-bit -> 28-bit + 28-bit
    generate_round_keys(Ck, Dk, round_keys);    // generate 16 round keys

    int iv_bits[64];
    hexa_to_bin(iv_hex, iv_bits);      // IV to binary

    const int B = DES_BLOCK_SIZE;
    long long total = cipherbytes_length;
    if (total < B){ //if ciphertext length < block size
        return -1;
    } 

    // exact multiple of 8 -> normal CBC
    if (total % B == 0) {
        int prev[64], Cbits[64], Pbits[64];
        for (int i=0;i<64;i++) {
            prev[i] = iv_bits[i];
        }
        unsigned char block[8], outb[8];
        long long pos = 0, outpos = 0;

        while (pos < total) {    //loop through each cipher block
            for (int j=0;j<B;j++) block[j] = Cipher_bytes[pos+j];
            bytes_to_bits(block, Cbits);            
            DES_decrypt(Cbits, round_keys, Pbits);
            xor_bits(Pbits, prev, 64, Pbits);
            bits_to_bytes(Pbits, outb);
            for (int j=0;j<B;j++) {
                plaintext_out[outpos++] = outb[j];
            }
            for (int k=0;k<64;k++) {
                prev[k] = Cbits[k];
            }
            pos += B;
        }
        return outpos;
    }

    // CBC-CTS (ciphertext stealing)
    long long r = (total % B);                 // number of leftover bytes in the second-to-last ciphertext block (C_{n-1})
    long long n_minus_2_len = total - r - B;   // bytes up to C_{n-2}
    if (n_minus_2_len < 0) {
        return -1;
    }

    unsigned char *partial_block = Cipher_bytes + n_minus_2_len;     // C_{n-1}* (r bytes)
    unsigned char *last_complete_block = Cipher_bytes + n_minus_2_len + r; // C_n (8 bytes)

    // decrypt last complete block
    int last_complete_block_bits[64], Zbits[64];
    bytes_to_bits(last_complete_block, last_complete_block_bits);
    DES_decrypt(last_complete_block_bits, round_keys, Zbits);
    unsigned char Zbytes[8];
    bits_to_bytes(Zbits, Zbytes);

    // combine the partial block and the last (8 - r) bytes of Z
    unsigned char Cn_1_full[8];
    for (int j=0;j<r;j++) {
        Cn_1_full[j] = partial_block[j];
    }
    for (int j=0;j<8-r;j++) {
        Cn_1_full[r+j] = Zbytes[r+j];
    }

    // CBC-decrypt C1..C_{n-2}, then C_{n-1}
    int prev[64];
    for (int i=0;i<64;i++) {
        prev[i] = iv_bits[i];
    }

    long long pos = 0, outpos = 0;
    unsigned char block[8], outb[8];
    int Cbits[64], Pbits[64];

    // CBC-decrypt for all the full blocks up to C_{n-2}
    while (pos < n_minus_2_len) {
        for (int j=0;j<B;j++) block[j] = Cipher_bytes[pos+j];
        bytes_to_bits(block, Cbits);
        DES_decrypt(Cbits, round_keys, Pbits);
        xor_bits(Pbits, prev, 64, Pbits);
        bits_to_bytes(Pbits, outb);
        for (int j=0;j<B;j++) {
            plaintext_out[outpos++] = outb[j];
        }
        for (int k=0;k<64;k++) {
            prev[k] = Cbits[k];
        }
        pos += B;
    }

    // decrypt the combined block
    bytes_to_bits(Cn_1_full, Cbits);
    DES_decrypt(Cbits, round_keys, Pbits);
    xor_bits(Pbits, prev, 64, Pbits);
    bits_to_bytes(Pbits, outb);
    for (int j=0;j<B;j++){
        plaintext_out[outpos++] = outb[j];
    } 

    // recover last r bytes
    for (int j=0;j<r;j++) {
        plaintext_out[outpos++] = (unsigned char)(partial_block[j] ^ Zbytes[j]);
    }

    return outpos;
}

// Utility 1: Confidentiality
void Confidentiality() {
    printf("\n--- Confidentiality Only ---\n");

    char plaintext[4096], key_hex[64], iv_hex[64];
    while(getchar() != '\n');
    printf("Enter message to encrypt: ");
    if (!fgets(plaintext, sizeof(plaintext), stdin)) {
        printf("No message read.\n"); 
        return;
    }
    chomp(plaintext);
    long long msg_len = (long long)strlen(plaintext);

    // Read key and validate
    do {
        printf("Enter DES key (16 hex): "); 
        if(!fgets(key_hex, sizeof(key_hex), stdin))  {
            return;
        }
        chomp(key_hex);
        if (strlen(key_hex) != 16 || !isHexa(key_hex)) {
            fprintf(stderr,"Invalid key: must be exactly 16 hexadecimal characters.\n");
        }
    } while(!isHexa(key_hex));

    // Read IV and validate
    do {
        printf("Enter IV (16 hex): ");
        if(!fgets(iv_hex,sizeof(iv_hex),stdin)) {
            return;
        }
        chomp(iv_hex);
        if (strlen(iv_hex) != 16 || !isHexa(iv_hex)) {
            fprintf(stderr,"Invalid IV: must be exactly 16 hexadecimal characters.\n");
        }
    } while(!isHexa(iv_hex));

    // Convert key to 64-bit
    int key_bits[64], key56[56], C[28], D[28], round_keys[16][48];
    hexa_to_bin(key_hex, key_bits);
    parity_bit_drop(key_bits, key56); //64-bit -> 56-bit
    split_key56(key56, C, D);   //56-bit -> 28-bit + 28-bit
    generate_round_keys(C, D, round_keys);  //generate 16 round keys
    
    // Convert IV to 64-bit
    int iv_bits[64];
    hexa_to_bin(iv_hex, iv_bits);
    
   // CBC-CTS encryption
    const int B = DES_BLOCK_SIZE; // 8
    long long n_blocks = (msg_len + B - 1) / B; // complete blocks
    long long r = msg_len % B;                  // leftover bytes (0..7)

    if (n_blocks == 0) {
        printf("Empty message.\n");
        return;
    }

    unsigned char pblock[8], cblock[8];
    int Pbits[64], Xbits[64], Cbits[64], prev_cipher[64];

    // store ciphertext blocks to apply CTS output 
    unsigned char Cblocks[520][8];  
    for (int i = 0; i < 64; i++) {  // initialize the previous cipher = the IV value
        prev_cipher[i] = iv_bits[i];
    }

    for (long long b = 0; b < n_blocks; b++) {
        // loop through each block, if its last block nad r > 0, only copy r bytes
        for (int j = 0; j < B; j++) {	// fill the array with zeros
            pblock[j] = 0;
        }
        long long base = b * B;
        int to_copy = (b == n_blocks - 1 && r != 0) ? (int)r : B;
        for (int j = 0; j < to_copy; j++) {
            pblock[j] = (unsigned char)plaintext[base + j];
        }

        // XOR
        bytes_to_bits(pblock, Pbits);
        xor_bits(Pbits, prev_cipher, 64, Xbits);

        // 
        DES_encrypt(Xbits, round_keys, Cbits);

        // save and chain
        bits_to_bytes(Cbits, cblock);
        for (int j = 0; j < B; j++) {
            Cblocks[b][j] = cblock[j];
        }
        for (int j = 0; j < 64; j++) {
            prev_cipher[j] = Cbits[j];
        }
    }

    // print ciphertext 
    printf("\nCiphertext (hex, CBC-CTS):");

    char cipher_hex[4096 * 2 + 512];
    size_t hexlen = 0;

    if (r == 0 || n_blocks == 1) {
        // normal CBC output
        for (long long b = 0; b < n_blocks; b++) {
            for (int j = 0; j < B; j++) {
                hexlen += sprintf(cipher_hex + hexlen, "%02X", Cblocks[b][j]);
            }
        }
    } else {
        // when remainder exists
        long long n = n_blocks;

        // C1..C_{n-2}
        for (long long b = 0; b < n - 2; b++) {
            for (int j = 0; j < B; j++) {
                hexlen += sprintf(cipher_hex + hexlen, "%02X", Cblocks[b][j]);
            }
        }

        // C_{n-1}* = first r bytes of C_{n-1}
        for (int j = 0; j < (int)r; j++) {
            hexlen += sprintf(cipher_hex + hexlen, "%02X", Cblocks[n - 2][j]);
        }

        // C_n (full block)
        for (int j = 0; j < B; j++) {
            hexlen += sprintf(cipher_hex + hexlen, "%02X", Cblocks[n - 1][j]);
        }
    }
    cipher_hex[hexlen] = '\0';   // terminate string (end of string)
    printf("%s\n", cipher_hex);

    // self-test (decrypt and compare)
    unsigned char recovered[4096];
    long long rec_len = Decrypt_CBC_CTS(cipher_hex, key_hex, iv_hex, recovered, sizeof(recovered));
    if (rec_len < 0) {
        printf("[!] Decrypt_CBC_CTS failed.\n");
    } else {
        if (rec_len < (long long)sizeof(recovered)) recovered[rec_len] = '\0'; {
            printf("Decrypted plaintext: %s\n", recovered);
        }

        int same = 1;
        // compare up to the shorter length
        long long cmp_len = (rec_len < msg_len) ? rec_len : msg_len;
        for (long long i = 0; i < cmp_len; ++i) {
            if ((unsigned char)recovered[i] != (unsigned char)plaintext[i]) {
                same = 0; 
                break;
            }
        }
        
        if (same && rec_len > msg_len) {
            for (long long i = msg_len; i < rec_len; ++i) {
                if (recovered[i] != 0) { 
                    same = 0; 
                    break; 
                }
            }
        }
        
        recovered[msg_len] = '\0';

        if (same) {
            printf("[Success] Ciphertext round-trip matches the original.\n");
        }
        else {
            printf("[Failed] Round-trip mismatch.\n");
        }
    }
}

// Utility 2: Authentication
void Authentication() { 
    printf("\n--- Authenication only ---\n");
    printf("\nNOTICE: RSA key generation is required before proceeding.\n");
    
    long long p, q, e;
    printf("Enter prime p (10 digits): ");
    if(scanf("%lld", &p) != 1) {
        printf("Invalid input!");
        return;
    }
    while(!isPrime(p) || p < 0) {
        if(!isPrime(p)){
            printf("%lld is not a prime number. Enter a prime number: ", p);
        } else {
            printf("%lld is less than Zero. Enter a prime number > 0: ", p);
        }
        scanf("%lld", &p);
    }
    
    printf("Enter prime number q (10 digits): ");
    if(scanf("%lld", &q) != 1) {
        printf("Invalid input!");
        return;
    }
    while(!isPrime(q) || q == p || q < 0) {
        if (q == p) {
            printf("The two prime numbers must not equal each other! Enter a different q: ");
        } else if(!isPrime(q)) {
            printf("%lld is not a prime number. Enter a prime number: ", q);
        } else {
            printf("%lld is less than Zero. Enter a prime number > 0: ", q);
        }
        scanf("%lld", &q);
    }
    
    __int128 n = (__int128)p * (__int128)q; //calculate n
    printf("N (modulus): ");
    print_int128(n);
    printf("\n");
    __int128 fi = (__int128)(p - 1) * (__int128)(q - 1); //calculate ϕ(n)
    printf("ϕ(N) (Euler's Totient Function): ");
    print_int128(fi);
    printf("\n");
    printf("Enter the public key exponent (e): ");
    scanf("%lld", &e);
    while(((__int128)e < 1) || (__int128)e >= fi || (GCD((__int128)e, fi) != 1)) {
        printf("%lld is not coprime to (", e);
        print_int128(fi);
        printf(") or witchar_as_integern the range 1 < e < ");
        print_int128(fi);
        printf(", enter the correct value of e: ");
        if(scanf("%lld", &e) != 1) {
            printf("Invalid input!");
            return;
        }
    }
    
    // compute max secure block size in BYTES
    long long max_block_size = block_size(n);
    if (max_block_size <= 0) { 
        printf("n too small! There is no secure block size. Choose larger primes.\n"); 
        return; 
    }
    
    __int128 PrK = extendedEUCinv((__int128)e, fi);
    
    printf("\n");
    printf("p = %lld\nq = %lld\n", p, q);
    printf("(e * d) mod phi(n) = "); 
    print_int128(((__int128)e * PrK) % fi); 
    printf("    [should = 1]\n");
    
    //RSA key pair:
    printf("Public key: (e = %lld, N = ", e);
    print_int128(n);
    printf(")\n");
    printf("Private key: (d = ");
    print_int128(PrK);
    printf(", N = ");
    print_int128(n);
    printf(")\n");
    
    //Debug:
    //printf("Block size (bytes): %lld (since 256^%lld < n)\n", max_block_size, max_block_size);
    printf("\n");
    //Plaintext inserting
    printf("Enter your message to be encrypted: ");
    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF) {
        //read until gets the end of the previous line 
    }
    char PlainText[4096];
    if (!fgets(PlainText, sizeof PlainText, stdin)) {
        printf("No message read.\n"); 
        return;
    }
    long long length = (long long)strlen(PlainText);
    if (length > 0 && PlainText[length - 1] == '\n') {
        PlainText[--length] = '\0';
    }

    //segmentation --> blocks --> encrypt
    long long blocks = (length + max_block_size - 1) / max_block_size;   //calculate # of blocks [ceil(L/k)]
    __int128 Cipher[4096];                    //stores ciphertext
    long long sizeOfBlocks[4096];                //store # of bytes in each block

    long long position = 0; //current position in the plaintext 
    for (long long index = 0; index < blocks; index++) {
        long long byte_to_encrypt = max_block_size;
        
        //if last block is shorter than the max_block_size
        if (position + byte_to_encrypt > length) {
            byte_to_encrypt = length - position; // last short chunk
        }
        
        //convert the next segment of the plaintext into integers
        __int128 M = MSGtoASCII(PlainText, position, byte_to_encrypt); 
        
        //encrypt the integer
        __int128 encryptedBlock = RSA_ENC(M, e, n);
        
        //store the encrypted value and its size 
        Cipher[index] = encryptedBlock;
        sizeOfBlocks[index] = byte_to_encrypt;
        
        //move to the next segment
        position += byte_to_encrypt;
    }
    
    printf("\n");
    
    //ciphertext blocks
    printf("Ciphertext blocks (decimal): ");
    for (long long index = 0; index < blocks; index++) {
        print_int128(Cipher[index]);
        if (index + 1 < blocks) {
            printf(" ");
        }
    }
    printf("\n");
    
    printf("Ciphertext blocks (letters): ");
    for (long long index = 0; index < blocks; index++) {
        char s[256];
        num_to_letters(Cipher[index], s);
        printf("%s", s);
        if (index + 1 < blocks) {
            printf(" ");
        }
    }
    printf("\n\n");
    
    // decrypt --> unpack blocks --> combining (via letters round-trip)
    char Decrypted[4096];
    position = 0;
    for (long long index = 0; index < blocks; index++) {
        //get the letters of the ciphertext 
        char s[256];
        num_to_letters(Cipher[index], s);       
    
        //decode letters to number
        __int128 decimal_cipher = base26_to_i128(s);       
    
        //decrypt and unpack blocks
        __int128 decimal_M = RSA_DEC(decimal_cipher, PrK, n);
        ASCIItoMSG(Decrypted, position, sizeOfBlocks[index], decimal_M);
        position += sizeOfBlocks[index];
    }

    Decrypted[position] = '\0';
    printf("Decrypted: %s\n", Decrypted);
    
    printf("\n");
    
    //----------- Digital Signature ----------
    //  Digital Signature (SHA-256 + RSA) 
    unsigned char hash[SHA256_DIGEST_LENGTH];
    
    //hash the original plaintext
    SHA256((const unsigned char*)PlainText, (size_t)length, hash);
    
    //map hash into RSA field (integer value of the digest mod(n))
    __int128 H = digest_to_int128(hash, n);
    
    //sign with private key (d): s = H^d mod n
    __int128 Signed = square_and_multiply(H, PrK, n);
    
    //verify with public key (e): v = Signed^e mod n, it should = H
    __int128 V = square_and_multiply(Signed, e, n);
    
    printf("SHA-256 integer value of the digest (mod ("); 
    print_int128(n);
    printf(")): ");
    print_int128(H); 
    printf("\n\n");
    printf("SHA-256 digest of the message (hex): ");
    print_hex(hash, SHA256_DIGEST_LENGTH);
    printf("\n\n");
    printf("Signature (decimal): "); 
    print_int128(Signed); 
    printf("\n\n");
    char sigLetters[256];
    num_to_letters(Signed, sigLetters);
    printf("Signature (letters): %s\n", sigLetters);
    printf("\n");
    printf("Signature verification: ");
    if(V == H) {
        printf("VALID\n");
    } else {
        printf("INVALID\n");
    }
    
}

// Utility 3: Confidentiality + Authentication
void Confidentiality_and_Authentication() {
    printf("\n--- Confidentiality & Authentication ---\n");
    
    // clear any leftover newline from previous scanf
    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF) {
        //read until gets the end of the previous line 
    }
    
    char mode[32];
    if (!read_line("Mode (send/receive): ", mode, sizeof mode)) {
        return;
    }
    for (char *p = mode; *p; ++p) {
        *p = (char)tolower((unsigned char)*p);
    }

    if (strcmp(mode, "send") == 0) {
        // ---------- SENDER PART ----------
        char plaintext[4096];
        if (!read_line("Enter plaintext: ", plaintext, sizeof plaintext)) {
            return;
        }
        long long msg_len = (long long)strlen(plaintext);
    
        //DES key and IV (hex) with validation
        char key_hex[64], iv_hex[64];
        do { 
            if (!read_line("DES key (16 hex): ", key_hex, sizeof key_hex)) {
                return; 
            }
        } while (!isHexa(key_hex)); //validate the key is 16-digit hexadecimal
        
        do {
            if (!read_line("IV (16 hex): ", iv_hex, sizeof iv_hex)) {
             return; 
            }
        } while (!isHexa(iv_hex));  //validate the key is 16-digit hexadecimal

        // DES key process
        int key_bits[64], key56[56], Ck[28], Dk[28], round_keys[16][48];
        hexa_to_bin(key_hex, key_bits);
        parity_bit_drop(key_bits, key56);   // 64-bit -> 56-bit
        split_key56(key56, Ck, Dk);     // 56-bit -> 28-bit + 28-bit
        generate_round_keys(Ck, Dk, round_keys);    // generate 16 round keys

        // IV bits
        int iv_bits[64];
        hexa_to_bin(iv_hex, iv_bits);

        // CBC-CTS encryption
        const int B = DES_BLOCK_SIZE; // 8
        long long n_blocks = (msg_len + B - 1) / B;     // number of complete blocks
        long long r = msg_len % B;           //leftover bytes in last block

        unsigned char pblock[8], cblock[8];
        int Pbits[64], Xbits[64], Cbits[64], prev_cipher[64];
        unsigned char Cblocks[520][8];
        
        //initialize the previous cipher = IV
        for (int i = 0; i < 64; i++) {
            prev_cipher[i] = iv_bits[i];
        }
        
        // loop through each block, if its last block nad r > 0, only copy r bytes
        for (long long b = 0; b < n_blocks; b++) { 
            for (int j = 0; j < B; j++) { 
                pblock[j] = 0;
            }
            long long base = b * B;
            int to_copy = (b == n_blocks - 1 && r != 0) ? (int)r : B;
            for (int j = 0; j < to_copy; j++) {
                pblock[j] = (unsigned char)plaintext[base + j];
            }
            
            // XOR then encrypt
            bytes_to_bits(pblock, Pbits);
            xor_bits(Pbits, prev_cipher, 64, Xbits);
            DES_encrypt(Xbits, round_keys, Cbits);

            bits_to_bytes(Cbits, cblock);
            for (int j = 0; j < B; j++) {
                Cblocks[b][j] = cblock[j];
            }
            for (int j = 0; j < 64; j++) {
                prev_cipher[j] = Cbits[j];
            }
        }

        // Build contiguous hex (ciphertext)
        char cipher_hex[4096 * 2 + 512];
        size_t hexlen = 0;
        if (n_blocks == 1 || r == 0) {  //normal CBC output (exact multiple of 8 or single block)
            for (long long b = 0; b < n_blocks; b++) {
                for (int j = 0; j < B; j++) {
                    hexlen += (size_t)sprintf(cipher_hex + hexlen, "%02X", Cblocks[b][j]);
                }
            }
        } else {
            long long n = n_blocks;
            //C1..C_{n-2}
            for (long long b = 0; b < n - 2; b++) {
                for (int j = 0; j < B; j++) {
                    hexlen += (size_t)sprintf(cipher_hex + hexlen, "%02X", Cblocks[b][j]);
                }
            }
            //C_{n-1}*  (first r bytes of C_{n-1})
            for (int j = 0; j < (int)r; j++) {
                hexlen += (size_t)sprintf(cipher_hex + hexlen, "%02X", Cblocks[n - 2][j]);
            }
            //C_n (full block)
            for (int j = 0; j < B; j++) {
                hexlen += (size_t)sprintf(cipher_hex + hexlen, "%02X", Cblocks[n - 1][j]);
            }
        }
        cipher_hex[hexlen] = '\0';      //terminate string
        
        //---------- Digital Signature ----------
        // Sign SHA-256(plaintext) with RSA private key d, n
        //hash the original plaintext with SHA-256
        unsigned char hash[SHA256_DIGEST_LENGTH];

        // if the plaintext is only one block and < 8 bytes
        if (n_blocks == 1 && r != 0) {  
            unsigned char padded[DES_BLOCK_SIZE];   // define and fill the temp array with zeros
            for (int j = 0; j < DES_BLOCK_SIZE; ++j) {
                padded[j] = 0;
            }
            for (int j = 0; j < r; ++j) {   // copy the r plaintext into the temp array
                padded[j] = (unsigned char)plaintext[j];
            } 
            SHA256(padded, DES_BLOCK_SIZE, hash);   // hash the padded 8-byte
        } else {
            SHA256((const unsigned char*)plaintext, (size_t)msg_len, hash);
        }

        long long d_ll, n_ll;
        printf("RSA private exponent d (decimal): ");
        if (scanf("%lld", &d_ll) != 1) { 
            printf("Bad input.\n"); 
            return; 
        }
        printf("RSA modulus n (decimal): ");
        if (scanf("%lld", &n_ll) != 1) { 
            printf("Bad input.\n"); 
            return; 
        }
        
        // clear any leftover newline from previous scanf
        int ch; 
        while ((ch = getchar()) != '\n' && ch != EOF) {
            
        }

        __int128 n = (__int128)n_ll, d = (__int128)d_ll;
        long long p_ll = 0, q_ll = 0;
        if (!factor_n_two_primes(n, &p_ll, &q_ll)) {
            printf("[!] Invalid RSA modulus n: not a product of two primes.\n");
            return;
        }
        
        //compute φ(n) = (p-1)(q-1)
        __int128 phi_n = (__int128)(p_ll - 1) * (__int128)(q_ll - 1);
        
        //d must satisfy 1 < d < φ(n) and gcd(d, φ(n)) = 1
        if (d <= 1 || d >= phi_n || GCD(d, phi_n) != 1) {
            printf("[!] Invalid private exponent d for this n: need 1 < d < φ(n) and gcd(d, φ(n)) = 1.\n");
            return;
        }
        
        __int128 Hmod = 0; // digest reduced mod n
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            Hmod = (Hmod * 256 + hash[i]) % n;
        } 
        __int128 S = square_and_multiply(Hmod, d, n);
        
        // signature as letters
        char sigLetters[256];
        num_to_letters(S, sigLetters);

        // Output package (to receiver)
        printf("\n--- PACKAGE (give these to the receiver) ---\n");
        printf("Ciphertext (hex, CBC-CTS, no spaces):\n%s\n\n", cipher_hex);
        printf("Signature (decimal): "); print_int128(S); 
        printf("\n");
        printf("Signature (letters): %s\n", sigLetters);

    } else if (strcmp(mode, "receive") == 0) {
        // ---------- RECEIVER PART ----------
        char cipher_hex[4096 * 2 + 512];
        if (!read_line("Ciphertext hex (no spaces): ", cipher_hex, sizeof cipher_hex)) {
            return;
        }
        
        //DES key and IV with validation
        char key_hex[64], iv_hex[64];
        do { 
            if (!read_line("DES key (16 hex): ", key_hex, sizeof key_hex)) {
                return; 
            } 
         
        } while (!isHexa(key_hex));
        do { 
            if (!read_line("IV (16 hex): ", iv_hex, sizeof iv_hex)){
                return;
            }
        } while (!isHexa(iv_hex));

        long long S_ll;
        printf("Signature (decimal): ");
        if (scanf("%lld", &S_ll) != 1) { 
            printf("Invalid Input!\n"); 
            return; 
        }

        long long e_ll, n_ll;
        printf("RSA public exponent e (decimal): ");
        if (scanf("%lld", &e_ll) != 1) { 
            printf("Invalid Input!\n"); 
            return; 
        }
        printf("RSA modulus n (decimal): ");
        if (scanf("%lld", &n_ll) != 1) { 
            printf("Invalid Input!\n"); 
            return; 
        }
        
        // clear any leftover newline from previous scanf
        int ch; 
        while ((ch = getchar()) != '\n' && ch != EOF) {
            
        }

        __int128 e = (__int128)e_ll, n = (__int128)n_ll, S = (__int128)S_ll;
        // n must be product of two primes
        long long p_ll = 0, q_ll = 0;
        if (!factor_n_two_primes(n, &p_ll, &q_ll)) {
            printf("[!] Invalid RSA modulus n: not a product of two primes.\n");
            return;
        }
        // φ(n)
        __int128 phi_n = (__int128)(p_ll - 1) * (__int128)(q_ll - 1);
        
        // e must satisfy 1 < e < φ(n) and gcd(e, φ(n)) = 1
        if (e <= 1 || e >= phi_n || GCD(e, phi_n) != 1) {
            printf("[!] Invalid public exponent e for this n: need 1 < e < φ(n) and gcd(e, φ(n)) = 1.\n");
            return;
        }
        
        // Decrypt (CBC-CTS)
        unsigned char recovered[4096];
        long long rec_len = Decrypt_CBC_CTS(cipher_hex, key_hex, iv_hex, recovered, sizeof recovered);
        if (rec_len < 0) { 
            printf("[!] Decrypt failed.\n");
            return;
        }

        recovered[rec_len] = '\0';
        printf("\nDecrypted plaintext: %s\n", recovered);

        // Verify signature
        //recompute SHA-256 for the decrypted plaintext
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(recovered, (size_t)rec_len, hash);

        __int128 Hmod = 0;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            Hmod = (Hmod * 256 + hash[i]) % n;
        }
        __int128 V = square_and_multiply(S, e, n);

        printf("Signature verification: ");
        if(V == Hmod) {
            printf("VALID\n");
        } else {
            printf("INVALID\n");
        }

    } else {
        printf("Unknown mode. Type 'send' or 'receive'.\n");
    }
}

// Utility 4: RSA cryptanalysis
void RSA_cryptanalysis() {
    int e, n, C;
    bool found = false;
    printf("\nRSA Cryptanalysis\n\n");
    printf("Enter modulus n (two digits): ");
    if(scanf("%d", &n) != 1) {
        printf("Invalid input!\n");
        return;
    }

    printf("Enter public exponent e: ");
    if(scanf("%d", &e) != 1) {
        printf("Invalid input!\n");
        return;
    }
    
    int fi = phi(n);
    while((e < 1) || e >= fi || (GCD(e, fi) != 1)) {
        printf("%d is not coprime to (%d) or witchar_as_integern the range 1 < e < %d, enter the correct value of e: ", e, fi, fi);
        if(scanf("%d", &e) != 1) {
            printf("Invalid input!");
            return;
        }
    }

    printf("Enter ciphertext C: ");
    if(scanf("%d", &C) != 1) {
        printf("Invalid input!");
        return;
    }
    
    int attempts = 0;
    for(int possible_message = 0 ; possible_message < n ; possible_message++) {
        attempts++;
        if(square_and_multiply(possible_message, e, n) == C) {
            printf("Match: m = %d   [after %d attempts]\n", possible_message, attempts);
            found = true;
        }
    }
    
    if(!found) {
        printf("No match found.\n");
    }
    
}

// Utility 5: Image Encryption
void imageEncryption() {
    // clear any leftover newline from previous scanf
    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF) {
        
    }

    const char *py_interpreter = "python3";
    const char *script = PY_SCRIPT_PATH;   // fixed path

    char input_img[1024];
    char want_save[16];
    char action[16];   // "encrypt" or "decrypt"
    char mode[16];     // "ecb" or "cbc"
    char key_hex[64];
    char iv_hex[64];

    printf("\n--- Image Encryption / Decryption  ---\n");

   //choose encrypt / decrypt
    if (!read_line("Action (encrypt/decrypt): ", action, sizeof action)) { 
        perror("read action"); 
        return; 
        
    }
    //convert the user's choice (encrypt/decrypt) to lower case
    for (char *p = action; *p; ++p) {
        *p = (char)tolower((unsigned char)*p);
    }
    //validate the user's choice
    if (strcmp(action, "encrypt") != 0 && strcmp(action, "decrypt") != 0) {
        printf("Invalid action. Type 'encrypt' or 'decrypt'.\n"); return;
    }
    //ask for plain/encrypted image path
    const char *wchar_as_integerch = (strcmp(action, "decrypt") == 0) ? "Encrypted image path: " : "Plain image path: ";
    
    if (!read_line(wchar_as_integerch, input_img, sizeof input_img)) { 
        perror("read input"); 
        return; 
    }
    
    //normalize the path
    normalize_wsl_path(input_img);
    
    //ask if the user wants to save a tinted channels then convert the choice to lower case
    if (!read_line("Save tinted channels? [y/N]: ", want_save, sizeof want_save)) { 
        perror("read save"); 
        return; 
    }
    for (char *p = want_save; *p; ++p) {
        *p = (char)tolower((unsigned char)*p);
    }

    //ask for the encryption/decryption mode then convert the choice to lower case
    if (!read_line("Mode (ecb/cbc): ", mode, sizeof mode)) { 
        perror("read mode"); 
        return; 
    }
    for (char *p = mode; *p; ++p) {
        *p = (char)tolower((unsigned char)*p);
    }
    //validate the choice
    if (strcmp(mode, "ecb") != 0 && strcmp(mode, "cbc") != 0) {
        printf("Invalid mode. Type 'ecb' or 'cbc'.\n"); 
        return;
    }
    
    //DES key
    if (!read_line("DES key (16 hex chars): ", key_hex, sizeof key_hex)) { 
        perror("read key"); 
        return; 
    }
    //validate DES key
    if (!isHexa(key_hex)) {
        printf("Key must be exactly 16 hex chars (optionally 0x prefix).\n"); 
        return; 
    }
    
    //IV value when using CBC mode
    int need_iv = (strcmp(mode, "cbc") == 0);
    if (need_iv) {
        if (!read_line("IV (16 hex chars, required for CBC): ", iv_hex, sizeof iv_hex)) {
            perror("read iv"); 
            return; 
        }
        if (!isHexa(iv_hex)) { 
            printf("IV must be exactly 16 hex chars (optionally 0x prefix).\n"); 
            return; 
        }
    }

    // Build argv for running python file command: python3 /home/ahmad/Cryptography/image_encryption.py --input <img> [--save-channels]
    char *argv[20];
    int i = 0;
    argv[i++] = (char*)py_interpreter; //python3
    argv[i++] = (char*)script;
    argv[i++] = "--input";
    argv[i++] = input_img;
    if (want_save[0] == 'y') {
        argv[i++] = "--save-channels";
    }
    if (strcmp(action, "encrypt") == 0) {
        argv[i++] = "--encrypt"; 
    }
    else {
        argv[i++] = "--decrypt";
    }
    argv[i++] = mode;
    argv[i++] = "--key-hex";
    argv[i++] = key_hex;
    if (need_iv) {
        argv[i++] = "--iv-hex"; 
        argv[i++] = iv_hex; 
    }
    argv[i++] = NULL;   //end the array
    //so the command will be like tchar_as_integers:
    // argv[0] = "python3"       // the interpreter (the actual program to run)
    // argv[1] = "/home/ahmad/Cryptography/image_encryption.py"  // your Python script
    // argv[2] = "--input"       
    // argv[3] = "image.jpg"
    // argv[4] = "--encrypt"     // or "--decrypt"
    // argv[5] = "cbc"           // mode (ecb/cbc)
    // argv[6] = "--key-hex"     
    // argv[7] = "133457799BBCDFF1"
    // argv[8] = "--iv-hex"      // (only if CBC)
    // argv[9] = "0123456789ABCDEF"
    // argv[10] = NULL           

    //fork : child execute the python file, parent waits for the child
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork failed"); 
        return; 
    }
    if (pid == 0) { //child
        execvp(argv[0], argv);
        perror("execvp python3");
        argv[0] = (char*)"python";
        execvp(argv[0], argv);
        perror("execvp python");
        _exit(127);
    } else { //parent
        int status = 0;
        if (waitpid(pid, &status, 0) == -1) { 
            perror("waitpid"); 
            return; 
        }
        if (WIFEXITED(status)) { //child exited normally
            int code = WEXITSTATUS(status);
            if (code == 0) {
                printf("\n[Success] Python finished successfully.\n");
            }
            else {
                printf("\n[Failed] Python exited with code %d.\n", code);
            }
        } else if (WIFSIGNALED(status)) { //child was killed
            printf("\n[Failed] Python terminated by signal %d.\n", WTERMSIG(status));
        } else {
            printf("\n[Failed] Python ended abnormally.\n");
        }
    }
}

// main function
int main()
{
    int choice;
    while(1) {
        printMenu();
        printf("Select option: ");
        if(scanf("%d", &choice) != 1) {
            printf("Invalid input!.\n");
            break;
        }
        
        switch(choice) {
        case 0:
            printf("Exiting...\n");
            return 0;
            
        case 1: // Utility 1
            Confidentiality();
            break;
            
        case 2: // Utility 2
            Authentication();
            break;
            
        case 3: // Utility 3 (1 + 2)
            Confidentiality_and_Authentication();
            break;
            
        case 4: // Utility 4
            RSA_cryptanalysis();
            break;
            
        case 5: // Utility 5
            imageEncryption();
            break;
        
        default:
            printf("Invalid choice. Try again.\n");
        }
    }
    return 0;
}
