# Lock & Key Tool – Secure Communication System
This project implements a secure communication system featuring confidentiality, authentication, and image encryption using DES and RSA.

**Files**
* Lock_and_Key.c – Main program implementing the tool.
* DES.c – DES encryption algorithm implementation.
* DES.h – Header file for DES functions and constants.
* Penguin.png - image for testing.

**Requirements**
* GCC compiler
* OpenSSL library (-lcrypto)

**Compilation Instructions**
1. Compile DES implementation:
    `gcc -c DES.c -o DES.o`
2. Compile main program with DES object file:
   `gcc Lock_and_Key.c DES.o -o LAK -lcrypto -lm`
3. Run the tool:
   `./LAK`
   
**Features**
* Text encryption using DES (CBC mode with Ciphertext Stealing).
* RSA key generation, digital signature creation, and verification.
* Image encryption using ECB/CBC modes with Ciphertext Stealing.
* Cryptanalysis of RSA short message encryption.

**Usage**
1. Run `./LAK` to start the menu.
2. Choose the desired operational mode:
- Confidentiality Only (DES encryption)
- Authentication Only (RSA digital signatures)
- Confidentiality & Authentication
- RSA Cryptanalysis
- Image Encryption
3. Follow the on-screen prompts to enter messages, keys, or files as needed.
