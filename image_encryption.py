import argparse
import os
from typing import List, Tuple

import numpy as np
from PIL import Image

# bytes -> bits
def bytes_to_bits64(block8: bytes) -> List[int]:
    # 8 bytes -> 64-bit
    assert len(block8) == 8     #ensure the input is exactly 8 bytes
    out = []    
    for byte in block8:     #loop over each byte
        for i in range(8):
            out.append((byte >> (7 - i)) & 1)   #shift the byte right by (7 - i) then take the LSB ---- gives the bits from MSB -> LSB
    return out

# bits -> bytes
def bits64_to_bytes(bits: List[int]) -> bytes:
    #64-bit -> 8 bytes
    assert len(bits) == 64      #ensure the list is exactly 64-bit
    out = bytearray(8)      #modifiable array of zeros (8 bytes)
    for i in range(8):
        val = 0
        for j in range(8):
            val = (val << 1) | (bits[i*8 + j] & 1)  #shift the curent val by 1 bit, ensures the bit is 0 or 1, combine the new bit into val
        out[i] = val    #after 8 iterations -> val contains a full byte, store the compeleted bytes
    return bytes(out)   #convert the modifiable array to a non-modifiable and return it

#bitwise XOR
def xor_bits(a: List[int], b: List[int]) -> List[int]:
    return [ (x ^ y) & 1 for x, y in zip(a, b) ]

# DES tables 
PC1 = [  # parity drop (64 -> 56)
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
]

PC2 = [  # compression permutation (56 -> 48)
    14,17,11,24,1,5,
    3,28,15,6,21,10,
    23,19,12,4,26,8,
    16,7,27,20,13,2,
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32
]

SHIFT_TABLE = [ 1,1,2,2,2,2,2,2, 1,2,2,2,2,2,2,1 ]

IP = [
    58,50,42,34,26,18,10,2,
    60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,
    64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,
    59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,
    63,55,47,39,31,23,15,7
]

E_TABLE = [
    32,1,2,3,4,5,4,5,6,7,8,9,
    8,9,10,11,12,13,12,13,14,15,16,17,
    16,17,18,19,20,21,20,21,22,23,24,25,
    24,25,26,27,28,29,28,29,30,31,32,1
]

P_TABLE = [
    16,7,20,21,29,12,28,17,
    1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9,
    19,13,30,6,22,11,4,25
]

FP = [
    40,8,48,16,56,24,64,32,
    39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,
    37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,
    35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,
    33,1,41,9,49,17,57,25
]

SBOX = [
    [ # S1
     [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
     [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
     [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
     [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]
    ],
    [ # S2
     [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
     [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
     [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
     [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]
    ],
    [ # S3
     [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
     [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
     [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
     [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]
    ],
    [ # S4
     [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
     [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
     [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
     [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]
    ],
    [ # S5
     [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
     [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
     [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
     [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]
    ],
    [ # S6
     [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
     [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
     [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
     [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]
    ],
    [ # S7
     [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
     [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
     [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
     [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]
    ],
    [ # S8
     [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
     [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
     [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
     [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]
    ]
]

# DES calculations
def permute(in_bits: List[int], table: List[int]) -> List[int]:
    # first bit is 1 and python lists starts with 0 so i - 1
    # bits [0, 1, 0, 1] , table [2, 4, 1, 3] -> result [1, 1, 0, 0]
    return [in_bits[i-1] for i in table]

# reduce a 64-bit into 56-bit
def parity_bit_drop(key64: List[int]) -> List[int]:
    return permute(key64, PC1)  # 56 bits

# split the key into two halves
def split_key56(key56: List[int]) -> Tuple[List[int], List[int]]:
    return key56[:28], key56[28:]

# circular shift left by s
def left_circular_shift(arr: List[int], shifts: int) -> List[int]:
    s = shifts % 28
    # arr[s:] = elements from s to the end of the list
    # arr[:s] = first s elements
    return arr[s:] + arr[:s]

# 56-bit -> 48-bit
def compression_permutation(cd56: List[int]) -> List[int]:
    return permute(cd56, PC2)  # 48 bits

# generate all 16 DES round keys
def generate_round_keys(c28: List[int], d28: List[int]) -> List[List[int]]:
    round_keys = []
    C, D = c28[:], d28[:]    # c28 and d28: left and right halves of the key (28-bit each)
    # [:] creates a new list to be shifted later so the original halves are not modified
    for s in SHIFT_TABLE:
        C = left_circular_shift(C, s)  
        D = left_circular_shift(D, s)   
        CD = C + D
        rk = compression_permutation(CD)
        round_keys.append(rk)   # store the round key
    return round_keys  # 16 key x 48-bit

# initial permutation 
def initial_permutation(in64: List[int]) -> List[int]:
    return permute(in64, IP)

# expand the right half 32-bit -> 48-bit
def expand_right(r32: List[int]) -> List[int]:
    return permute(r32, E_TABLE)  # 48

# S-Box subsitutions, 48-bit -> 32-bit
def sbox_layer(in48: List[int]) -> List[int]:
    out32 = []
    for i in range(8):
        b = in48[i*6:(i+1)*6]
        row = (b[0] << 1) | b[5]
        col = (b[1] << 3) | (b[2] << 2) | (b[3] << 1) | b[4]
        val = SBOX[i][row][col]  # 0..15
        out32.extend([(val >> 3) & 1, (val >> 2) & 1, (val >> 1) & 1, val & 1])
    return out32

# P-Box
def p_permutation(in32: List[int]) -> List[int]:
    return permute(in32, P_TABLE)

# final permutation
def final_permutation(in64: List[int]) -> List[int]:
    return permute(in64, FP)

# reverse the order of the DES round keys
def reverse_round_keys(rks: List[List[int]]) -> List[List[int]]:
    return list(reversed(rks)) # iterator over the keys in reverse order and store them into a list

def des_encrypt_block_bits(plain64: List[int], round_keys: List[List[int]]) -> List[int]:
    # encrypt one 64-bit block with given round keys (16×48)
    ip = initial_permutation(plain64)
    L = ip[:32] # first 32-bit
    R = ip[32:] # last 32-bit
    for rk in round_keys:
        ER = expand_right(R)           # 32-bit -> 48-bit
        xk = xor_bits(ER, rk)          # XOR round key
        s32 = sbox_layer(xk)           # 48-bit -> 32-bit
        p32 = p_permutation(s32)       # 32-bit -> 32-bit, output of the DES round function f(R, K)
        newR = xor_bits(L, p32)        # bitwise XOR (L, p32), store the output in the newR
        L, R = R, newR                 # swap, L becomes the old R and R becomes the newR
    preoutput = R + L                   # swap after the 16 rounds 
    return final_permutation(preoutput)

# DES decryption
def des_decrypt_block_bits(cipher64: List[int], round_keys: List[List[int]]) -> List[int]:
    # Decrypt one 64-bit block
    # same as encryption process but reverse the round keys first
    return des_encrypt_block_bits(cipher64, reverse_round_keys(round_keys))

# Key/IV inputs
# convert the 16 hexa DES key into bits
def bits64_from_hex(hexstr: str) -> List[int]:
    s = hexstr.strip().replace(" ", "").lower()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) != 16:
        raise SystemExit("DES --key-hex must be exactly 16 hex characters (64 bits).")
    try:
        val = int(s, 16) # hexa to integer
    except ValueError:
        raise SystemExit("DES --key-hex is not valid hex.")
    return [(val >> (63 - i)) & 1 for i in range(64)]   # integer to list of bits

# convert 16 hexa into 8 bytes
def bytes8_from_hex(hexstr: str) -> bytes:
    s = hexstr.strip().replace(" ", "").lower()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) != 16:
        raise SystemExit("DES --iv-hex must be exactly 16 hex characters (64 bits).")
    try:
        val = int(s, 16)    # hexa to integer
    except ValueError:
        raise SystemExit("DES --iv-hex is not valid hex.")
    return val.to_bytes(8, "big") # integer to bytes

# Block-mode (ECB/CBC)
# ECB mode encryption
def ecb_encrypt_bytes(data: bytes, enc_block_fn) -> bytes:
    # ECB with ciphertext stealing (CTS), no padding needed.
    bs = 8  # DES block size
    n_full = len(data) // bs    # number of complete 8-byte blocks
    rem = len(data) % bs    # number of bytes left in the last block

    # exact multiple of block size -> normal ECB
    if rem == 0:
        out = bytearray()   # modifiable array
        for i in range(n_full):
            blk = data[i*bs:(i+1)*bs]
            out.extend(enc_block_fn(blk))
        return bytes(out)

    # not multiple of block size (8) -> ECB-CTS
    if n_full == 0:
        raise ValueError("ECB-CTS requires at least one full block before the final partial block")

    out = bytearray()   # modifiable array
    # Encrypt all blocks up to the penultimate normally
    for i in range(n_full - 1):     # loop over all blocks except the last one
        blk = data[i*bs:(i+1)*bs]
        out.extend(enc_block_fn(blk))

    # CTS on the last two blocks
    Pn1 = data[(n_full-1)*bs:n_full*bs]   # last complete block
    Pn  = data[n_full*bs:]                # partial block

    X = enc_block_fn(Pn1)                 # encrypt last complete block
    Cn = X[:rem]                          # first rem bytes of X
    Y = Pn + X[rem:]                      # combine partial block and Cn
    Cn1 = enc_block_fn(Y)                 # C_{N-1} = E(Y)

    # Output: ... C_{N-1} (full), then C_N (short)
    out.extend(Cn1)
    out.extend(Cn)
    return bytes(out)

def cbc_cts_cs1_encrypt_bytes(data: bytes, enc_block_fn, iv: bytes) -> bytes:
    # CBC with ciphertext stealing. 
    bs = 8  # DES block size
    if len(iv) != bs:
        raise ValueError("IV must be 8 bytes for DES.")
    if len(data) < bs:
        raise ValueError("CBC-CTS requires at least one full block.")

    out = bytearray()   # modifiable array
    prev = iv   # stores the value of iv then the previous ciphertext block 
    n_full = len(data) // bs     # number of complete 8-byte blocks
    rem = len(data) % bs    # number of bytes left in the last block

    # Up to block n - 2
    for i in range(max(0, n_full - 1)):
        P = data[i*bs:(i+1)*bs]     # extract a block
        x = bytes(a ^ b for a, b in zip(P, prev))   # XOR with previous ciphertext (iv for the first time)
        C = enc_block_fn(x)     # encrypt the XORed block
        out.extend(C)
        prev = C    # update prev to hold the current ciphertext

    if rem == 0:    # exact multiple of 8
        # last block XORed with the previos ciphertext, encrypted, appended in the output
        P_last = data[(n_full-1)*bs:n_full*bs]
        x = bytes(a ^ b for a, b in zip(P_last, prev))
        C_last = enc_block_fn(x)
        out.extend(C_last)
        return bytes(out)

    # remainder != 0
    P_last_full = data[(n_full-1)*bs:n_full*bs]     # last complete 8-byte block, encrypt as above
    x = bytes(a ^ b for a, b in zip(P_last_full, prev))
    C_last_full = enc_block_fn(x)

    P_tail = data[n_full*bs:]   # last block
    Pn_padded = P_tail + bytes(bs - rem)    # pad the last block to 8-byte
    x2 = bytes(a ^ b for a, b in zip(Pn_padded, C_last_full))   # XOR with previous ciphertext
    C_star = enc_block_fn(x2)   # encrypt (final ciphertext block)

    out.extend(C_last_full[:rem])  # take the first rem bytes 
    out.extend(C_star)  # last full ciphertext block
    return bytes(out)


#-------------- Decrypt --------------
# ECB decyption
def ecb_decrypt_bytes(data: bytes, dec_block_fn) -> bytes:
    # ECB decryption with ciphertext stealing (CTS)
    bs = 8      # block size (bytes)
    n_full = len(data) // bs    # number of complete 8-bytes block
    rem = len(data) % bs    # number of bytes left in the last block

    # exact multiple of block size -> normal ECB
    if rem == 0:    # exact multiple of 8
        out = bytearray()   # modifiable array
        for i in range(n_full):
            Ci = data[i*bs:(i+1)*bs]    # current ciphertext block
            out.extend(dec_block_fn(Ci))    # DES decrypt 
        return bytes(out)

    # ECB-CTS (last two blocks)
    if n_full == 0:
        raise ValueError("This data cannot be decrypted with ECB-CTS, because its length is wrong.")

    out = bytearray()   # modifiable array
    # Decrypt all except the last two blocks normally
    for i in range(n_full - 1):
        Ci = data[i*bs:(i+1)*bs]
        out.extend(dec_block_fn(Ci))

    # CTS on the last two blocks
    Cn1 = data[(n_full-1)*bs:n_full*bs]   # last complete block
    Cn  = data[n_full*bs:]                # partial block (rem bytes)

    Y = dec_block_fn(Cn1)                 # decrypt last complete block
    Pn = Y[:rem]                          # recover last plaintext block
    tailX = Y[rem:]                       # this was tail(X)

    X = Cn + tailX                        # combine the rem bytes and the leftover bytes 
    Pn1 = dec_block_fn(X)                 # recover the full second-to-last plaintext block

    # Output: ... P_{N-1} (full), then P_N (short)
    out.extend(Pn1)
    out.extend(Pn)
    return bytes(out)
    
# CBC decryption with ciphertext stealing
def cbc_cts_cs1_decrypt_bytes(data: bytes, dec_block_fn, iv: bytes) -> bytes:
    bs = 8      # block size
    if len(iv) != bs:
        raise ValueError("IV must be 8 bytes for DES.")
    if len(data) < bs:
        raise ValueError("CBC-CTS requires at least one full block.")

    n_full = len(data) // bs    # number of complete 8-bytes block
    rem = len(data) % bs    # number of bytes left in the last block

    # Standard CBC when exact multiple of block size
    if rem == 0:    # exact multiple of 8
        out = bytearray()   # modifiable array
        prev = iv
        for i in range(n_full):
            Ci = data[i*bs:(i+1)*bs]    # current ciphertext block
            Di = dec_block_fn(Ci)   # DES decrypt  
            Pi = bytes(a ^ b for a, b in zip(Di, prev)) # XOR with the previous ciphertext or IV if it is the first time
            out.extend(Pi)
            prev = Ci   # update previous block
        return bytes(out)

    # if rem != 0
    d = rem  # length of final partial block
    out = bytearray()   # modifiable array

    # Ciphertext layout: C1..C_{n-2} (full blocks), then C' (d bytes), then C* (1 full block)
    prefix_len = (n_full - 1) * bs
    C_prime  = data[prefix_len:prefix_len + d]        # C' (partial block)
    C_star   = data[-bs:]                             # C* (last full block)

    # Decrypt all prefix blocks normally (full blocks before the last two)
    prev = iv
    for i in range(0, prefix_len, bs):
        Ci = data[i:i+bs]
        Di = dec_block_fn(Ci)
        Pi = bytes(a ^ b for a, b in zip(Di, prev))
        out.extend(Pi)
        prev = Ci  

    # Last two blocks
    X  = dec_block_fn(C_star)        # decrypt last full block
    X1 = X[:d]                       # first d bytes of the final plaintext
    X2 = X[d:]                       # remaining bytes
    C_n1 = C_prime + X2              # partial block + remaining bytes -> original complete 8-byte -> decrypt normally

    # decrypt the second-to-last plaintext block
    D_n1 = dec_block_fn(C_n1)
    P_n1 = bytes(a ^ b for a, b in zip(D_n1, prev))
    out.extend(P_n1)

    # decrypt last partial blok
    P_n = bytes(a ^ b for a, b in zip(X1, C_prime))
    out.extend(P_n)

    return bytes(out)

# DES block adapters (bytes <-> bits)
class DESContext:

    # DES key as 64-bit list
    def __init__(self, key64_bits: List[int]):
        key56 = parity_bit_drop(key64_bits)     # 64-bit -> 56-bit 
        C, D = split_key56(key56)   # 56-bit -> 28-bit and 28-bit
        self.round_keys = generate_round_keys(C, D)

    def encrypt_block(self, block8: bytes) -> bytes:
        bits = bytes_to_bits64(block8)  # 8-byte -> 64-bit
        out_bits = des_encrypt_block_bits(bits, self.round_keys)    # DES encryption 
        return bits64_to_bytes(out_bits)    # convert the result into 64-bit

    def decrypt_block(self, block8: bytes) -> bytes:
        bits = bytes_to_bits64(block8)  # 8-byte -> 64-bit
        out_bits = des_decrypt_block_bits(bits, self.round_keys)    # DES decryption 
        return bits64_to_bytes(out_bits)    # convert the result into 64-bit

# Image I/O 
def read_color_image(path: str) -> np.ndarray:
    img = Image.open(path).convert("RGB")   # open the image using pillow and ensure it is in RGB format (Red, Green, Blue) = 3 channels
    return np.array(img, dtype=np.uint8)    # convert the pillow image into numpy array, each pixel channel value is 0–255 (standard 8-bit color)

# save a numpy array as an RGB image
def save_image_rgb(path: str, arr: np.ndarray) -> None:
    Image.fromarray(arr.astype(np.uint8), mode="RGB").save(path)

# saves each color channel of an RGB image separately, tinted in its own color
def save_channels_tinted(base_out: str, rgb: np.ndarray) -> None:
    r, g, b = rgb[:, :, 0], rgb[:, :, 1], rgb[:, :, 2]
    zeros = np.zeros_like(r, dtype=np.uint8)    # used to mute other channels when isolating one
    Image.fromarray(np.dstack((r, zeros, zeros)), "RGB").save(f"{base_out}_R.png")
    Image.fromarray(np.dstack((zeros, g, zeros)), "RGB").save(f"{base_out}_G.png")
    Image.fromarray(np.dstack((zeros, zeros, b)), "RGB").save(f"{base_out}_B.png")

# ensures that an RGB image’s dimensions are padded up to the nearest multiple of 8 (height and width)
def pad_to_multiple_of_8(rgb: np.ndarray) -> Tuple[np.ndarray, int, int]:
    h, w, c = rgb.shape # height, width, channels
    assert c == 3
    # rounds up to the nearest multiple of 8
    new_h = (h + 7) // 8 * 8
    new_w = (w + 7) // 8 * 8
    if new_h == h and new_w == w:   # no padding needed if both dimensions are multiple of 8
        return rgb, 0, 0    # return original image and padding size (0, 0)
    # create a new black image with the new dimensions and copy the original image into the top-left corner
    out = np.zeros((new_h, new_w, 3), dtype=np.uint8)  
    out[:h, :w, :] = rgb
    return out, new_h - h, new_w - w    # return padded image with extra rows and colums added

def encrypt_channel_8x8(channel: np.ndarray, mode: str, des_ctx: DESContext, iv8: bytes) -> np.ndarray:
    H, W = channel.shape
    assert H % 8 == 0 and W % 8 == 0    # confirm dimensions are multiples of 8

    def enc_block(b: bytes) -> bytes: return des_ctx.encrypt_block(b)   # encrypt an 8-byte block with DES

    data = channel.copy().reshape(-1).tobytes()  # make a copy of the channel -> 1D array -> bytes objects -> pixel values
    # encrypt the whole channel block by block
    if mode == "ecb":
        enc = ecb_encrypt_bytes(data, enc_block)
    elif mode == "cbc":
        enc = cbc_cts_cs1_encrypt_bytes(data, enc_block, iv8)
    else:
        raise SystemExit("mode must be 'ecb' or 'cbc'")
    # encrypted byte string -> unit8 array -> (H, W) channel -> output same dimensions but pixel values are encrypted
    return np.frombuffer(enc, dtype=np.uint8).reshape((H, W))   


def decrypt_channel_8x8(channel: np.ndarray, mode: str, des_ctx: DESContext, iv8: bytes) -> np.ndarray:
    H, W = channel.shape
    assert H % 8 == 0 and W % 8 == 0     # confirm dimensions are multiples of 8

    def dec_block(b: bytes) -> bytes: return des_ctx.decrypt_block(b)   # decrypt an 8-byte block with DES

    data = channel.copy().reshape(-1).tobytes()   # make a copy of the channel -> 1D array -> bytes objects -> pixel values
    # decrypt the whole channel block by block
    if mode == "ecb":
        dec = ecb_decrypt_bytes(data, dec_block)
    elif mode == "cbc":
        dec = cbc_cts_cs1_decrypt_bytes(data, dec_block, iv8)
    else:
        raise SystemExit("mode must be 'ecb' or 'cbc'")
    # decrypted byte string -> unit8 array -> (H, W) channel -> recover the original channel
    return np.frombuffer(dec, dtype=np.uint8).reshape((H, W))


def process_image(path: str, save_channels_flag: bool, encrypt: str, decrypt: str, key_hex: str, iv_hex: str):
    base = os.path.splitext(os.path.basename(path))[0]

    # Step 1: read image as RGB
    rgb = read_color_image(path)
    h, w, _ = rgb.shape

    if save_channels_flag:
    #    print("Saving tinted channels R/G/B…")
        save_channels_tinted(base, rgb)

    # Step 2: pad to multiples of 8 
    padded, pad_h, pad_w = pad_to_multiple_of_8(rgb)

    # Step 3: reuse padded image

    # If neither encrypt nor decrypt is set, we're done
    if encrypt is None and decrypt is None:
        return

    # Build DES context (key: hexa to bits, round keys, etc)
    key64_bits = bits64_from_hex(key_hex)
    des_ctx = DESContext(key64_bits)

    # If CBC, IV is needed
    iv8 = b"\x00"*8
    mode = (encrypt or decrypt).lower()
    if mode == "cbc":
        iv8 = bytes8_from_hex(iv_hex)

    # separate channels
    R, G, B = padded[:, :, 0], padded[:, :, 1], padded[:, :, 2]

    if encrypt is not None:
        print(f"[Encrypt] DES-{mode.upper()}")
        # encrypt each channel independently with DES in chosen mode
        R_out = encrypt_channel_8x8(R, mode, des_ctx, iv8)
        G_out = encrypt_channel_8x8(G, mode, des_ctx, iv8)
        B_out = encrypt_channel_8x8(B, mode, des_ctx, iv8)
        # recombine them to have the final encrypted image
        enc_rgb = np.stack([R_out, G_out, B_out], axis=2)
        out_name = f"{base}_des_{mode}.png"
        save_image_rgb(out_name, enc_rgb)
        print(f" Saved encrypted image: {out_name}")

    if decrypt is not None:
        print(f"[Decrypt] DES-{mode.upper()}")
        # decrypt each channel independently with DES in chosen mode
        R_out = decrypt_channel_8x8(R, mode, des_ctx, iv8)
        G_out = decrypt_channel_8x8(G, mode, des_ctx, iv8)
        B_out = decrypt_channel_8x8(B, mode, des_ctx, iv8)
        # recombine them to have the final decrypted image
        dec_rgb = np.stack([R_out, G_out, B_out], axis=2)
        out_name = f"{base}_des_{mode}_dec.png"
        save_image_rgb(out_name, dec_rgb)
        print(f" Saved decrypted image: {out_name}")

# Command line interface
def main():
    # command argumetns
    ap = argparse.ArgumentParser(description="Image modes lab (DES from scratch).")
    ap.add_argument("--input", required=True, help="Path to input image (bmp/jpg/png/...)")
    ap.add_argument("--save-channels", action="store_true", help="Save tinted R/G/B channel images")
    ap.add_argument("--encrypt", choices=["ecb", "cbc"], help="Encrypt per 8×8 tile with DES")
    ap.add_argument("--decrypt", choices=["ecb", "cbc"], help="Decrypt per 8×8 tile with DES")
    ap.add_argument("--key-hex", required=False, help="DES key: 16 hex chars (64 bits incl. parity)")
    ap.add_argument("--iv-hex",  required=False, help="DES IV : 16 hex chars (64 bits). Required for CBC.")
    args = ap.parse_args()

    # validate the arguments 
    if (args.encrypt is not None) == (args.decrypt is not None):
        if args.encrypt is None and args.decrypt is None:
            pass 
        else:
            raise SystemExit("Choose exactly one of --encrypt or --decrypt.")

    # enforce key when choosing encrypt or decrypt
    if (args.encrypt is not None or args.decrypt is not None) and not args.key_hex:
        raise SystemExit("Provide --key-hex (16 hex chars) for encrypt/decrypt.")
    # enforce IV when choosing CBC
    mode = (args.encrypt or args.decrypt)
    if mode == "cbc" and not args.iv_hex:
        raise SystemExit("CBC requires --iv-hex (16 hex chars).")

    # pass the arguments to process image
    process_image(
        path=args.input,
        save_channels_flag=args.save_channels,
        encrypt=args.encrypt,
        decrypt=args.decrypt,
        key_hex=args.key_hex,
        iv_hex=args.iv_hex
    )


if __name__ == "__main__":
    main()

