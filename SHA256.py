#Used https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf for reference

import math
import binascii

msg = "abc"

K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

def rotR(x,n):
    stringlol = format(str(bin(x))[2:], '0>32')
    stringlol = stringlol[-n:] + stringlol[:-n]
    return int(stringlol, 2)

def shr(x,n): #Shift x to the right by n places
    return x >> n

def capS_0(x):
    return rotR(x, 2) ^ rotR(x, 13) ^ rotR(x, 22)

def capS_1(x):
    return rotR(x, 6) ^ rotR(x, 11) ^ rotR(x, 25)

def lowerS_0(x):
    return rotR(x, 7) ^ rotR(x, 18) ^ shr(x, 3)

def lowerS_1(x):
    return rotR(x, 17) ^ rotR(x, 19) ^ shr(x, 10)

def Ch(x,y,z):
    return (x&y)^(~x&z)

def Maj(x,y,z):
    return (x&y)^(x&z)^(y&z)

def padMsg(message):
    length = len(message)*8 #8 bits/ASCII character
    k = (447 - length) % 512 #k is residue of solution to: length + 1 + k (congruent to) 448 mod 512
    binMsg = int(binascii.hexlify(message), 16) #Convert message to binary number
    binMsg = (binMsg << 1) + 1 #Append 1 to binary representation of message
    return format((binMsg << (k+64)) ^ length, '0512b') #Shift left by k, add length to the end

def hash(msg):
    global K
    twoPow32 = 1 << 32 #SHA-256 uses 32 bit words
    paddedMsg = padMsg(msg)
    M = [int(paddedMsg[i:i+32], 2) for i in range(0, len(paddedMsg), 32)]
    W = []
    H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

    #Step 1.) Prepare Message Schedule
    for t in range(16):
        W.append(M[t])
    for t in range(16, 64):
        W.append((lowerS_1(W[t-2]) + W[t-7] + lowerS_0(W[t-15]) + W[t-16]) % twoPow32)

    #Step 2.) Initialize working variables a-h with previous hash value
    a = H[0]
    b = H[1]
    c = H[2]
    d = H[3]
    e = H[4]
    f = H[5]
    g = H[6]
    h = H[7]

    #Step 3.) Compute the hash
    for t in range(64):
        T1 = (h + capS_1(e) + Ch(e,f,g) + K[t] + W[t]) % twoPow32
        T2 = (capS_0(a) + Maj(a,b,c)) % twoPow32
        h = g
        g = f
        f = e
        e = (d + T1) % twoPow32
        d = c
        c = b
        b = a
        a = (T1 + T2) % twoPow32

    #Step 4.) Compute the ith intermediate hash value
    H[0] = (H[0] + a) % twoPow32
    H[1] = (H[1] + b) % twoPow32
    H[2] = (H[2] + c) % twoPow32
    H[3] = (H[3] + d) % twoPow32
    H[4] = (H[4] + e) % twoPow32
    H[5] = (H[5] + f) % twoPow32
    H[6] = (H[6] + g) % twoPow32
    H[7] = (H[7] + h) % twoPow32

    #Step 5.) Convert H0:H7 to hex, concatenate
    xd = ""
    for x in H:
        xd+=format(x, '0x')
    return xd

result = hash(msg)
print "Got:            ", result
print "Supposed to be: ", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
print "Are they equal?", "Yes" if result == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" else "NOOOOO"
