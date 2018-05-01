#Alex Hutman
#SHA256
#Used https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf for reference

from sys import version_info
import math
import binascii
import hashlib
import time

#-------------------------------------------- BEGIN Input message from user --------------------------------------------#
py3 = version_info[0] > 2
if py3:
    msg = input('Enter a message. The SHA256 digest will be returned: ')
else:
    msg = raw_input('Enter a message. The SHA256 digest will be returned: ')
print("Computing SHA256 hash of " + "\"" + msg + "\"...")
#-------------------------------------------- END Input message from user --------------------------------------------#


#-------------------------------------------- BEGIN SHA256 Constants --------------------------------------------#
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
#-------------------------------------------- END SHA256 Constants --------------------------------------------#


#-------------------------------------------- BEGIN SHA256 Functions --------------------------------------------#
def rotR(x,n): #Perform a circular right shift on x by n bits. Assumes bit length of 32.
    rotatedStr = format(str(bin(x))[2:], '0>32')
    rotatedStr = rotatedStr[-n:] + rotatedStr[:-n]
    return int(rotatedStr, 2)

def shr(x,n): #Shift x to the right by n places. Truncates the rightmost n bits.
    return x >> n

def capS_0(x): #Capital Sigma_0 function
    return rotR(x, 2) ^ rotR(x, 13) ^ rotR(x, 22)

def capS_1(x): #Capital Sigma_1 function
    return rotR(x, 6) ^ rotR(x, 11) ^ rotR(x, 25)

def lowerS_0(x): #Lowercase sigma_0 function
    return rotR(x, 7) ^ rotR(x, 18) ^ shr(x, 3)

def lowerS_1(x): #Lowercase sigma_1 function
    return rotR(x, 17) ^ rotR(x, 19) ^ shr(x, 10)

def Ch(x,y,z): #Ch function
    return (x&y)^(~x&z)

def Maj(x,y,z): #Maj function
    return (x&y)^(x&z)^(y&z)
#-------------------------------------------- END SHA256 Functions --------------------------------------------#


#-------------------------------------------- BEGIN SHA256 Main --------------------------------------------#
def padMsg(message):                                                #Pads message to be a multiple of 512 bits. The first "length" bits are the message, followed by "k" zeroes, followed by a 1 bit, followed by 64 bits containing "length" in binary
    length = len(message)*8                                         #8 bits/ASCII character
    k = (447 - length) % 512                                        #k is residue of solution to: length + 1 + k (congruent to) 448 mod 512
    binMsg = int(binascii.hexlify(message.encode('utf-8')),16)      #Convert message to binary number
    binMsg = (binMsg << 1) + 1                                      #Append 1 to binary representation of message
    binMsg = bin((binMsg << (k+64)) ^ length)[2:]                   #Shift add k+64 zeroes to the right, add length to the very end
    leftPad = 512*int(math.ceil(len(binMsg)/512.0))
    return binMsg.zfill(leftPad)                                    #Fill left with appropriate amount of zeroes


def hash(msg):                                                      #Performs the actual hashing of the message
    global K
    twoPow32 = 1 << 32                                              #SHA-256 uses 32 bit words, need to mod by 2^32 sometimes.
    paddedMsg = padMsg(msg)
    M = [paddedMsg[i:i+512] for i in range(0, len(paddedMsg), 512)] #Break M into 512-bit blocks
    for i in range(len(M)):                                         #Break each block into 16 subblocks of size 32 bits.
        M[i] = [int(M[i][j:j+32],2) for j in range(0, len(M[i]), 32)]
    H = [[None for i in range(8)] for j in range(len(M)+1)]         #There will be (number of blocks) hashes
    H[0] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19] #Initial hash values for first block are predetermined

    #Step 1.) Prepare Message Schedule
    for i in range(1,len(M)+1):
        W = []
        for t in range(16):
            W.append(M[i-1][t])
        for t in range(16, 64):
            W.append((lowerS_1(W[t-2]) + W[t-7] + lowerS_0(W[t-15]) + W[t-16]) % twoPow32)

        #Step 2.) Initialize working variables a-h with previous hash value
        a = H[i-1][0]
        b = H[i-1][1]
        c = H[i-1][2]
        d = H[i-1][3]
        e = H[i-1][4]
        f = H[i-1][5]
        g = H[i-1][6]
        h = H[i-1][7]

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
        H[i][0] = (H[i-1][0] + a) % twoPow32
        H[i][1] = (H[i-1][1] + b) % twoPow32
        H[i][2] = (H[i-1][2] + c) % twoPow32
        H[i][3] = (H[i-1][3] + d) % twoPow32
        H[i][4] = (H[i-1][4] + e) % twoPow32
        H[i][5] = (H[i-1][5] + f) % twoPow32
        H[i][6] = (H[i-1][6] + g) % twoPow32
        H[i][7] = (H[i-1][7] + h) % twoPow32

    #Step 5.) Convert H[(num blocks)][0]:H[num blocks][7] to hex, concatenate
    result = ""
    for x in H[len(M)]:
        y = format(x, '0x').zfill(8)
        result += y
    return result
#-------------------------------------------- END SHA256 Main --------------------------------------------#


#-------------------------------------------- BEGIN Print Result --------------------------------------------#
time0 = int(round(time.time() * 1000))
msgHash = hash(msg)
time1 = int(round(time.time() * 1000))
deltaTime = int(time1-time0)
trueHash = hashlib.sha256(msg.encode('utf-8')).hexdigest()

if py3:
    print("Got:         ", msgHash)
    print("True answer: ", trueHash)
    print("Are they equal?", "Yes" if msgHash == trueHash else "Oh dear.")
    print("This took", deltaTime, "ms")
else:
    print "Got:         ", msgHash
    print "True answer: ", trueHash
    print "Are they equal?", "Yes" if msgHash == trueHash else "Oh dear."
    print "This took", deltaTime, "ms"
#-------------------------------------------- END Print Result --------------------------------------------#
