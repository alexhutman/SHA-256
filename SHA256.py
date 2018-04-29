#Used https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf for reference

import math
import binascii

w = 32 #SHA-256 uses 32 bit words
twoPowW = 1 << w
msg = "abc"

with open('constants.txt') as file:
    global constants
    constants = {}
    lines = file.readlines()
    for i in range(64):
        constants[i] = int(lines[i].rstrip(), 16)

def rotR(val, shift):  # partly from https://www.falatic.com/index.php/108/python-and-bitwise-rotation
    max_bits = math.floor(math.log(val, 2))+1
    print(max_bits)
    return ((val & (2**max_bits-1)) >> shift%max_bits) | (val << (max_bits-(shift%max_bits)) & (2**max_bits-1))

def onesComp(num):
    length = math.floor(math.log(num, 2))+1
    return num^(int('1'*length,2))

def addMod(x,y): #returns x+y mod 2^w
    global twoPowW
    return (x+y)%twoPowW

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
    return (x&y)^(onesComp(x)&z)

def Maj(x,y,z):
    return (x&y)^(x&z)^(y&z)

def padMsg(message): #TODO: MAKE THIS WORK
    length = len(message)*8 #8 bits/ASCII character
    k = (447 - length) % 512 #k is residue of solution to: length + 1 + k (congruent to) 448 mod 512
    binMsg = int(binascii.hexlify(message), 16) #Convert message to binary number
    binMsg = (binMsg << 1) + 1 #Append 1 to binary representation of message
    return (binMsg << (k+64)) ^ length #Shift left by k, add length to the end





a = 29
#print (bin(a))
#print (bin(rotR(a,1)))
print(bin(padMsg(msg)))
