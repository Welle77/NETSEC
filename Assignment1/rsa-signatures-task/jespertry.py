from Crypto.Hash import SHA256
from Crypto.Signature.pss import MGF1
from Crypto.Math import Primality
import math
import secrets
import random

system_random = random.SystemRandom()

messageToSign = b'Hello world'

saltLength = 32
modBits = 3072

def EMSA_PSS_ENCODE(M, emBits):
 hash = SHA256.new(M)

 emLen = math.ceil(emBits /8)
 hLen = len(hash.digest())
 sLen = saltLength
 
 salt = secrets.token_bytes(saltLength)
 
 zeroArray = bytearray(8)
 salt = bytearray(salt)
 hash = bytearray(hash.digest())

 mDot = zeroArray + hash + salt

 H = bytearray(SHA256.new(mDot).digest())

 oneArray = bytearray(1)
 oneArray[0] = 1
 PS = bytearray(emLen - sLen - hLen - 2)
 DB = PS + oneArray + salt
 
 dbMask = bytearray(MGF1(H, emLen - hLen - 1, SHA256))
 
 maskedDb = bytearray(len(dbMask))
 
 for index in range(0,len(dbMask),1):
  maskedDb[index] = DB[index] ^ dbMask[index]
 
 #NOT correct - should calculate which bits to set.
 numberOfBitsToClear = (8 * emLen) - emBits
 x = 0b11111111
 x = x >> numberOfBitsToClear
 maskedDb[0] &= x
 
 bcByteArray = bytearray(1)
 bcByteArray[0] = 188
 EM = maskedDb + H + bcByteArray

 return EM

def OS2IP(string):
 return int.from_bytes(string, 'big')

def RSASP1(K, m):
 n = K[0]
 d = K[1]
 assert 0 < m < (n - 1)
 return m**d % n

def I2OSP(integer):
 return integer.to_bytes(math.ceil(integer.bit_length() /8),'big')

def RSASSA_PSS_SIGN(K: tuple, M):
 encodedMessage = EMSA_PSS_ENCODE(M, modBits - 1)
 encodedInteger = OS2IP(encodedMessage)
 signaturePrimitive = RSASP1(K, encodedInteger)
 signature = I2OSP(signaturePrimitive)
 print(signature)
 return signature
 
def RSASSA_PSS_VERIFY(pubK, M, S):
 raise NotImplementedError

def RSAVP1(pubK, s):
 #Should apply RSASP1 signature primitive - produce signature representative
 raise NotImplementedError

def EMSA_PSS_VERIFY(M, EM, emBits):
 raise NotImplementedError

def generate_keys(keySize):
    p = generate_large_prime(keySize)
    q = generate_large_prime(keySize)
    n = p*q
    
    while True:
        e = system_random.randrange(2**(keySize-1), 2**keySize)
        if gcd(e,(p-1)*(q-1)) == 1:
            break

    d = findModInverse(e,(p-1)*(q-1))

    publicKey = (n, e)
    privateKey = (n, d)

    return (privateKey, publicKey)

def generate_large_prime(keySize):
    while True:
        num = system_random.randrange(2**(keySize-1), 2**keySize) # 2**keySize means 2^keySize
        if Primality.test_probable_prime(num):
            return num
        
        # if check_if_prime(num):
        #     return num

# def check_if_prime(num):
#     # https://geeksforgeeks.org/python-program-to-check-whether-a-number-is-prime-or-not/
#     if num > 1:
#         for i in range(2, int(num/2)+1):
#             if (num % i) == 0:
#                 return False
#             else:
#                 return True
#     else:
#         return False
 
# region cryptomath module
# http://inventwithpython.com/hacking (BSD Licensed)

def gcd(a, b):
    # Return the GCD of a and b using Euclid's Algorithm
    while a != 0:
        a, b = b % a, a
    return b


def findModInverse(a, m):
    # Returns the modular inverse of a % m, which is
    # the number x such that a*x % m = 1

    if gcd(a, m) != 1:
        return None # no mod inverse if a & m aren't relatively prime

    # Calculate using the Extended Euclidean Algorithm:
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3 # // is the integer division operator
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m
 # endregion
 
def main():
 privKey, pubKey = generate_keys(modBits)
 signature = RSASSA_PSS_SIGN(privKey, messageToSign)
 print(signature)
 
if __name__ == "__main__":
 main()