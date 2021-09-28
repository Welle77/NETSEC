from Crypto.Hash import SHA256
from Crypto.Signature.pss import MGF1
import math
import secrets

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
 byteValue = maskedDb[0]
 maskedDb[0] &= 0b01111111
 bcByteArray = bytearray(1)
 bcByteArray[0] = 188
 EM = maskedDb + H + bcByteArray

 return EM

def OS2IP(string):
 return int.from_bytes(string, 'big')

def RSASP1(K: tuple, m):
 raise NotImplementedError

def I2OSP(integer):
 return integer.to_bytes(math.ceil(integer.bit_length() /8),'big')

def RSASSA_PSS_SIGN(K: tuple, M):
 encodedMessage = EMSA_PSS_ENCODE(M, modBits - 1)
 encodedInteger = OS2IP(encodedMessage)
 signaturePrimitive = RSASP1(K, encodedInteger)
 signature = I2OSP(signaturePrimitive)
 return signature

def RSASSA_PSS_VERIFY(pubK, M, S):
 raise NotImplementedError

def RSAVP1(pubK, s):
 #Should apply RSASP1 signature primitive - produce signature representative
 raise NotImplementedError

def EMSA_PSS_VERIFY(M, EM, emBits):
 raise NotImplementedError
 
def generateKeys():
 #Should generate valid keys somehow
 return (1,2), (3,4) 
 
def main():
 privKey, pubKey = generateKeys()
 signature = RSASSA_PSS_SIGN(privKey, messageToSign)
 print(signature)
 
if __name__ == "__main__":
 main()