import requests
from Crypto.Util.Padding import pad


basepath = 'http://localhost:5000'
quotepath = basepath + '/quote'

textToEncrypt = '<redacted>' + ' plain CBC is not secure!'

def askPaddingOracle(text):
 cookies = {'authtoken': text.hex()}
 response = requests.get(quotepath, cookies = cookies)
 return response

def askForQuote(text):
 cookies = {'authtoken': text.hex()}
 response = requests.get(quotepath, cookies = cookies)
 print(response.text)
 return response
 
def encryptBlock(prev, next):

   CipherBytes =  bytearray(16)
   dBlock = bytearray(16)
   cMarked = bytearray(16)
   

   for byteindex in range (15,-1, -1): 
      paddingvalue = 16 - byteindex
      for index in range(15, byteindex, -1):
         cMarked[index] = paddingvalue ^ dBlock[index]
     
      for value in range(0,256):
         cMarked[byteindex] = value
         blockToSend = cMarked + prev
         
         response = askPaddingOracle(blockToSend)
         
         if 'padding is incorrect' not in response.text.lower():
            dByteValue = value ^ paddingvalue
            dBlock[byteindex] = dByteValue
            cipherByte = next[byteindex] ^ paddingvalue ^ value
            CipherBytes[byteindex] = cipherByte
            print(str(cipherByte))
            break
         else:
            continue

   return CipherBytes

 

def main():
   encodedText = textToEncrypt.encode()
   textByteArray = bytearray(encodedText)
   plainTextArray = pad(textByteArray, 16)

   p1 = bytearray(plainTextArray[0:16])
   p2 = bytearray(plainTextArray[16:32])
   p3 = bytearray(plainTextArray[32:48])

   c3 = bytearray(16)
   c2 = encryptBlock(c3, p3)
   c1 = encryptBlock(c2, p2)
   iv = encryptBlock(c1, p1)
   finalCipher = iv + c1 + c2 + c3
   askForQuote(finalCipher)   
 
if __name__ == "__main__":
 main()