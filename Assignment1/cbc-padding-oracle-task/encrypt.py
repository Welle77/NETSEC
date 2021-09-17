import requests
import secrets

basepath = 'http://localhost:5000'
basepath = 'http://localhost:5000'
quotepath = basepath + '/quote'

textToEncrypt = '<redacted>' + ' plain CBC is not secure!'

def askPaddingOracle(text):
 cookies = {'authtoken': text.hex()}
 response = requests.get(quotepath, cookies = cookies)
 return response
 
def main():
 encodedText = textToEncrypt.encode()
 textByteArray = bytearray(encodedText)
 
 plainTextArray = bytearray(48)
 
 for index in range(35, 48):
  plainTextArray[index] = 13
 
 for index in range (0, 35):
  plainTextArray[index] = textByteArray[index]
 
 cipherN = bytearray(16)
 
 p1 = bytearray(plainTextArray[0:16])
 p2 = bytearray(plainTextArray[16:32])
 p3 = bytearray(plainTextArray[32:48])
 
 intermediate = bytearray(16)
 emptyBlock = bytearray(16)
 
 for value in range(0,255):
  emptyBlock[15] = value
  Cdot = emptyBlock + cipherN
  response = askPaddingOracle(Cdot)
  if 'padding is incorrect' not in response.text.lower():
   plaintextValue = p3[15]
   print(value)
   print(plaintextValue)
   print(value ^ 1 ^ plaintextValue)
   intermediate[15] = value ^ 1 ^ plaintextValue
   break
  else:
   continue
 
 
 
if __name__ == "__main__":
 main()