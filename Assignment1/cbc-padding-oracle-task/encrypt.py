import requests
from Crypto.Util.Padding import pad
import math

#basepath = 'http://localhost:5000'
basepath = 'https://cbc.syssec.lnrd.net'
quotepath = basepath + '/quote'

#secretFromOracleAttack = '<redacted>'
secretFromOracleAttack = "I should have used authenticated encryption because ..."
textToEncrypt = secretFromOracleAttack + ' plain CBC is not secure!'

def askPaddingOracle(text: bytearray):
    cookies = {'authtoken': text.hex()}
    response = requests.get(quotepath, cookies=cookies)
    return response

def askForQuote(text: bytearray):
    cookies = {'authtoken': text.hex()}
    response = requests.get(quotepath, cookies=cookies)
    return response

def encryptBlock(prev, next):

    CipherBytes = bytearray(16)
    dBlock = bytearray(16)
    cMarked = bytearray(16)
    
    for byteindex in range(15, -1, -1):
        paddingvalue = 16 - byteindex
        for index in range(15, byteindex, -1):
            cMarked[index] = paddingvalue ^ dBlock[index]

        for value in range(0, 256):
            cMarked[byteindex] = value
            blockToSend = cMarked + prev
            print('Trying value: ' + str(value))
            response = askPaddingOracle(blockToSend)

            if 'padding is incorrect' not in response.text.lower():
                dByteValue = value ^ paddingvalue
                dBlock[byteindex] = dByteValue
                cipherByte = next[byteindex] ^ paddingvalue ^ value
                CipherBytes[byteindex] = cipherByte
                print(cipherByte)
                break
            else:
                continue

    return CipherBytes

def main():
    encodedText = textToEncrypt.encode()
    textByteArray = bytearray(encodedText)
    plainTextArray = pad(textByteArray, 16)
    amountOfBlocks = math.ceil(len(plainTextArray)/16)
    plainTextBlockArray = []
    cipherTextBlockArray = []
    lastCipherBlock = bytearray(16)
    
    for block in range(0, amountOfBlocks):
        plainTextBlockArray.append(
            bytearray(plainTextArray[16*block:16*block+16]))

    cipherTextBlockArray.append(lastCipherBlock)

    for index in range(amountOfBlocks - 1, -1, -1):

        encryptedBlock = encryptBlock(
            cipherTextBlockArray[0], plainTextBlockArray[index])
        cipherTextBlockArray.insert(0, encryptedBlock)

    blockToSend = bytearray()
    for x in cipherTextBlockArray:
        blockToSend += x

    print(askForQuote(blockToSend).text)

if __name__ == "__main__":
    main()
