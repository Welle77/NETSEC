import requests
import json
import math
import base64
import string

basepath = 'https://rsa.syssec.lnrd.net/'
quotepath = basepath + '/quote'
keypath = basepath + '/pk'
signpath = basepath + '/sign_random_document_for_students'

#The message we want to have signed
desiredMessage = 'You got a 12 because you are an excellent student! :)'.encode()

#Set to decimal value 5, such that desiredmessage and randomMessage1 is divisible
randomMessage1 = ''.encode()

#Used for the random message attack
randomMessage2 = 'This is a test'.encode()

def json_to_cookie(j: str) -> str:
    """Encode json data in a cookie-friendly way using base64."""
    # The JSON data is a string -> encode it into bytes
    json_as_bytes = j.encode()
    # base64-encode the bytes
    base64_as_bytes = base64.b64encode(json_as_bytes, altchars=b'-_')
    # b64encode returns bytes again, but we need a string -> decode it
    base64_as_str = base64_as_bytes.decode()
    return base64_as_str

def tryGetQuote(msg: bytes, signature: bytes ):
 j = json.dumps({'msg': msg, 'signature': signature})
 cookies = {'grade': json_to_cookie(j)}
 response = requests.get(quotepath, cookies = cookies)
 return response.text

def signMessage(message: bytes):
 hex = message.hex()
 path = buildSignPath(hex)
 response = requests.get(path)
 data = json.loads(response.text)
 signature = bytes.fromhex(data['signature'])
 message = bytes.fromhex(data['msg'])
 signatureInteger = int.from_bytes(signature, 'big')
 messageInteger = int.from_bytes(message, 'big')
 return (messageInteger, signatureInteger)
 
def getPublicKey():
 return requests.get(keypath).text

def buildSignPath(data: str):
 return signpath + '/' + data

def signRandomMessageAttack():
 N = json.loads(getPublicKey())['N']
 
 m1Int, s1Int = signMessage(randomMessage1)
 
 m2Int, s2Int = signMessage(randomMessage2)
 
 sInt = (s1Int * s2Int) % N
 mInt = (m1Int * m2Int) % N
 
 s = sInt.to_bytes(math.ceil(sInt.bit_length() /8),'big')
 m = mInt.to_bytes(math.ceil(mInt.bit_length() /8),'big')
 
 mHex = m.hex()
 sHex = s.hex()
 
 return tryGetQuote(mHex, sHex)

def signDesiredMessageAttack():
 N = json.loads(getPublicKey())['N']
 
 m1Int, s1Int = signMessage(randomMessage1)
 
 mInt = int.from_bytes(desiredMessage, 'big')
 
 #Needs to be a whole number, and therefore using // - ensures result is whole number
 m2Int = mInt//m1Int % N
 
 bytelength = math.ceil(m2Int.bit_length() /8)
 m2Bytes = m2Int.to_bytes(bytelength, 'big')
 
 m2Int, s2Int = signMessage(m2Bytes)
 
 sInt = s1Int * s2Int % N
 
 s: bytes = sInt.to_bytes(math.ceil(sInt.bit_length() / 8), 'big')
 
 mHex = desiredMessage.hex()
 sHex = s.hex()
 
 return tryGetQuote(mHex, sHex)

def main():
 #print(signRandomMessageAttack())
 print(signDesiredMessageAttack())
 
if __name__ == "__main__":
 main()