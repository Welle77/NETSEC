import requests
import json
import math
import sys

basepath = 'http://localhost:5000'
gradepath = basepath + '/grade'
quotepath = basepath + '/quote'
keypath = basepath + '/pk'
signpath = basepath + '/sign_random_document_for_students'

m = b'You got a 12 because you are an excellent student! :)'
m1 = b'Rando message'

# might be good explanation here https://crypto.stackexchange.com/questions/35644/chosen-message-attack-rsa-signature/35656

def tryGetQuote(message, signature):
 j = json.dumps({'msg': message, 'signature': signature})
 cookies = {'grade': j}
 response = requests.get(quotepath, cookies = cookies)
 return response

def signMessage(message):
 hex = message.hex()
 path = buildSignPath(hex)
 return requests.get(path)
 
def getPublicKey():
 return requests.get(keypath).text
 
def getGradeCookie():
 response = requests.get(gradepath)
 cookie = response.cookies.get('grade')
 return cookie

def buildSignPath(data):
 return signpath + '/' + data

def main():
 N = json.loads(getPublicKey())['N']
 e = json.loads(getPublicKey())['e']
 
 m1Response = signMessage(m1)
 m1Data = json.loads(m1Response.text)
 
 s1 = m1Data['signature'].encode()
 
 s1Int = int.from_bytes(s1, 'big')
 
 mInt = int.from_bytes(m, 'big')
 m1Int = int.from_bytes(m1, 'big')
 
 x = int((mInt*(1/m1Int)))
 m2Int = x % N
 
 m2 = m2Int.to_bytes(math.ceil(m2Int.bit_length() / 8), 'big')

 m2Response = signMessage(m2)
 
 s2 = json.loads(m2Response.text)['signature'].encode()
 s2Int = int.from_bytes(s2, 'big')

 sInt = (s1Int*s2Int) %N
 
 mHex = m.hex()
 sHex = (sInt.to_bytes(math.ceil(sInt.bit_length() / 8), 'big')).hex()
 
 response = tryGetQuote(mHex, sHex)
 
if __name__ == "__main__":
 main()