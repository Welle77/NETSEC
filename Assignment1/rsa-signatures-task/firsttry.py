import requests
import json
import math

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
 n = json.loads(getPublicKey())['N']
 e = json.loads(getPublicKey())['e']
 
 print(n)
 print(e)
 
 m1Response = signMessage(m1)
 m1Data = json.loads(m1Response.text)
 s1 = m1Data['signature']
 s1 = s1.encode()
 s1Int = int.from_bytes(s1, 'big')
 
 mInt = int.from_bytes(m, 'big')
 m1Int = int.from_bytes(m1, 'big')
 
 x = mInt * (m1Int^1)
 m2Int = x % n
 
 m2 = m2Int.to_bytes(math.ceil(n.bit_length() / 8), 'big')
 
 m2Response = signMessage(m2)
 m2Data = json.loads(m2Response.text)
 
 s2 = m2Data['signature']
 s2 = s2.encode()
 s2Int = int.from_bytes(s2, 'big')
 
 sInt = (s1Int * s2Int)^e
 
 s = sInt.to_bytes(math.ceil(n.bit_length() / 8), 'big')
 
 mHex = m.hex()
 sHex = s.hex()
 
 print(tryGetQuote(mHex, sHex).text)
 
 #data = 'tolv'
 #data = data.encode()
 #hex = data.hex()
 #print(signData(hex).content)
 #print(getGradeCookie())
 #print(getPublicKey())
 
if __name__ == "__main__":
 main()