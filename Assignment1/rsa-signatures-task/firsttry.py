import requests
import json
import math
import sys

basepath = 'http://localhost:5000'
gradepath = basepath + '/grade'
quotepath = basepath + '/quote'
keypath = basepath + '/pk'
signpath = basepath + '/sign_random_document_for_students'

#The message we want to have signed
desiredMessage = 'You got a 12 because you are an excellent student! :)'.encode()

#Set to decimal value 5, such that desiredmessage and randomMessage1 is divisible
randomMessage1 = ''.encode()

#Used for the random message attack
randomMessage2 = 'This is a test'.encode()

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

def signRandomMessageAttack():
 N = json.loads(getPublicKey())['N']
 
 m1Response = signMessage(randomMessage1)
 m1Data = json.loads(m1Response.text)
 s1 = bytes.fromhex(m1Data['signature'])
 m1 = bytes.fromhex(m1Data['msg'])
 s1Int = int.from_bytes(s1, 'big')
 m1Int = int.from_bytes(m1, 'big')
 
 m2Response = signMessage(randomMessage2)
 m2Data = json.loads(m2Response.text)
 s2 = bytes.fromhex(m2Data['signature'])
 m2 = bytes.fromhex(m2Data['msg'])
 s2Int = int.from_bytes(s2, 'big')
 m2Int = int.from_bytes(m2, 'big')
 
 sInt = (s1Int * s2Int) % N
 mInt = (m1Int * m2Int) % N
 
 s = sInt.to_bytes(math.ceil(sInt.bit_length() /8),'big')
 m = mInt.to_bytes(math.ceil(mInt.bit_length() /8),'big')
 
 mHex = m.hex()
 sHex = s.hex()
 
 return tryGetQuote(mHex, sHex).text

def signDesiredMessageAttack():
 N = json.loads(getPublicKey())['N']
 
 m1Response = signMessage(randomMessage1)
 m1Data = json.loads(m1Response.text)
 s1 = bytes.fromhex(m1Data['signature'])
 m1 = bytes.fromhex(m1Data['msg'])
 s1Int = int.from_bytes(s1, 'big')
 m1Int = int.from_bytes(m1, 'big')
 
 mInt = int.from_bytes(desiredMessage, 'big')
 
 #Needs to be a whole number, and therefore using // - ensures result is whole number
 m2Int = mInt//m1Int % N
 
 bytelength = math.ceil(m2Int.bit_length() /8)
 m2Bytes = m2Int.to_bytes(bytelength, 'big')
 
 m2Response = signMessage(m2Bytes)
 m2Data = json.loads(m2Response.text)
 m2Hex = m2Data['msg']
 s2Hex = m2Data['signature']
 s2 = bytes.fromhex(s2Hex)
 m2 = bytes.fromhex(m2Hex)
 
 s2Int = int.from_bytes(s2, 'big')
 
 sInt = s1Int * s2Int % N
 
 s = sInt.to_bytes(math.ceil(sInt.bit_length() / 8), 'big')
 
 mHex = desiredMessage.hex()
 sHex = s.hex()
 
 return tryGetQuote(mHex, sHex).text

def main():
 print(signRandomMessageAttack())
 print(signDesiredMessageAttack())
 
if __name__ == "__main__":
 main()