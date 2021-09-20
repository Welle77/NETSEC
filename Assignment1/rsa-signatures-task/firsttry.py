import requests

basepath = 'http://localhost:5000'
gradepath = basepath + '/grade'
quotepath = basepath + '/quote'
keypath = basepath + '/pk'
signpath = basepath + '/sign_random_document_for_students'

# might be good explanation here https://crypto.stackexchange.com/questions/35644/chosen-message-attack-rsa-signature/35656

def signData(data):
 path = buildSignPath(data)
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
 data = 'tolv'
 data = data.encode()
 hex = data.hex()
 print(signData(hex).content)
 print(getGradeCookie())
 print(getPublicKey())
 
if __name__ == "__main__":
 main()