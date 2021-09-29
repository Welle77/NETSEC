import json
import math
import sys
import random
import time

system_random = random.SystemRandom()

def main():
    keySize = 1024
    print(generate_key(keySize))

def generate_key(keySize):
    p = generate_large_prime(keySize)
    q = generate_large_prime(keySize)
    n = p*q
    
    while True:
        e = system_random.randrange(2**(keySize-1), 2**keySize)
        if gcd(e,(p-1)*(q-1)) == 1:
            break

    d = findModInverse(e,(p-1)*(q-1))

    publicKey = (n, e)
    privateKey = (n, d)

    return (publicKey, privateKey)

def generate_large_prime(keySize):
    while True:
        num = system_random.randrange(2**(keySize-1), 2**keySize) # 2**keySize means 2^keySize
        if check_if_prime(num):
            return num

def check_if_prime(num):
    # https://geeksforgeeks.org/python-program-to-check-whether-a-number-is-prime-or-not/
    if num > 1:
        for i in range(2, int(num/2)+1):
            if (num % i) == 0:
                return False
            else:
                return True
    else:
        return False
 
# region cryptomath module
# http://inventwithpython.com/hacking (BSD Licensed)

def gcd(a, b):
    # Return the GCD of a and b using Euclid's Algorithm
    while a != 0:
        a, b = b % a, a
    return b


def findModInverse(a, m):
    # Returns the modular inverse of a % m, which is
    # the number x such that a*x % m = 1

    if gcd(a, m) != 1:
        return None # no mod inverse if a & m aren't relatively prime

    # Calculate using the Extended Euclidean Algorithm:
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3 # // is the integer division operator
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m
 # endregion
 
if __name__ == "__main__":
    main()
    