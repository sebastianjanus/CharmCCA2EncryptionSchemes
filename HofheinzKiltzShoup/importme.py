from charm.toolbox.PKEnc import PKEnc
from charm.toolbox.integergroup import IntegerGroup, integer
from charm.toolbox.integergroup import IntegerGroup, integer, lcm, gcd
from charm.toolbox.integergroup import RSAGroup
import base64
import random
import hmac
from hashlib import sha1 as sha1hashlib
import hashlib
import sys
import math


sys.setrecursionlimit(15000)
def bbs(u,k,n):
    K = list()
    for z in range(0,k):
        K.append(lsb(u))
        u= (u * u) % n     
    K_=list_to_bin(K,k)
    return K_
    
def lsb(x):
    return (int(x) & 0b1)
    
def list_to_bin(K,k):
    b = K[0]
    for z in range(1,k):
        b= b << 1
        b = b | K[z]
    return b
    
def blum_check(value):
    tmp=value % 4
    if (tmp==3):
        return 1
    else:
        return 0
    
def jacobi(a,n):
    if a == 0:
        return 0
    if a == 1:
        return 1
    if a == 2:
        n8 = n%8
        if n8 == 3 or n8 == 5:
            return -1
        else:
            return 1
    if a%2 == 0:
        return jacobi(2,n) * jacobi(a//2,n)
    if a >= n:
        return jacobi(a%n,n)
    if a%4 == 3 and n%4 == 3:
        return -jacobi(n,a)
    else:
        return jacobi(n,a)

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)