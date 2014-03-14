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
import importme


debug = False
class HOF(PKEnc):	
    # Init Function prepares the CHARM environment.
    def __init__(self, groupObj, p=0, q=0):
        PKEnc.__init__(self)
        global group
        global lt
        global lk
        lt=lk=160
        group = groupObj
        group.p, group.q, group.r = p, q, 2
    
        
        
    # keygen generates the public and private key.
    def keygen(self, secparam):
        group.n=group.p*group.q
        global n_quarter, n_half
        n_quarter = ((group.n -1) / 4) % group.n
        n_half = ((group.n -1) / 2) % group.n
    
        g = group.random(n_half)
        while(importme.jacobi(int(g),int(group.n))!=1):
            g=group.random(n_half)
        g = g % group.n
        
        alpha = group.random(n_quarter)
        alpha = alpha % group.n

        X=g ** (alpha * ((2 ** (lk + lt)) % group.n)) 
        pk={'g': g, 'X' : X}
        sk={'alpha': alpha}
        
        return (pk, sk)

    # encrypts the message M with the help of a symmetric dummy function based on the generated key K.
    def encrypt(self, pk, M):

        r = group.random(n_quarter)
        r= r % group.n
        

        R= pk['g'] ** (r * ((2 ** (lk + lt)) % group.n)) 
        print(R<=n_half)
        print(importme.jacobi(int(R),int(group.n)))
        m = hashlib.sha1()
        m.update(str(R).encode('utf-8'))
        t=m.hexdigest()
        t=(int(t,16) % ((2 ** lt) -1))+1
        t= t % group.n

        S = ((pk['g'] ** t) * pk['X']) ** r
        print(S<=n_half)
        print(importme.jacobi(int(S),int(group.n)))
        

        key_m=pk['g'] ** (r * ((2 ** lt)% group.n))
        K=importme.bbs(int(key_m),lk,group.n)
        c= M ^ K
        C={'R': R, 'S': S, 'c' : c}
        return C

    # decrypts c, checks validity and outputs the message M.
    def decrypt(self, pk, sk, C):
        
        if(importme.jacobi(int(C['R']),int(group.n))!=1):
            print("ERROR1")
        if(importme.jacobi(int(C['S']),int(group.n))!=1):
            print("ERROR2")
        m2 = hashlib.sha1()
        m2.update(str(C['R']).encode('utf-8'))
        t2=m2.hexdigest()
        t2=(int(t2,16) % ((2 ** lt) -1))+1
        t2=t2%group.n


        eins=C['S'] ** ((2**(lt+lk)) % group.n)
        eins = eins % group.n

        zwei = C['R'] ** ((t2 % group.n)+(sk['alpha']*((2**(lt+lk)) % group.n)))
        zwei = zwei % group.n
        if(eins!=zwei):
            print("ERROR3")
            
        tst=gcd(int(t2),2**(lk+lt))
        c=int(math.log(float(int(tst)))/math.log(2))
        c=c % group.n

        (gg,a,b)=importme.egcd(int(t2),2**(lk+lt))
        a=(a % (2**(lk+lt))) % group.n
        b=(b % int(t2)) % group.n

        T = ((C['S']**a) * (C['R']**(b - (a * sk['alpha'])))) ** ((2%group.n) ** ((lt % group.n) - c))
        
        K2=importme.bbs(T,lk,group.n)
        M = C['c'] ^ K2
        
        return M
        
        
        