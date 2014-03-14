from base64 import b64encode, b64decode
from charm.toolbox.ecgroup import G
from charm.toolbox.PKEnc import PKEnc
from charm.toolbox.integergroup import IntegerGroup, integer
from charm.core.crypto.cryptobase import MODE_CBC,AES,selectPRP
from math import ceil
import json
import hmac
from base64 import b64encode,b64decode
import pbkdf2
import hashlib
from hashlib import sha1 as sha1hashlib
import os

'''
Author: Sebastian Janus
Date:   13.04.2013

Implementation of hybrid Cramer-Shoup, based on the decisional Diffie-Hellman assumption.
Integer instantiation only. Implementation based on Shoup. Using Hash Functions as a Hedge against Chosen Ciphertext Attacks.
'''

debug = False
class HCS(PKEnc):	
    # Init Function prepares the CHARM environment.
    def __init__(self, groupObj, p=0, q=0):
        PKEnc.__init__(self)
        global group
        group = groupObj
        group.p, group.q, group.r = p, q, 2

    # keygen generates the public and private key.
    def keygen(self, secparam=0):
        group.paramgen(secparam)
        p = group.p
        g1 = group.randomGen()
        w, x, y, z = group.random(), group.random(), group.random(), group.random()	
        g2 = g1 ** w	
        c = g1 ** x
        d = g1 ** y 
        h = g1 ** z
		
        pk = { 'g1' : g1, 'g2' : g2, 'c' : c, 'd' : d, 'h' : h }
        sk = { 'w' : w, 'x' : x, 'y' : y, 'z' : z}
        return (pk, sk)

    # encrypts the message M with the public key after it has been encoded. Key derivation function pbkdf2 is used to derive keys k and K.
    def encrypt(self, pk, M):
        r     = group.random()
        ka=bytes(str(int(pk['h'] ** r)), 'utf-8')
        salt=b'This is salt'
        salt2=b'This is salty'
        k=group.encode(pbkdf2.pbkdf2(hashlib.sha256,ka, salt, 32000, 16))
        K=group.encode(pbkdf2.pbkdf2(hashlib.sha256,ka, salt2, 32000, 16))
        u1 = pk['g1'] ** r
        u2 = pk['g2'] ** r
        alpha = group.hash((u1, u2))
        #msg = group.encode(M)
        chi = K ^ integer(M)
        v     = (pk['c'] ** r) * (pk['d'] ** (r * alpha))
        t=hmac.new(bytes(str(int(k)),'utf-8'),bytes(str(chi),"utf-8"),digestmod=sha1hashlib).hexdigest()
        c = { 'u1' : u1, 'u2' : u2, 'v' : v, 'chi' : chi, 't' : t}
        return c
    
    # decrypts the ciphertext c and decodes the element afterwards.
    def decrypt(self, pk, sk, c):
        alpha_2 = group.hash((c['u1'], c['u2']))
        v_2= c['u1'] ** (sk['x']+(sk['y']*alpha_2))
        ka_2=bytes(str(int(c['u1'] ** sk['z'])), 'utf-8')
        salt=b'This is salt'
        salt2=b'This is salty'
        k_2=group.encode(pbkdf2.pbkdf2(hashlib.sha256,ka_2 , salt, 32000, 16))
        K_2=group.encode(pbkdf2.pbkdf2(hashlib.sha256,ka_2 , salt2, 32000, 16))
        if (c['v']!=v_2):
            return 'ERROR'
        if (c['t']!=hmac.new(bytes(str(int(k_2)),'utf-8'),bytes(str(c['chi']),"utf-8"),digestmod=sha1hashlib).hexdigest()):
            return 'ERROR'
        if (c['u2']!=(c['u1']**sk['w'])):
            return 'ERROR'
        m= c['chi'] ^ K_2
        return m
        

