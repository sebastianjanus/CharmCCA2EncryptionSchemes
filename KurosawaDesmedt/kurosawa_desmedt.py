from charm.toolbox.PKEnc import PKEnc
from charm.toolbox.integergroup import IntegerGroup, integer
import base64
from charm.toolbox.ecgroup import G

'''
Author: Sebastian Janus
Date:   01.04.2013

Implementation of Kurosawa-Desmedt encryption scheme, based on the decisional Diffie-Hellman assumption and a symmetric encryption scheme.
Integer instantiation only. Implementation based on Kaoru Kurosawa and Yvo Desmedt. A New Paradigm of Hybrid Encryption Scheme.
'''

debug = False
class KD(PKEnc):	
    # Init Function prepares the CHARM environment.
    def __init__(self, groupObj, p=0, q=0):
        PKEnc.__init__(self)
        global group
        group = groupObj
        if group.groupSetting() == 'integer':
            group.p, group.q, group.r = p, q, 2

    # keygen generates the public and private key.    
    def keygen(self, secparam=0):
        if group.groupSetting() == 'integer':
            if group.p == 0 or group.q == 0:
                group.paramgen(secparam)
            p = group.p
            print("p",p)
            g1, g2 = group.randomGen(), group.randomGen()
        elif group.groupSetting() == 'elliptic_curve':
            group.paramgen(secparam)
            g1, g2 = group.random(G), group.random(G)
        
        x1, x2, y1, y2 = group.random(), group.random(), group.random(), group.random()	
        c = ((g1 ** x1) * (g2 ** x2))
        d = ((g1 ** y1) * (g2 ** y2)) 
       	
        pk = { 'g1' : g1, 'g2' : g2, 'c' : c, 'd' : d }
        sk = { 'x1' : x1, 'x2' : x2, 'y1' : y1, 'y2' : y2}
       
        return (pk, sk)

    # encrypts the message M with the a symmetric key encryption scheme that derives the key K fom the public key.
    def encrypt(self, pk, M):
        r     = group.random()
        u1    = (pk['g1'] ** r)
        u2    = (pk['g2'] ** r)
        alpha = group.hash((u1, u2))
        v     = (pk['c'] ** r) * (pk['d'] ** (r * alpha))
        #v = v % group.p
        K = group.hash(v)

        #msg=group.encode(M)
       
		# replace with symmetric key encryption scheme based on PRBG key generator and one-time pad, such as the scheme presented in Shoup: Using Hash Functions as a Hedge against Chosen Ciphertext Attacks.
		
                
        c = { 'u1' : u1, 'u2' : u2}
        return c
    
    # decrypts c, checks validity and outputs the message M.
    def decrypt(self, pk, sk, c):
        alpha = group.hash((c['u1'], c['u2']))
        v = (c['u1'] ** (sk['x1'] + (sk['y1'] * alpha))) * (c['u2'] ** (sk['x2'] + (sk['y2'] * alpha)))
        #v = v % group.p
        K = group.hash(v)
            # replace with symmetric key encryption scheme based on PRBG key generator and one-time pad, such as the scheme presented in Shoup: Using Hash Functions as a Hedge against Chosen Ciphertext Attacks.
        #M=group.decode(msg)
        return K
