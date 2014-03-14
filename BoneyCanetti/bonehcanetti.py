from charm.toolbox.PKEnc import PKEnc
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.schemes.ibenc.ibenc_bb03 import IBE_BB04
import random
import hmac
from hashlib import sha1 as sha1hashlib

'''
Author: Sebastian Janus
Date:   20.05.2013

Implementation of of Chosen-Ciphertext Security from Identity-based Encryption from Boneh, Canetti, Halevi and Katz.
Based on a modified version, presented in the master thesis.

'''
debug = False
class CHK04(PKEnc):
    # Init Function prepares the CHARM environment.
    def __init__(self, ibe_scheme, hibe_scheme,groupObj):
        global ibe, group, hash_ibe
        ibe = ibe_scheme
        hash_ibe = hibe_scheme
        group = groupObj
        
    # Encpasulation scheme. Init function, that generates a random value s with the size secparam/10.    
    def init_enc(self,secparam):
        
        s = bytes(str(int(random.getrandbits(int(secparam/10)))),'utf-8')             
        
        return s
    
    # Encapsulation scheme. Encapsulation function, which choses x at random and generates r, com and dec.
    def S_enc(self,pub, k1):
        
        x = random.getrandbits(k1)  
        r = group.hash(str(x))
        com = bytes(hmac.new(pub,bytes(str(x),'utf-8'),digestmod=sha1hashlib).hexdigest(),'utf-8')   
        com = str(com,'utf-8')
        dec = x
        
        s_res = {'r' : r, 'com' : com , 'dec' : dec}      
        
        return s_res
    
    # Encapsulation scheme. Recovery function, which checks wheter a hash of dec is equal to com. If so, r is generated and outputted.
    def R_enc(self,pub, com, dec):
    
        if(str(bytes(hmac.new(pub,bytes(str(dec),'utf-8'),digestmod=sha1hashlib).hexdigest(),'utf-8'),'utf-8')   == com):
            r_res = group.hash(str(dec))
        else:
            print("ERROR 2")
            
        
        return r_res
    
    # Key generation function, which generates the master public and master secret key.                
    def keygen(self, secparam):
       
        (mpk, msk) = ibe.setup()
        pub = self.init_enc(secparam)
        pk = { 'mpk' : mpk, 'pub' : pub }
        return (pk, msk)
        
    # Modified encryption function, which encrypts a random element of GT with the help of the underlying IBE and then uses the hash 
    # of this encryption as a symmetric key to actually encrypt the message m. 
    def encrypt(self, pk, message, secparam, k1):
        
        s_res=self.S_enc(pk['pub'],k1)

        P=group.random(GT)
        H_P=group.hash(str(P))
        msg=int(str(message)+str(s_res['dec']))
        c = hash_ibe.encrypt(pk['mpk'],s_res['com'], P)
        c_=msg ^ int(H_P)
        t = hmac.new(bytes(str(s_res['r']),'utf-8'),bytes(str(c_),'utf-8'),digestmod=sha1hashlib).hexdigest()
        l = len(str(s_res['dec']))
        enc = { 'com' : s_res['com'], 'c' : c, 'c_' : c_, 't' : t, 'l':l }
        
        return enc

    # Undoes the encryption.
    def decrypt(self, pk, sk, enc):
        
        identity = str(enc['com'])
        dk = hash_ibe.extract(sk, identity)         
        P2=hash_ibe.decrypt(pk, dk, enc['c'])
        H_P2=group.hash(str(P2))
        msg2= enc['c_'] ^int(H_P2)
        message2=int(str(msg2)[0:len(str(msg2))-enc['l']])
        dec2=int(str(msg2)[len(str(msg2))-enc['l']:])
                
        if(str(bytes(hmac.new(pk['pub'],bytes(str(dec2),'utf-8'),digestmod=sha1hashlib).hexdigest(),'utf-8'),'utf-8')   == enc['com']):
            r_res = group.hash(str(dec2))
            
        r_res=self.R_enc(pk['pub'],enc['com'],dec2)
        if(enc['t'] == hmac.new(bytes(str(r_res),'utf-8'),bytes(str(enc['c_']),'utf-8'),digestmod=sha1hashlib).hexdigest()):
            return message2
        else:
            print("ERROR")
        