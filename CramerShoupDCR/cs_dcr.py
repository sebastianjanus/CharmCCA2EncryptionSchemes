from charm.toolbox.ecgroup import G
from charm.toolbox.PKEnc import PKEnc
from charm.toolbox.integergroup import IntegerGroup, integer, lcm, gcd
from charm.core.math.integer import integer,isPrime,gcd,random,randomPrime,toInt
from charm.toolbox.conversion import Conversion
from charm.core.engine.util import *
from math import ceil
import base64

'''
Author: Sebastian Janus
Date:   18.03.2013

Implementation of Cramer-Shoup CCA2-secure encryption scheme, based on the decisional composite residuosity assumption.
Integer instantiation only. Implementation based on R. Cramer and V. Shoup. Universal Hash Proofs and a Paradigm for Adaptive Chosen Ciphertext Secure Public-Key Encryption.

'''

debug = False
class CSDCR(PKEnc):	
    # Init Function prepares the CHARM environment.
    def __init__(self, groupObj):
        PKEnc.__init__(self)
        global group
        group = groupObj
        
    # Definies parameter that are used throughout encryption and decryption. Can be executed before actual encryption/decryption is required.    
    def parameter(self,secparam):
        (p, q, na) = group.paramgen(secparam)
        global n 
        n = na
        global n2
        n2 = n * n
        global n2_half, n_quarter
        n2_half= n2/2
        n_quarter = n/4
        
    # takes a string and represents as a bytes object
    def encode(self, modulus, message):    
        elem = integer(message)
        return elem % modulus
    
    # gamma function is defined as an injective mapping function, splitting u1, u2 and e in k parts.
    def gamma(self,u1, e, k):
        concat_str=str(hex(int(u1))[2:]+hex(int(e))[2:])
        length= int(len(concat_str)/k)
        gamma=list()
        for z in range(0,k):
            gamma.append(integer(concat_str[(z*length):(z+1)*length], 'utf-8') % n2)
                   
        return gamma
    
    # chi function is a one-to-one map from a + bN mod N^2 to b mod N. 
    def chi(self, rho):
        factor = integer(rho) / integer(n)
        pi= (factor % n) % n2
        
        return pi   
      
    # keygen generates the public and private key.    
    def keygen(self, secparam, k): 
        while True:
            mu = group.random(n2)
            if gcd(mu,n2)==1:
                break
        g = (mu % n2) ** (2*n)
        
        x,y = group.random(n2_half), group.random(n2_half)
        x= x % n2
        y= y % n2
        z_list = list()
        for z in range(0,k):
            z_list.append(group.random(n2_half))
            z_list[z] = z_list[z] % n2
    
        c = g ** x
        d = g ** y
        h_list = list()
        for z in range(0,k):
            h_list.append(g**z_list[z])
        
        pk = { 'g' : g, 'c' : c, 'd' : d, 'h_list' : h_list }
        sk = { 'x' : x, 'y' : y, 'z_list' : z_list }
        print("PK",pk)
        return(pk,sk)

    # encrypts the message M with the public key after it has been encoded. 
    def encrypt(self, pk, M, k):
        r_n     = group.random(n_quarter)
        r = integer(r_n) % n2
        u1 = pk['g'] ** r
        rho = pk['c'] ** r
        pi = self.chi(rho)
        e = self.encode(n2, M) * pi
        tmp = []
        tmp_ges=1
        gamma = self.gamma(u1,e,k)
        for p in range(0,k):
            tmp.append((pk['h_list'][p] ** (r * gamma[p])))
            tmp_ges= tmp_ges * tmp[p]
            
        rho_dach = (pk['d'] ** r) * tmp_ges 
        pi_dach = self.chi(rho_dach)
        
        c = { 'u1' : u1, 'e' : e, 'pi_dach' : pi_dach }
        return c
    
    # decrypts c, checks validity and outputs the message M.
    def decrypt(self, pk, sk, c, k):
        tmp_ges = 0
        tmp = []
        gamma = self.gamma(c['u1'], c['e'],k)
        for p in range(0,k):
            tmp.append(gamma[p] * sk['z_list'][p])
            tmp_ges = tmp_ges + tmp[p]
        rho_dach_2 = c['u1'] ** (sk['y'] + tmp_ges)
        pi_dach_2 = self.chi(rho_dach_2)
        if(c['pi_dach'] != pi_dach_2):
            return 'ERROR'
        rho = c['u1'] ** sk['x']
        pi = self.chi(rho) 
        msg = c['e'] / pi
        return msg
        

