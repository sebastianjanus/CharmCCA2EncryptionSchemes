from charm.toolbox.ecgroup import G
from charm.toolbox.PKEnc import PKEnc
from charm.toolbox.integergroup import IntegerGroup, integer
import base64

'''
Author: Sebastian Janus
Date:   12.03.2013

Implementation of Cramer-Shoup CCA2-secure encryption scheme, based on the decisional Diffie-Hellman assumption.
Integer instantiation only. Implementation based on R. Cramer and V. Shoup. Universal Hash Proofs and a Paradigm for Adaptive Chosen Ciphertext Secure Public-Key Encryption.

'''

debug = False
class CS98(PKEnc):	
    # Init Function prepares the CHARM environment.
    def __init__(self, groupObj, p=0, q=0):
        PKEnc.__init__(self)
        global group
        group = groupObj
        group.p, group.q, group.r = p, q, 2
        
    # gamma function is defined as an injective mapping function, splitting u1, u2 and e in k parts.
    def gamma(self,u1, u2, e, k):
        concat_str=str(hex(int(u1))[2:]+hex(int(u2))[2:]+hex(int(e))[2:])
        length= int(len(concat_str)/k)
        gamma=list()
        gamma_2=list()
        for z in range(0,k):
            gamma.append(group.encode(bytes(concat_str[(z*length):(z+1)*length], 'utf-8')))
                   
        return gamma
    
    # keygen generates the public and private key.
    def keygen(self, secparam,k):
        #group.paramgen(secparam)
        p = group.p
        print("p",p)
        print("q",group.q)
        print("Grouporder:",group.groupOrder())
        
        g1, g2 = group.randomGen(), group.randomGen()
        print("g1",g1)
                
        x1, x2, y1, y2 = group.random(), group.random(), group.random(), group.random()
        z_list = list()
        for z in range(0,(2*k)):
            z_list.append(group.random())	
        c = ((g1 ** x1) * (g2 ** x2))
        d = ((g1 ** y1) * (g2 ** y2)) 
        h_list = list()
        for z in range(0,k):
            h_list.append((g1 ** z_list[((z)*2)+1]) * (g2 ** z_list[2*z]))
		
        pk = { 'g1' : g1, 'g2' : g2, 'c' : c, 'd' : d, 'h_list' : h_list }
        sk = { 'x1' : x1, 'x2' : x2, 'y1' : y1, 'y2' : y2, 'z_list' : z_list }
        return (pk, sk)

    # encrypts the message M with the public key after it has been encoded as an element of Zp.
    def encrypt(self, pk, M, k):
        r     = group.random()
        u1    = (pk['g1'] ** r)
        u2    = (pk['g2'] ** r)
        pi    = (pk['c'] ** r)
        e     = group.encode(M) * pi
        gamma = self.gamma(u1,u2,e,k)
        tmp_ges = 1
        tmp = []
        for p in range(0,k):
            tmp.append((pk['h_list'][p] ** (r * gamma[p])))
            tmp_ges= (tmp_ges % group.p) * tmp[p]
        pi_2a = (pk['d'] ** r) * tmp_ges
		
                
        c = { 'u1' : u1, 'u2' : u2, 'e' : e, 'pi_2a' : pi_2a }
        return c

    # decrypts c, checks validity and outputs the message M.
    def decrypt(self, pk, sk, c,k):
        tmp_links_ges = 0
        tmp_rechts_ges = 0
        tmp_links = []
        tmp_rechts = []
        gamma=self.gamma(c['u1'], c['u2'], c['e'],k)
        for p in range(0,k):
            tmp_links.append(gamma[p] * sk['z_list'][((p)*2)+1])
            tmp_rechts.append(gamma[p] * sk['z_list'][(p*2)])
            tmp_rechts_ges = (tmp_rechts_ges % group.p) + tmp_rechts[p]
            tmp_links_ges = (tmp_links_ges % group.p) + tmp_links[p]
        pi_2b = (c['u1'] ** (sk['y1'] + tmp_links_ges)) * (c['u2'] ** (sk['y2'] + tmp_rechts_ges))
        if(c['pi_2a'] != pi_2b):
            return 'ERROR'
        pi = ( c['u1'] ** sk['x1']) * (c['u2'] ** sk['x2']) 
        M = ( c['e'] / pi) 
        return group.decode(M)
