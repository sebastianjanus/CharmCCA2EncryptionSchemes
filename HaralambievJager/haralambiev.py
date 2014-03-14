from charm.toolbox.PKEnc import PKEnc
from charm.toolbox.integergroup import IntegerGroup, integer
import base64
import random
import hmac
from hashlib import sha1 as sha1hashlib


debug = False
class HARA2(PKEnc):	
    # Init Function prepares the CHARM environment.
    def __init__(self, groupObj, p=0, q=0):
        PKEnc.__init__(self)
        global group
        group = groupObj
        group.p, group.q, group.r = p, q, 2
        
    # Implementation of the Levin-Goldreich Harcore-Predicate.
    def hardcore_func(self,a,b,secparam):
        a_=bin(int(a))
        b_=bin(int(b))
        sum=0
        for z in range(2, len(bin(int(a)))):
            sum = sum + (int(a_[z]) * int(b_[z]))       
        sum = sum % 2
        return sum
    
    # Helper function that concatinates the single bits from a list into a single bin value
    def list_to_bin(self,K,k):
        b = K[0]
        for z in range(1,k):
            b= b << 1
            b = b | K[z]
        return b
        
        
    # keygen generates the public and private key.
    def keygen(self, secparam,k):
        #group.paramgen(secparam)
        p = group.p
        g = group.randomGen()
        s = bytes(str(int(random.getrandbits(int(secparam/10)))),'utf-8') 
        R = random.getrandbits(secparam+10)
        x1, x2, y1, y2 = group.random(), group.random(), group.random(), group.random()
        z_list = list()
        for z in range(0,k):
            z_list.append(group.random())	
        X1=g ** x1
        X2=g ** x2
        Y1=g ** y1
        Y2=g ** y2
        Z_list = list()
        for z in range(0,k):
            Z_list.append(g ** z_list[z])
		
        pk = { 'g' : g, 'X1' : X1, 'X2' : X2, 'Y1' : Y1, 'Y2' : Y2, 'Z_list' : Z_list, 's' : s, 'R': R }
        sk = { 'x1' : x1, 'x2' : x2, 'y1' : y1, 'y2' : y2, 'z_list' : z_list }
        return (pk, sk)

    # encrypts the message M with the help of a symmetric dummy function based on the generated key K.
    def encrypt(self, pk, M,k,secparam):
        r     = group.random()
        C0= pk['g'] ** r
        t= bytes(hmac.new(pk['s'],bytes(str(int(C0)),'utf-8'),digestmod=sha1hashlib).hexdigest(),'utf-8')   
        t= int(t,16) % group.p
        C1= ((pk['X1'] ** t) * pk['X2']) ** r
        t_kg=((pk['Y1'] ** t) * pk['Y2']) ** r
        random.seed(int(t_kg))
        KG=random.getrandbits(secparam)
        K = list()
        for z in range(0,k):
            K.append(self.hardcore_func((pk['Z_list'][z] ** r), pk['R'], secparam))
            
        K_=self.list_to_bin(K,k)
        Kf=KG ^ K_
        c_ = M ^ Kf	
                        
        c = { 'C0' : C0, 'C1' : C1, 'Kf' : Kf, 'c_' : c_ }
        return c

    # decrypts c, checks validity and outputs the message M.
    def decrypt(self, pk, sk, c,k,secparam):
        
        t2=bytes(hmac.new(pk['s'],bytes(str(int(c['C0'])),'utf-8'),digestmod=sha1hashlib).hexdigest(),'utf-8')  
        t2 = int(t2,16) % group.p
        if(c['C1']!=(c['C0'] ** (sk['x1']* t2 + sk['x2']))):
            print('ERROR1')
        t_kg2=c['C0'] ** ((sk['y1']*t2)+sk['y2'])
        random.seed(int(t_kg2))
        KG2=random.getrandbits(secparam)
        K2 = list()
        for z in range(0,k):
            K2.append(self.hardcore_func((c['C0'] ** sk['z_list'][z]), pk['R'], secparam))  
             
        K2_=self.list_to_bin(K2,k)
        Kf=KG2 ^ K2_
        M = c['c_'] ^ Kf
        
        return M
        
        
        