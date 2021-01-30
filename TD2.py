# -*- coding: utf-8 -*-
"""
Created on Fri Jan 29 16:23:44 2021

@author: Quentin
"""
import secrets
import bip39gen
import hashlib
import hmac
import os
import binascii

def bip39(seed=[]):
    if not seed:
        seedInt = secrets.randbits(128)
        seedInt=bin(seedInt).replace("0b","")
        while len(seedInt)<128:
            seedInt='0'+seedInt
        checkSum=seedInt[:int(len(seedInt)/32)]
        temp= seedInt+checkSum
        msi=[]
        for i in range(int(len(temp)/11)):
            msi.append(temp[i:i+11])
        wordlist=bip39gen.words()
        msm=[]
        for i in msi:
            msm.append(wordlist[int(i, 2)])
        print(msi)
        print(msm)
    else:
        wordlist = bip39gen.words()
        temp=[]
        for i in seed:
            temp.append(wordlist.index(i))
        msi=[]
        for i in temp:
            bits=bin(i).replace("0b", "")
            while len(bits)<11:
                bits='0'+bits
            msi.append(bits)
        print(msi)
        
def hexToBin(x):
    scale = 16 ## equals to hexadecimal
    num_of_bits = 8
    return bin(int(x, scale))[2:].zfill(num_of_bits)

def bip32(seed):

    seed_512 = hashlib.sha512(seed).hexdigest()
    
    seed_512_bin = hexToBin(seed_512)
    mprk=seed_512[:int(len(seed_512)/2)]
    mcc=seed_512[int(len(seed_512)/2):]
    
    index='0'
    seed_512_bin += index
    child1 = hashlib.sha512(seed_512_bin.encode('ascii')).hexdigest()

    child1bin = hexToBin(child1)
    print(len(child1bin))
    
bip32(b'000011001000001100100100110010010011001001011100100101110010010110001001011010100101101110010110111001011011100101101110010110111001')