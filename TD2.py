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

#------------------ BIP 39 -------------------
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
        
        
#--------- Fonctions de transformation ----------
        
def hexToBin(x):
    scale = 16 ## equals to hexadecimal
    num_of_bits = 8
    return bin(int(x, scale))[2:].zfill(num_of_bits)

def bitstring_to_bytes(s):
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')

def int_to_bitstring(x):
    return "{0:b}".format(x)


#------------------ BIP 32 -------------------

# Child key derivation en ne fournissant que la seed
def bip32_standard(seed):

    seed_512 = hashlib.sha512(seed).hexdigest()
    
    seed_512_bin = hexToBin(seed_512)
    mprk=seed_512_bin[:int(len(seed_512)/2)]
    mcc=seed_512_bin[int(len(seed_512)/2):]
    
    # index ≥ 2147483648 (or 2^31) for the child to be a hardened key
    index='10000000000000000000000000000000'
    
    #The 00 pads the private key to make it 33 bytes long.
    data = '00'+mprk+index
    
    child_resultat = hmac.new(
        bitstring_to_bytes(mcc),
        msg= bitstring_to_bytes(data),
        digestmod=hashlib.sha512
        ).hexdigest()
    
    # on a : child = [privatekey, chaincode, index]
    child_resultat = hexToBin(child_resultat)
    child_resultat_prk = int(child_resultat[:int(len(child_resultat)/2)],2) + int(mprk,2)
    child = [
        int_to_bitstring(child_resultat_prk),
        child_resultat[int(len(child_resultat)/2):],
        index
        ]
    return child

# Child key derivation à l'index i
def bip32_index(seed, index):

    seed_512 = hashlib.sha512(seed).hexdigest()
    
    seed_512_bin = hexToBin(seed_512)
    mprk=seed_512_bin[:int(len(seed_512)/2)]
    mcc=seed_512_bin[int(len(seed_512)/2):]
    
    # index ≥ 2147483648 (or 2^31) for the child to be a hardened key
    index += 2147483648
    index = int_to_bitstring(index)
    
    #The 00 pads the private key to make it 33 bytes long.
    data = '00'+mprk+index
    
    child_resultat = hmac.new(
        bitstring_to_bytes(mcc),
        msg= bitstring_to_bytes(data),
        digestmod=hashlib.sha512
        ).hexdigest()
    
    # on a : child = [privatekey, chaincode, index]
    child_resultat = hexToBin(child_resultat)
    child_resultat_prk = int(child_resultat[:int(len(child_resultat)/2)],2) + int(mprk,2)
    child = [
        int_to_bitstring(child_resultat_prk),
        child_resultat[int(len(child_resultat)/2):],
        index
        ]

    return child

# Child key derivation à l'index i et à la profondeur m
def bip32_index_depth(seed, index, depth):

    seed_512 = hashlib.sha512(seed).hexdigest()
    
    seed_512_bin = hexToBin(seed_512)
    mprk=seed_512_bin[:int(len(seed_512)/2)]
    mcc=seed_512_bin[int(len(seed_512)/2):]
    
    # index ≥ 2147483648 (or 2^31) for the child to be a hardened key
    index += 2147483648
    index_temp = index + 1
    index = int_to_bitstring(index)
    index_temp = int_to_bitstring(index_temp)


    data = '00'+mprk+index_temp
    
    child_resultat = hmac.new(
        bitstring_to_bytes(mcc),
        msg= bitstring_to_bytes(data),
        digestmod=hashlib.sha512
        ).hexdigest()
    
    
    # on a : child[depth] = [privatekey, chaincode, index]
    child_resultat = hexToBin(child_resultat)
    child_resultat_prk = int(child_resultat[:int(len(child_resultat)/2)],2) + int(mprk,2)
    child = [[
        int_to_bitstring(child_resultat_prk),
        child_resultat[int(len(child_resultat)/2):],
        index_temp
        ]]
    
    for m in range(0, depth+1):
        if m != depth:
            index_temp = int_to_bitstring(int(index_temp,2) + 1)
            #The 00 pads the private key to make it 33 bytes long.
            data = '00'+child[m][0]+index_temp
    
            child_resultat = hmac.new(
                bitstring_to_bytes(child[m][1]),
                msg= bitstring_to_bytes(data),
                digestmod=hashlib.sha512
                ).hexdigest()
            
            # on a : child[depth] = [privatekey, chaincode, index]
            child_resultat = hexToBin(child_resultat)
            child_resultat_prk = int(child_resultat[:int(len(child_resultat)/2)],2) + int(child[m][0],2)
            child.append([
                int_to_bitstring(child_resultat_prk),
                child_resultat[int(len(child_resultat)/2):],
                index_temp
                ])
        else:
            data = '00'+child[m][0]+index
    
            child_resultat = hmac.new(
                bitstring_to_bytes(child[m][1]),
                msg= bitstring_to_bytes(data),
                digestmod=hashlib.sha512
                ).hexdigest()
            
            # on a : child[depth] = [privatekey, chaincode, index]
            child_resultat = hexToBin(child_resultat)
            child_resultat_prk = int(child_resultat[:int(len(child_resultat)/2)],2) + int(child[m][0],2)
            child.append([
                int_to_bitstring(child_resultat_prk),
                child_resultat[int(len(child_resultat)/2):],
                index
                ])
    
    return child
    
bip32_index(b'000011001000001100100100110010010011001001011100100101110010010110001001011010100101101110010110111001011011100101101110010110111001',
            2)
bip32_index_depth(b'000011001000001100100100110010010011001001011100100101110010010110001001011010100101101110010110111001011011100101101110010110111001',
            2, 3)