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
    if not seed:  # cas ou on veut générer une seed
        seedIntOr = secrets.randbits(128)  # on genere l'entier pour la seed
        seedInt = bin(seedIntOr)[2:].zfill(128)  # on le transforme en binaire et on pad avec des zeros à gauche
        seedIntOr = hex(seedIntOr)  # valeur de la seed en hexa pour la hasher et pour vérifier les résultats
        hash = hashlib.sha256(
            binascii.unhexlify(seedIntOr[2:])).hexdigest()  # hashage de la seed pour avoir la checksum
        checkSum = bin(int(hash[0], 16))[2:]  # la checksum est le premier chiffre en hexa du hash de la seed
        checkSum = checkSum.zfill(4)  # on pad la checksum si nécessaire
        temp = seedInt + checkSum  # on rajoute la checksum a la seed en binaire
        msi = []  # tableau contenant la seed avec la checksum en paquets de 11
        for i in range(12):
            msi.append(temp[11 * i:11 * i + 11])  # on crée les 12 paquets de 11 bits
        wordlist = bip39gen.words()  # on génère la wordlist bip 39 en anglais
        msm = []
        for i in msi:
            msm.append(wordlist[int(i, 2)])  # on rajoute chaque mot correspondant à chaque paquet de 11 bits
        resSeed = 'La seed binaire est : ' + ''.join(msi)[:-4]
        resMnemo = 'La seed mnemonic est : ' + ' '.join(msm)
        return resMnemo + '\n' + resSeed + '\n' + 'La checksum est : ' + checkSum
    else:  # cas ou on importe une seed
        wordlist = bip39gen.words()  # on génère la wordlist bip 39 en anglais
        temp = []
        for i in seed:
            temp.append(wordlist.index(i))  # on récupère les indexs en int de chaque mot dans la wordlist
        msi = []
        for i in temp:
            bits = bin(i)[2:]  # on convert les indexs en bits
            bits = bits.zfill(11)  # on pad les paquets
            msi.append(bits)
        seedCheckSum = ''.join(msi)  # on concatene tous les paquets en 1 seul string (on a la seed + la checksum
        seedHex = seedCheckSum[:len(seedCheckSum) - 4]  # on récupère uniquement la seed
        seedHex = hex(int(seedHex, 2))[2:]  # on convertit la seed en hexa
        hash = hashlib.sha256(binascii.unhexlify(seedHex)).hexdigest()  # on la hash
        checkSum = bin(int(hash[0], 16))[
                   2:]  # on convertit en binaire le premier chiffre du hash pour avoir la checksum
        checkSum = checkSum.zfill(4)  # on pad la checksum si nécessaire
        test = checkSum == seedCheckSum[-4:]  # verification de la checksum
        return 'La seed en binaire est : '+ ''.join(msi) +'\n' + ' Cette seed est correcte : ' + str(test)
        
        
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
    seed_512 = hashlib.sha512(seed).hexdigest() # On hash la seed
    
    # Séparation en deux des bits du hash
    seed_512_bin = hexToBin(seed_512)
    mprk=seed_512_bin[:int(len(seed_512_bin)/2)] # 256 premiers bits pour la private key
    mcc=seed_512_bin[int(len(seed_512_bin)/2):] # 256 derniers bits pour le chain code
    
    print('\nMaster private key : ', mprk)
    print('Master chain code : ', mcc)

    # index ≥ 2147483648 (or 2^31) for the child to be a hardened key
    index='10000000000000000000000000000000'
    
    #The 00 pads the private key to make it 33 bytes long.
    data = '00'+mprk+index
    
    # HMAC-SHA512 du parent pour trouver le child
    child_resultat = hmac.new(
        bitstring_to_bytes(mcc),
        msg= bitstring_to_bytes(data),
        digestmod=hashlib.sha512
        ).hexdigest()
    
    
    child_resultat = hexToBin(child_resultat)
    # Les 256 premiers bits du result + parent private key = private key du child
    child_resultat_prk = int(child_resultat[:int(len(child_resultat)/2)],2) + int(mprk,2)
    
    # on a : child = [privatekey, chaincode, index]
    child = [
        int_to_bitstring(child_resultat_prk),
        child_resultat[int(len(child_resultat)/2):],
        index
        ]
    
    print('\nChild private key : ', child[0])
    print('Child chain code : ', child[0])
    return child

# Child key derivation à l'index i
def bip32_index(seed, index):
    seed_512 = hashlib.sha512(seed).hexdigest()
    
    seed_512_bin = hexToBin(seed_512)
    mprk=seed_512_bin[:int(len(seed_512_bin)/2)]
    mcc=seed_512_bin[int(len(seed_512_bin)/2):]
    
    print('\nMaster private key : ', mprk)
    print('Master chain code : ', mcc)
    
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

    print('\nChild private key : ', child[0])
    print('Child chain code : ', child[0])
    return child

# Child key derivation à l'index i et à la profondeur m
def bip32_index_depth(seed, index, depth):
    seed_512 = hashlib.sha512(seed).hexdigest()
    
    seed_512_bin = hexToBin(seed_512)
    mprk=seed_512_bin[:int(len(seed_512_bin)/2)]
    mcc=seed_512_bin[int(len(seed_512_bin)/2):]

    print('\nMaster private key : ', mprk)
    print('Master chain code : ', mcc)
    
    # index ≥ 2147483648 (or 2^31) for the child to be a hardened key
    index += 2147483648
    index_temp = index + 1 # On créé un nouvel index qui s'itérera pour les niveaux de dérivation
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
    
    # On itère sur chaque niveau de dérivation, chaque child généré devient le parent du niveau suivant
    for m in range(0, depth):
        if m != depth-1:
            index_temp = int_to_bitstring(int(index_temp,2) + 1)
            #The 00 pads the private key to make it 33 bytes long.
            data = '00'+child[m][0]+index_temp
    
            child_resultat = hmac.new(
                bitstring_to_bytes(child[m][1]),
                msg= bitstring_to_bytes(data),
                digestmod=hashlib.sha512
                ).hexdigest()
            
            child_resultat = hexToBin(child_resultat)
            child_resultat_prk = int(child_resultat[:int(len(child_resultat)/2)],2) + int(child[m][0],2)
            # on a : child[depth] = [privatekey, chaincode, index]
            child.append([
                int_to_bitstring(child_resultat_prk),
                child_resultat[int(len(child_resultat)/2):],
                index_temp
                ])
            
            print('\nNiveau de dérivation ', m+1)
            print('Child private key : ', child[m+1][0])
            print('Child chain code : ', child[m+1][1])
            print('Index : ', int(child[m+1][2], 2))
            
        else:
            data = '00'+child[m][0]+index
    
            child_resultat = hmac.new(
                bitstring_to_bytes(child[m][1]),
                msg= bitstring_to_bytes(data),
                digestmod=hashlib.sha512
                ).hexdigest()
            
            child_resultat = hexToBin(child_resultat)
            child_resultat_prk = int(child_resultat[:int(len(child_resultat)/2)],2) + int(child[m][0],2)
            # on a : child[depth] = [privatekey, chaincode, index]
            child.append([
                int_to_bitstring(child_resultat_prk),
                child_resultat[int(len(child_resultat)/2):],
                index
                ])
            
            print('\nNiveau de dérivation ', m+1)
            print('Child private key : ', child[m+1][0])
            print('Child chain code : ', child[m+1][1])
            print('Index : ', int(child[m+1][2], 2))
    
    return child


#------------------ MAIN -------------------
print('\n \n ----------------- BIP 39 -----------------\n \n')
print("1) Génération d'une seed \n")
print(bip39())
print('\n \n \n')
seed= ''.split(sep=' ')
print("2) Import d'une seed \n"
      "\n On verifie si la seed : 'train idea soldier protect stamp clump plastic disagree stage humor solution icon'  est correcte" )
print(bip39(['train', 'idea', 'soldier', 'protect', 'stamp', 'clump', 'plastic', 'disagree', 'stage', 'humor', 'solution', 'icon']))
print('\n \n')

print('----------------- BIP 32 -----------------\n')
seed = b'01000111100111000010101100111111000111000101001011101010001110101100000011010001101110100011110101010101000010001010111111110100'
print('Dans cette partie on utilise la seed suivante :')
print('479c2b3f1c52ea3ac0d1ba3d5508aff4')

print('\n1) Générer une clé enfant :')
bip32_standard(seed)

print("\n2) Générer une clé enfant à l'index 2 :")
bip32_index(seed, 2)

print("\n3) Générer une clé enfant à l’index 2 au niveau de dérivation 3:")
bip32_index_depth(seed, 2, 3)

print('\n')