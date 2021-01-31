# TD2 programmation blockchain
## BIP 39 (1ère partie)
Nous avons codé cette partie en 1 seule fonction cependant cette fonction distingue 2 cas :  
- génération d'une seed
- vérification d'une seed mnemonic que l'on importe
Pour générer une seed il suffit juste d'appeler la fonction sans rien passer en paramètre et pour vérifier une seed mnemonic il faut passer la seed en paramètre sous forme d'un tableau de string. 
### Cheminement global de la fonction

#### Génèration d'une seed
* On génère un entier aléatoire sur 128 bits (seed)
* On transforme l'entier en binaire
* On hash la seed à l'aide de l'argorithme sha256
* On récupère les 4 premiers bits de ce hash (checksum)
* On concatène les 2 on a donc 132 bits
* On sépare ces 132 bits en paquets de 11 bits
* On convertit chaque paquet en entier (index de la wordlist bip39)
* On récupère le mot correspondant

#### Importation d'une seed mnemonic
* On récupère l'index de chaque mot dans la wordlist bip39
* On transforme chaque entier en binaire
* On récupère les 128 premiers bits (seed)
* On hash la seed et on récupère les 4 premiers bits de ce hash
* On vérifie l'égalité entre les 4 derniers bits extraits depuis la seed mnemonic avec les 4 bits que l'on vient de calculer


## BIP 32 (2ème partie)

Nous avons décomposé cette partie en 3 fonctions c.à.d 3 manières différentes de générer des childs keys. 
* `bip32_standard` est la standard, elle prend en entrée la seed et génère d'abord les master private key `mprk` et chain code `mcc` en faisant un hash SHA-512 de la seed. Ensuite, on définit un index égal à 2^31, ce qui correspond à un index valable pour une clé renforcée (il doit être ≥ 2^31). Pour dériver l'enfant renforcé à partir du parent, on réalise un HMAC-SHA512 dont la clé est le `mcc` et le message une concaténation de cette forme : `00 || mprk || index`. Les 256 premiers bits du hash resultant sont additionés à la private key du parent pour former la private key du child. Le 256 derniers bits forment le chain code de l'enfant. La fonction retourne un tableau avec les résultats de l'enfant généré sous cette forme : `child = [privatekey, chaincode, index]`.
  
* `bip32_index` prend en entrée la seed et l'index voulu pour l'enfant sous forme d'entier int. Par souci de simplicité, on transforme nous même l'index en un index valable pour une clé renforcée en ajoutant systématiquement 2^31 au nombre entré. Le reste de la dérivation a le même fonctionnement que pour le `bip32_standard`, l'index a seulement été prédéfini. La fonction retourne un tableau avec les résultats de l'enfant généré sous cette forme : `child = [privatekey, chaincode, index]`.

* `bip32_index_depth` prend en entrée la seed, l'index et le niveau de dérivation voulu pour l'enfant sous forme d'entier int. Le reste de la dérivation a le même fonctionnement que pour le `bip32_standard`, seulement cette fois on réalise cette derivation autant de fois que de profondeur défini. A chaque niveau, le parent est le child du niveau précedent (ou la master key au niveau 0). De plus, on utilise un index qui s'itère sur lui même pour chaque niveau. Lorsque l'on atteint le niveau désiré en entrée, on applique l'index également choisi en entrée. La fonction retourne un tableau avec les résultats des enfants générés sous cette forme : `child[depth] = [privatekey, chaincode, index]`.


## Librairies utilisées :
* Secrets : pour générer l'entier aléatoire sur 128 bits
* bip39gen : pour générer automatiquement la wordlist dans un tableau de string
* hashlib : pour les différents hash
* hmac : pour les dérivations de clés
* binascii : pour des conversions
