Environnement Windows. Segwit compatible.
Developpement sous Harbour core V 3 (une evolution open source de Clipper 5) et base de données xbase (.DBF) :

https://github.com/harbour/core#how-to-get

Pré-requis :

1) Telechargez la derniere version du compilateur Harbour ici (harbour-nightly-win.exe) :
https://sourceforge.net/projects/harbour-project/files/binaries-windows/nightly/

A installer dans un dossier racine \HB32 (C:\hb32 par exemple)
-------------------------------------------------------------

2) Installez l'application Bitcoin-Core (https://bitcoin.org/fr/telecharger) et synchronisez integralement la blockchain.

Que fait ce logigiel :

Ce logiciel balaye l'intégralité de la blockchain locale (fichiers blkXXXXX.DAT) créée par le client 
Bitcoin-Core. Le chemin des fichiers .dat utilisé par défaut par l'application est %APPDATA%\bitcoin\blocks

Pour utiliser le programme, creer un dossier "Balance" sous C:\hb32 et decompressez l'integralité du dossier gitHub. 
Compiler le, pour cela, utilisez COMPIL.BAT ou utilisez directement le fichier compilé Balance.EXE :  

Compil BALANCE  

à la fin de la compilation, le programme se lance automatiquement, les fichiers .DBF/.NTX nécessaires sont créés et la 
récupération des blocs de la blockchain démarre. Attention la synchro du client Bitcoin-core doit être complete, sinon
la récupération ne pourra s'effectuer correctement.

Utilisation : 

Balance [Montant en Satoshis]

Exemple :  Balance 5000000000

Extrait dans un fichier SOLDES.CSV l'ensemble des adresses bitcoins avec un avoir >=50 BTC
Il y a actuellement environ 27 millions d'adresses bitcoins avec un solde positif et environ 370 000 000 en tout.

L'application crée un fichier DBF :

Adresses_non_nulles.DBF : Contient la liste des adresses bitcoin avec un avoir >0 ainsi que des informations 
sur les dates de premieres entrées/sorties, le nbre de transactions I/O, et la date de derniere entrée/sortie.

Un fichier CSV contenant l'ensemble des adresses avec un avoir determiné par le parametre de lancement :
-> Soldes.CSV extraction des adresses btc non nulles avec date de derniere modification

Exemple :
1111111111111111111114oLvT2;7110007;20110512074620
11111111111111111111BZbvjr;1000000;20110427015755
111SZ5LN4WeKd89CSt3i2fngnDzFL3nRw;1000000;20110604091137
111g3qjk7YzhdkKuMmTBzUB8gQ55YZ6MG;5000000000;20100713095544

!! Attention !!, l'extraction depuis le bloc 0 est longue (plusieurs jours?. 
Il faut au moins 128go d'espace sur le disque dur.
Pour le traitement, l'utilisaton d'un disque dur SSD >=128Go est très fortement recommandée 
pour limiter le temps d'extraction depuis le bloc 0 (aujourd'hui plus de 500,000 blocs).

Dans l'étape 1, il est possible de stopper le traitement par ECHAP jusqu'à un N° de bloc determiné. 
Attention, Il faut laisser se terminer les phases 2 et 3 jusqu'au bout..
Bien ententu, les soldes des adresses s'arrêteront à la date du dernier bloc analysé.
=> Lorsque l'application sera relancée, l'extraction reprendra automatiquement à partir du dernier bloc analysé.

