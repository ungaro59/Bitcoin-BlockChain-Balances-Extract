Environnement Windows. Segwit compatible.
Developpement sous Harbour core V 3 (une evolution open source de Clipper 5) et base de données xbase (.DBF) :

https://github.com/harbour/core#how-to-get

Telechargez la derniere version du compilateur Harbour ici :
https://sourceforge.net/projects/harbour-project/files/binaries-windows/

A decompresser dans le dossier C:\HB32 par exemple.
-------------------------------------------------------

Ce programme balaye l'intégralité de la blockchain locale (fichiers blkXXXXX.DAT) créée par le client 
Bitcoin-Core (0.15.1) ou ulterieurs. Le chemin des fichiers .dat utilisé par défaut par l'application 
est %APPDATA%\bitcoin\blocks

Pour compiler, creer un dossier "Balance" sous C:\hb32 et decompressez l'integralité du dossier gitHub. Pour compiler le programme, utilisez COMPIL.BAT :  

Compil BALANCE  

à la fin de la compilation, le programme se lance automatiquement et la récupération des blocs de la blockchain démarre.

Utilisation : 

Balance [Montant en Satoshis]

Exemple :  Balance 5000000000

Extrait dans un fichier SOLDES.CSV l'ensemble des adresses bitcoins avec un avoir >=50 BTC

L'application crée 4 fichiers DBF :

BLOCKS.DBF : Contient la liste de tous les blocks de la blockchain.
INPUTS.DBF : Contient toutes les transactions inputs (sent)
OUTPUTS.DBF : Contient toutes les transactions outputs (received)
Adresses_non_nulles.DBF : Contient la liste des adresses bitcoin avec un avoir positif ainsi que des informations 
sur les dates de premieres entrées/sorties et la date de derniere entrée/sortie.

Et un fichier CSV contenant l'ensemble des adresses avec un avoir determiné par le parametre de lancement :
-> Soldes.CSV extraction des adresses btc non nulles avec date de derniere modification

Exemple :
1111111111111111111114oLvT2;7110007;20110512074620
11111111111111111111BZbvjr;1000000;20110427015755
111SZ5LN4WeKd89CSt3i2fngnDzFL3nRw;1000000;20110604091137
111g3qjk7YzhdkKuMmTBzUB8gQ55YZ6MG;5000000000;20100713095544

!! Attention !!, l'extraction depuis le bloc 0 est TRES longues (plusieurs jours? 8-10j voir plus). 
Il faut au moins 500go d'espace sur le disque dur.
Pour le traitement, l'utilisaton d'un disque dur SSD >=500Go-1To Go est fortement recommandée 
pour limiter le temps d'extraction depuis le bloc 0 (aujourd'hui environ 500,000 blocs).

Il est possible de stopper le traitement par ECHAP jusqu'à un N° de bloc determiné. 
Bien ententu, les soldes des adresses s'arrêteront à la date du dernier bloc analysé.
=> Lorsque l'application sera relancée, l'extraction reprendra automatiquement à partir du dernier bloc analysé.
La phase 2 peut-être aussi longue que la phase 1 sans SSD, une durée de traitement approximative est calculée. 


