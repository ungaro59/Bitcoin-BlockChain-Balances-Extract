Environnement Windows. Segwit compatible.
Developpement sous Harbour core V 3 (une evolution open source de Clipper 5) et base de données Dbase :

https://github.com/harbour/core#how-to-get
https://sourceforge.net/projects/harbour-project/files/binaries-windows/

Balaye l'intégralité de la blockchain locale (fichiers blkXXXXX.DAT) créée par le client Bitcoin-Core (0.15.1).
Le chemin des fichiers .dat utilisé par défaut par l'application est %APPDATA%\bitcoin\blocks

Utilisation : 

Balance [Montant en Satoshis]

Exemple :  Balance 5000000000

Extrait dans un fichier SOLDES.CSV l'ensemble des adresses bitcoins avec un avoir >=50 BTC

L'application crée 4 fichiers DBF :

BLOCKS.DBF : Contient la liste de tous les blocks de la blockchain.
INPUTS.DBF : Contient toutes les transactions inputs (sent)
OUTPUTS.DBF : Contient toutes les transactions outputs (received)
Adresses_non_nulles.DBF : Contient la liste des adresses bitcoin avec un avoir positif

Et un fichier CSV contenant l'ensemble des adresses avec un avoir determiné par le parametre de lancement :
-> Soldes.CSV extraction des adresses btc non nulles avec date de derniere modification

Exemple :
1111111111111111111114oLvT2;7110007;20110512074620
11111111111111111111BZbvjr;1000000;20110427015755
111SZ5LN4WeKd89CSt3i2fngnDzFL3nRw;1000000;20110604091137
111g3qjk7YzhdkKuMmTBzUB8gQ55YZ6MG;5000000000;20100713095544

!! Attention !!, l'extraction depuis le bloc 0 est TRES longues (plusieurs jours? 8-10j). 
Il faut au moins 500go d'espace sur le disque dur.
Pour le traitement, l'utilisaton d'un disque dur SSD >=500Go-1To Go est fortement recommandée 
pour limiter le temps d'extraction depuis le bloc 0 (aujourd'hui environ 500,000 blocs).

Il est possible de stopper le traitement par ECHAP jusqu'à un N° de bloc determiné. 
Bien ententu, les soldes des adresses s'arrêteront à la date du dernier bloc analysé.
=> Lorsque l'application sera relancée, l'extraction reprendra automatiquement à partir du dernier bloc analysé.
La phase 2 peut-être aussi longue que la phase 1 sans SSD, une durée de traitement approximative est calculée. 


