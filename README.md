# Bitcoin-BlockChain-Balance-Parser
Extract Balances from all bitcoin address. Use .DAT of bitcoin-core client

Environnement Windows. Segwit compatible.
Developpement sous Harbour core V 3 (une evolution open source de Clipper 5) et base de données Dbase :

https://github.com/harbour/core#how-to-get

https://sourceforge.net/projects/harbour-project/files/binaries-windows/

Balaye l'intégralité de la blockchain locale (fichiers blkXXXXX.DAT) créée par le client Bitcoin-Core (0.15.1).
Le chemin des fichiers .dat utilisé par défaut par l'application est %APPDATA%\bitcoin\blocks
L'application crée 4 fichiers :

BLOCKS.DBF : Contient la liste de tous les blocks extraits.

INPUTS.DBF : Contient toutes les transactions inputs (sent)

OUTPUTS.DBF : Contient toutes les transactions outputs (received)

Adreses_non_nulles.DBF : Contient la liste des adresses bitcoin avec un avoir positif


-> Soldes.CSV extraction des adresses btc non nulles avec date de derniere modification


!! Attention !!, l'extraction depuis le bloc 0 est TRES longues (plusieurs jours). 
Pour le traitement, l'utilisaton d'un disque dur SSD (250-500 Go) est quasi-obligatoire 
pour limiter le temps d'extraction depuis le bloc 0 (aujourd'hui environ 500,000 blocs).





