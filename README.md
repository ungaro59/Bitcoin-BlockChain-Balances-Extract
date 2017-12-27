# Bitcoin-BlockChain-Balance-Parser
Extract Balances from all bitcoin address. Use .DAT of bitcoin-core client

Environnement Windows.
Developpement sous Harbour core V 3 (une evolution open source de Clipper 5) et base de données Dbase :

https://github.com/harbour/core#how-to-get

https://sourceforge.net/projects/harbour-project/files/binaries-windows/

set path = \hb32\comp\mingw\bin 
\hb32\bin\hbmk2 hbct.hbc -w1 balance
if errorlevel 1 goto FIN
Balance %1
:fIN



