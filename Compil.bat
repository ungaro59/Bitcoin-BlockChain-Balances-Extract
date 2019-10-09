set path = \hb32\comp\mingw\bin 
\hb32\bin\hbmk2 -w1 -mt %1 hbct.hbc
if errorlevel 1 goto FIN
%1 %2
:FIN
