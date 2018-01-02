#require "hbssl"
#include "fileio.ch"
#include "DbInfo.ch"

PROCEDURE Main()

SSL_init()
OpenSSL_add_all_algorithms()  //adds all algorithms SSL to the table (digests and ciphers). 

?base58_encode("0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6",5)
?
?

//Retourne l'adresse Btc correspondante au hash
//---------------------------------------------
Function Base58_encode(chaine1,type_conv)
   LOCAL ctx
   LOCAL digest

   LOCAL i,j, zeros, ALPHABET
   Local chaine2, Chaine3,Chaine4, First4bytes, resultat
   Local sZero, binsz, nsize, buf, buf58, high
   
   DO CASE
      CASE type_conv=0
	       chaine2=chaine1
	  CASE type_conv=1
	       chaine2=chaine1
	  CASE type_conv=2
	       return "Unable to decode public address"
	  case type_conv=3
	       chaine2=chaine1
	  case type_conv=4
	       chaine2=chaine1
	  case type_conv=5
	       Chaine2=""
           for i=1 to len(chaine1)/2
	          chaine2+=chr(HB_HexToNum(substr(chaine1,(i-1)*2+1,2)))
           next
		   type_conv=0
   ENDCASE


//   SSL_init()
//   OpenSSL_add_all_digests()
//   OpenSSL_add_all_ciphers()
//Chaine1="0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6"

   ctx := EVP_MD_CTX_create()
   EVP_MD_CTX_init( ctx )
   
   IF type_conv=0 .or. type_conv=3      //Public key 65 ou 33 octets
      EVP_DigestInit_ex( ctx, "SHA256" )
      EVP_DigestUpdate( ctx, chaine2 )
      resultat := ""
      EVP_DigestFinal( ctx, @resultat )
      //? "2) SHA256", ">" + hb_StrToHex( digest ) + "<"

      //EVP_MD_CTX_reset( ctx )
      EVP_DigestInit_ex( ctx, HB_EVP_MD_RIPEMD160 )
      EVP_DigestUpdate( ctx, resultat)
      resultat := ""
      EVP_DigestFinal( ctx, @resultat )
      //? "3) RIPEMD160", ">" + hb_StrToHex( digest ) + "<"
    else
	   resultat=chaine2
   ENDIF
   
   if type_conv<>4 
      Chaine3=chr(0)+resultat //Add version byte in front of RIPEMD-160 hash (0x00 for Main Network). Toutes les adresse BTC qui commencent par 1
	else
	  Chaine3=chr(5)+resultat //Add version byte in front of RIPEMD-160 hash.  Toutes les adresse BTC qui commencent par 3
   endif
   
   EVP_DigestInit_ex( ctx, "SHA256" )
   EVP_DigestUpdate( ctx, chaine3 )
   resultat := ""
   EVP_DigestFinal( ctx, @resultat )
   //? "5) SHA256", ">" + hb_StrToHex( digest ) + "<"
   
   EVP_DigestInit_ex( ctx, "SHA256" )
   EVP_DigestUpdate( ctx, resultat)
   resultat := ""
   EVP_DigestFinal( ctx, @resultat )
   //? "6) SHA256", ">" + hb_StrToHex( digest ) + "<"
   First4bytes=left(resultat,4)
   
   Chaine4=Chaine3+First4bytes
   ? "8) >" + hb_StrToHex( Chaine4 ) + "<"
   ?
   
   ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
   // Count leading zeros. 
   zcount=1
   DO WHILE zcount < len(Chaine4) .and. substr(Chaine4,zcount,1) = Chr(0)
     zcount++
   ENDDO
   
   //sZero = "1"
   binsz = len(chaine4)

   nsize = (binsz-zcount)*138/100 + 2
   buf = replicate(chr(0),nsize) 

   high = nsize - 1
   FOR i = zcount TO binsz
 	  j = nsize - 1
	  Carry = Asc(substr(Chaine4,i,1))
	  //?"J="+str(j)
	  //?"Carry="+str(Carry)
	  Do while .T.   
		Carry = Carry + 256*Asc(substr(buf,j,1))
		//?"Carry="+str(Carry)
		buf = stuff(buf,j,1,chr(mod(Carry,58)))
		//?"buf="+buf
		Carry = int(Carry / 58)
		j--
		if (j > high .or. Carry <> 0)
	     else
		    exit
		endif
	  Enddo
	
	  high = j
   NEXT
   
   buf58=""
   IF type_conv<>4  //P2SH address non concernées.
      zcount--
      IF zcount >0
  	     FOR i = 1 TO zcount
		     buf58 += "1"
   	     NEXT
      ENDIF
   ENDIF
   
   FOR j=1 TO (nsize-1)
  	   buf58+= substr(ALPHABET,Asc(substr(buf,j,1))+1,1)
   Next

RETURN buf58
   
