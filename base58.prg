#require "hbssl"
#include "fileio.ch"
#include "DbInfo.ch"

PROCEDURE Main()

Local t1,t2

SSL_init()
OpenSSL_add_all_algorithms()  //adds all algorithms SSL to the table (digests and ciphers). 

//11126yHiXjavR3oNVwV2GRNso2ah4MnZtm
?base58_encode("0000ebb22c6afe1fd46bf1ca17cae2a9496df9ac",5,1)
?base58_encode_origine("0000ebb22c6afe1fd46bf1ca17cae2a9496df9ac",5,1)

t1 := hb_DateTime()
//for i=1 to 10000
//39AkCuaDdaVFprYJbsv39E5oSRAcpuHNjb
?base58_encode("537459442be4f0ab9b09039c1b66811af5e8c581",5,4)
?base58_encode_origine("537459442be4f0ab9b09039c1b66811af5e8c581",5,4)

//3K6dpfCMRUQZv2djQwbFdRerG1hW5u41N
?base58_encode("bef1ac0aeb9489fb53dd493cc5a19f22d653271e",5,4)
?base58_encode_origine("bef1ac0aeb9489fb53dd493cc5a19f22d653271e",5,4)

//1111111111111111111114oLvT2
?base58_encode("0000000000000000000000000000000000000000",5,1)
?base58_encode_origine("0000000000000000000000000000000000000000",5,1)

//1BRQnyB2UE3DNB98m31MyLLqZNkyA8V63j 
?base58_encode("724f1a1962df88567590d40795111dda6a2cb3e5",5,1)
?base58_encode_origine("724f1a1962df88567590d40795111dda6a2cb3e5",5,1)

//12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX
?base58_encode("0496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858ee",5,0)
?base58_encode_origine("0496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858ee",5,0)


//16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM
?base58_encode("0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6",5,0)
?base58_encode_origine("0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6",5,0)

//next
t2 := hb_NToSec(hb_DateTime() - t1)
?"Duree :"
?t2
?

//Retourne l'adresse Btc correspondante au hash
//---------------------------------------------
Function Base58_encode(chaine1,type_conv,Conv2)
   LOCAL ctx
   LOCAL digest

   LOCAL i,j, zeros, ALPHABET
   Local chaine2, Chaine3,Chaine4, First4bytes, resultat
   Local sZero, binsz, nsize, buf, buf58, high,Carry, zcount,reste
   
   DO CASE
      CASE type_conv=0 //Public key Hexa 65 octets
	       chaine2=chaine1
	  CASE type_conv=1 //Public key hexa sur 20 octets Hash160
	       chaine2=chaine1
	  CASE type_conv=2 //Public key non decodable
	       return "Unable to decode public address"
	  case type_conv=3 //Public key sous sa version compresée de 33 octets (Traitement identique au format 65 octets)
	       chaine2=chaine1
	  case type_conv=4 //Public Key sur 20 octets sous sa version OP_HASH160 : hashed first with SHA-256 and then with RIPEMD-160. 
	       chaine2=chaine1
	  case type_conv=5 //Public key en ascii
	       Chaine2=""
           for i=1 to len(chaine1)/2
	          chaine2+=chr(HB_HexToNum(substr(chaine1,(i-1)*2+1,2)))
           next
		   type_conv=Conv2
   ENDCASE


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
   //? "8) >" + hb_StrToHex( Chaine4 ) + "<"
   //?
   
   ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
   // Count leading zeros. 
   zcount=1
   DO WHILE zcount < len(Chaine4) .and. substr(Chaine4,zcount,1) = Chr(0)
     zcount++
   ENDDO
   
   //sZero = "1"
   binsz = len(chaine4)

   //?"binsz="+str(binsz)
   //?"zcount="+str(zcount)
   nsize = int((binsz-zcount)*138/100 + 3)
   //?"nsize="+str(nsize)
   buf = replicate(chr(0),nsize) 

   high = nsize
   FOR i = zcount TO binsz
 	  
	  j = nsize
	  Carry = Asc(substr(Chaine4,i,1))
      //?"**** i="+str(i)      	 
	  //?"Carry="+str(Carry)
	  Do while j>0
	    //?"J="+str(j)
		Carry = Carry + 256*Asc(substr(buf,j,1))
		//?"Carry="+str(Carry)
		
		buf = stuff(buf,j,1,chr(mod(Carry,58)))
		//?"buf[j]=0x"+hb_StrToHex(substr(buf,j,1))
		//?hb_StrToHex(buf)
		reste=Carry
		Carry = int(Carry / 58)
		//?"Carry="+str(Carry)
		//wait "stop"
		j--
	        if Carry = 0 .and. j<high
		    exit
		endif
	  Enddo
	
	  high = j
   NEXT
  
   buf58=""  
   IF type_conv<>4  //P2SH address non concernées.
      zcount--
      if zcount>0
         for i=1 to zcount
            buf58+="1"
	 next
      endif
   endif

   zcount=1
   Do while Asc(substr(buf,zcount,1))=0
      zcount++	
   Enddo     
   for j=zcount to nsize
     buf58+=substr(ALPHABET,Asc(substr(buf,j,1))+1,1)
   next
	
RETURN buf58



//Retourne l'adresse Btc correspondante au hash
//---------------------------------------------
Function Base58_encode_origine(chaine1,type_conv,Conv2)
   LOCAL ctx
   LOCAL digest

   LOCAL i
   LOCAL zeros 
   LOCAL sEncoded, nOutputStart, ALPHABET, nInputStart 
   Local chaine2, Chaine3,Chaine4, First4bytes, resultat
   
   DO CASE
      CASE type_conv=0 //Public key Hexa 65 octets
	       chaine2=chaine1
	  CASE type_conv=1 //Public key hexa sur 20 octets Hash160
	       chaine2=chaine1
	  CASE type_conv=2 //Public key non decodable
	       return "Unable to decode public address"
	  case type_conv=3 //Public key sous sa version compresée de 33 octets (Traitement identique au format 65 octets)
	       chaine2=chaine1
	  case type_conv=4 //Public Key sur 20 octets sous sa version OP_HASH160 : hashed first with SHA-256 and then with RIPEMD-160. 
	       chaine2=chaine1
	  case type_conv=5 //Public key en ascii 65 octets
	       //Chaine1="0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6"
	       Chaine2=""
           for i=1 to len(chaine1)/2
	          chaine2+=chr(HB_HexToNum(substr(chaine1,(i-1)*2+1,2)))
           next
		   type_conv=Conv2
   ENDCASE



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
   //? "8) >" + hb_StrToHex( Chaine4 ) + "<"
   //Chaine5="A"+chr(0)+"B"
   //?len(chaine5)
   
   // Count leading zeros. 
   zeros=1
   DO WHILE zeros < len(Chaine4) .and. substr(Chaine4,zeros,1) = Chr(0)
     zeros++
   ENDDO
   

   // Convert base-256 digits to base-58 digits (plus conversion to ASCII characters) 
   sEncoded = "                                        "
   nOutputStart=37
   ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
   nInputStart = zeros 
   
   DO WHILE nInputStart <= len(chaine4)
    sEncoded=Stuff(sEncoded, nOutputStart, 1, substr(ALPHABET,divmod(@chaine4, nInputStart)+1,1))
   	nOutputStart--
	IF substr(chaine4,nInputStart,1) = chr(0)
		nInputStart++ // optimization - skip leading zeros 
	endif
   ENDDO

   IF type_conv<>4  //P2SH address non concernées.
      IF (zeros-1) >=1 
	    zeros--
		DO WHILE zeros >= 1
		    sEncoded=stuff(sEncoded,nOutputStart,1,substr(ALPHABET,1,1))
			nOutputStart--
			zeros--
		ENDDO
  	  ENDIF
    ENDIF

//? alltrim(sEncoded)
//   EVP_cleanup()  //Nettoire les tables ssl utilisées

RETURN alltrim(sEncoded)
   
function divmod(number, firstDigit)

// this is just long division which accounts for the base of the input digits 
LOCAL nRemainder,nDigit,nByte,nTemp,i

nRemainder = 0
FOR i = firstDigit TO len(number)
	nDigit = asc(substr(number,i,1))
	nTemp = nRemainder * 256 + nDigit
	nByte=int(nTemp / 58)
    number := stuff(number,i,1,chr(nByte))
	nRemainder = mod(nTemp, 58)
NEXT

RETURN nRemainder
