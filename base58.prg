#require "hbssl"
#include "fileio.ch"
#include "DbInfo.ch"

PROCEDURE Main()

SSL_init()
OpenSSL_add_all_algorithms()  //adds all algorithms SSL to the table (digests and ciphers). 

?base58_encode("0000ebb22c6afe1fd46bf1ca17cae2a9496df9ac",6)
?base58_encode("537459442be4f0ab9b09039c1b66811af5e8c581",9)
?base58_encode("bef1ac0aeb9489fb53dd493cc5a19f22d653271e",9)
?base58_encode("0000000000000000000000000000000000000000",6)
?base58_encode("724f1a1962df88567590d40795111dda6a2cb3e5",6)
?base58_encode("0496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858ee",5)
?base58_encode("0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6",5)
?

t1 := hb_DateTime()
for i=1 to 10000
//11126yHiXjavR3oNVwV2GRNso2ah4MnZtm
base58_encode("0000ebb22c6afe1fd46bf1ca17cae2a9496df9ac",6)

//39AkCuaDdaVFprYJbsv39E5oSRAcpuHNjb
base58_encode("537459442be4f0ab9b09039c1b66811af5e8c581",9)

//3K6dpfCMRUQZv2djQwbFdRerG1hW5u41N
base58_encode("bef1ac0aeb9489fb53dd493cc5a19f22d653271e",9)

//1111111111111111111114oLvT2
base58_encode("0000000000000000000000000000000000000000",6)

//1BRQnyB2UE3DNB98m31MyLLqZNkyA8V63j 
base58_encode("724f1a1962df88567590d40795111dda6a2cb3e5",6)

//12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX 
base58_encode("0496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858ee",5)

//16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM
base58_encode("0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6",5)

next



t2 := hb_NToSec(hb_DateTime() - t1)
?"Duree pour 70000 conversions :"
??t2
??"s"
?


// ---------------------------------------------
// Retourne l'adresse Btc correspondante au hash
// ---------------------------------------------
   FUNCTION Base58_encode( chaine1, type_conv )

   LOCAL ctx
   LOCAL digest

   LOCAL i
   LOCAL zeros
   LOCAL sEncoded, nOutputStart, ALPHABET, nInputStart
   LOCAL chaine2, Chaine3, Chaine4, First4bytes, resultat

   DO CASE
   CASE type_conv = 0 // Public key Hexa 65 octets
      chaine2 = chaine1
   CASE type_conv = 1 // Public key hexa sur 20 octets Hash160
      chaine2 = chaine1
   CASE type_conv = 2 // Public key non decodable
      RETURN "Unable to decode public address"
   CASE type_conv = 3 // Public key sous sa version compresée de 33 octets (Traitement identique au format 65 octets)
      chaine2 = chaine1
   CASE type_conv = 4 // Public Key sur 20 octets sous sa version OP_HASH160 : hashed first with SHA-256 and then with RIPEMD-160.
      chaine2 = chaine1
   CASE type_conv >= 5 // Public key en ascii 5,6,8,9
      // Chaine1="0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6"
      Chaine2 = ""
      FOR i = 1 TO Len( chaine1 ) / 2
         chaine2 += Chr( hb_HexToNum( SubStr( chaine1, ( i -1 ) * 2 + 1, 2 ) ) )
      NEXT
      type_conv = type_conv - 5
   ENDCASE

   ctx := EVP_MD_CTX_create()
   EVP_MD_CTX_init( ctx )

   IF type_conv = 0 .OR. type_conv = 3      // Public key 65 ou 33 octets
      EVP_DigestInit_ex( ctx, "SHA256" )
      EVP_DigestUpdate( ctx, chaine2 )
      resultat := ""
      EVP_DigestFinal( ctx, @resultat )
      // ? "2) SHA256", ">" + hb_StrToHex( digest ) + "<"

      // EVP_MD_CTX_reset( ctx )
      EVP_DigestInit_ex( ctx, HB_EVP_MD_RIPEMD160 )
      EVP_DigestUpdate( ctx, resultat )
      resultat := ""
      EVP_DigestFinal( ctx, @resultat )
      // ? "3) RIPEMD160", ">" + hb_StrToHex( digest ) + "<"
   ELSE
      resultat = chaine2
   ENDIF

   IF type_conv <> 4
      Chaine3 = Chr( 0 ) + resultat // Add version byte in front of RIPEMD-160 hash (0x00 for Main Network). Toutes les adresse BTC qui commencent par 1
   ELSE
      Chaine3 = Chr( 5 ) + resultat // Add version byte in front of RIPEMD-160 hash.  Toutes les adresse BTC qui commencent par 3
   ENDIF

   EVP_DigestInit_ex( ctx, "SHA256" )
   EVP_DigestUpdate( ctx, chaine3 )
   resultat := ""
   EVP_DigestFinal( ctx, @resultat )
   // ? "5) SHA256", ">" + hb_StrToHex( digest ) + "<"

   EVP_DigestInit_ex( ctx, "SHA256" )
   EVP_DigestUpdate( ctx, resultat )
   resultat := ""
   EVP_DigestFinal( ctx, @resultat )
   // ? "6) SHA256", ">" + hb_StrToHex( digest ) + "<"
   First4bytes = Left( resultat, 4 )

   Chaine4 = Chaine3 + First4bytes
   // ? "8) >" + hb_StrToHex( Chaine4 ) + "<"
   // Chaine5="A"+chr(0)+"B"
   // ?len(chaine5)

   sEncoded = CONVERSION_TO_BASE58( Chaine4 )

   RETURN sEncoded

#PRAGMA BEGINDUMP
#include "hbapi.h"
//#include <windows.h>

HB_FUNC(CONVERSION_TO_BASE58)
{
static const char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

unsigned char b58[35];
int carry;
int i, j, high, zcount = 0;
int size;

const unsigned char *bin = hb_parc(1);    //Chaine à convertir
int binsz = hb_parclen( 1 ) ;  //Taille de la chaine

while (zcount < binsz && !bin[zcount])
   ++zcount;

size = (binsz - zcount) * 138 / 100 + 1;
unsigned char buf[size];
memset(buf, 0, size);

for (i = zcount, high = size - 1; i < binsz; ++i, high = j)
  {
  for (carry = bin[i], j = size - 1; (j > high) || carry; --j)
      {
      carry += 256 * buf[j];
      buf[j] = carry % 58;
      carry /= 58;
      }
  }

for (j = 0; j < size && !buf[j]; ++j);

if (zcount) memset(b58, '1', zcount);

for (i = zcount; j < size; ++i, ++j)
 b58[i] = b58digits_ordered[buf[j]];

b58[i] = '\0';

hb_retc((char *) b58);
}

#pragma ENDDUMP
