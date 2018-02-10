/* Bitcoin Balances Extracter - Segwit compatible - Copyright 2017-2018 ungaro */
// Quelques infos de démarrage pour le décryptage de la blockchain : 
// http://codesuppository.blogspot.fi/2014/01/how-to-parse-bitcoin-blockchain.html
// https://github.com/libbitcoin/libbitcoin-explorer/wiki/Payment-Address-Deconstruction
// https://bitcoin.stackexchange.com/questions/19081/parsing-bitcoin-input-and-output-addresses-from-scripts/19108#19108
// https://bitcoin.stackexchange.com/questions/5021/how-do-you-get-the-op-hash160-value-from-a-bitcoin-address

#require "hbssl"
#include "fileio.ch"
#include "DbInfo.ch"

REQUEST SIXCDX // Pour des index NTX de plus de 4go (Jusqu'à 4To)

PROCEDURE Main()

   LOCAL Dossier_de_base, format_public_key, Nb_transac, Montants_a_partir_de, RPourcent_actu, Rpourcent
   LOCAL sMontant,exit_user := .F., SAI_NumBlock
   LOCAL SAI_Nom_Fichier, SAI_A_partir_du_block, SAI_dernier_block, nom_fichier, taille_fichier, SAI_Time_Stamp
   LOCAL bFlag_trouve_new_bloc, position_depart_block, numero_fichier, chemin_fichier, NSCRIPT_LENGTH
   LOCAL nCanal, position_block, gnBloc_actuel, NB_TRANS, TX_HASH_CLAIR, NTRANSACTION_INDEX
   LOCAL bufContenu_block, Hash_Block, nU_fichier, numenr, nb_transactions, ID_TRANSACTION_EN_COURS
   LOCAL MAGIC_CODE := Chr( 0xF9 ) + Chr( 0xBE ) + Chr( 0xB4 ) + Chr( 0xD9 )
   LOCAL nBdiff, pdiff, rDifficulty, Hash_previous_Block, gnNnum_block, numero_dernier_block
   LOCAL gnBloc_depart, nUmero_fichier_actu, nPtr, nMax_Block, pos_depart_block, nPointeur_fichier, NB_transac_segwit, Rpourcent_segwit
   LOCAL nPtrDebut_transaction, nadresse_debut_transaction
   LOCAL bFlagSegwit, nB_input_transactions, nTemp, nu_trans, i, bufScript_table, Flag_New_mined_Block
   LOCAL aStructBlocks, aStructTransactions
   LOCAL Transaction_Hash, nb_outputs_transactions, nB_output, nMontant_transaction
   LOCAL Public_key_65, Public_key_20, Public_key_33, position_debut_output_transaction, Table_transactions
   LOCAL nb_witness_fields, Taille_witness_fields, NPTRDEBUT_WITNESS, nb_witness, NPTRFIN_TRANSACTION
   LOCAL sCore_data, sfTransaction_buffer, numero_output, nb_bloc_traites
   LOCAL adresse_bitcoin, aStructAdr_non_nul, aStructINPUTS, aStructOUTPUTS
   LOCAL position_debut_input_transaction, dernier_bloc_traite
   LOCAL GnMoyenne, pThID, lOk, SAI_duree, flag_phase2
   LOCAL nbre_etapes, ligne_depart, aStructADRIMPACTEES, input_output, numero_transaction, TimeStamp
   LOCAL Transac_depart, Transac_actuelle, aStructID_TRANS, Montant_retire, Montant, Max_transaction, Table_adresses, Flag_ajoute_transaction

#define FP_DEBUT    0   // From beginning-of-file
#define FP_COURANT  1   // From the current pointer position
#define FP_FIN      2   // From end-of-file
#define HA_SHA_256  0   // Sha 256
#define TAILLE_DU_BLOC (asc(substr(bufContenu_Block,5,1))+asc(substr(bufContenu_Block,6,1))*256+asc(substr(bufContenu_Block,7,1))*65536+asc(substr(bufContenu_Block,8,1))*16777216)
#define VRAI .T.
#define FAUX .F.
#define HEXA_65  0
#define HEXA_20  1
#define HEXA_ERR 2
#define HEXA_33  3
#define HEXA_20_HASH160 4
#define DB_DBFLOCK_XHB64 5

/*
local nI, aStruct := { { "CHARACTER", "C", 25, 0 }, ;
                       { "NUMERIC",   "N",  8, 0 }, ;
                       { "DOUBLE",    "N",  8, 2 }, ;
                       { "DATE",      "D",  8, 0 }, ;
                       { "LOGICAL",   "L",  1, 0 }, ;
                       { "MEMO1",     "M", 10, 0 }, ;
                       { "MEMO2",     "M", 10, 0 } }
*/

   // REQUEST DBFCDX

   table_transactions := {}

   // Description des fichiers
   aStructBlocks := { { "num_bloc", "N", 10, 0 }, ;
      { "TimeStamp", "C", 14, 0 }, ;
      { "Fichier", "C", 12, 0 }, ;
      { "pos_bloc", "N", 9, 0 }, ;
      { "hash_bloc", "C", 64, 0 }, ;
      { "hashPbloc", "C", 64, 0 }, ;
      { "MerkleRoot", "C", 64, 0 }, ;
      { "Nb_transac", "N", 6, 0 }, ;
      { "TailleBloc", "N", 7, 0 }, ;
      { "Difficulte", "N", 16, 2 }, ;
      { "Nonce", "N", 11, 0 }, ;
      { "Version", "N", 11, 0 }, ;
      { "New_bloc", "N", 1, 0 } }

   aStructTransactions := { { "Id_trans", "N", 10, 0 }, ;  // N° unique de la transaction
      { "num_bloc", "N", 10, 0 }, ;
      { "TimeStamp", "C", 14, 0 } }

   aStructINPUTS := { { "Id_trans", "N", 10, 0 }, ;
      { "num_bloc", "N", 10, 0 }, ;
      { "TimeStamp", "C", 14, 0 }, ;
      { "tx_hash", "C", 64, 0 }, ;
      { "tr_index", "N", 5, 0 } }

   aStructOUTPUTS := { { "Id_trans", "N", 10, 0 }, ;
      { "num_bloc", "N", 10, 0 }, ;
      { "TimeStamp", "C", 14, 0 }, ;
      { "adresse", "C", 34, 0 }, ;
      { "Montant", "N", 14, 0 }, ;
      { "tx_hash", "C", 64, 0 }, ;
      { "nu_output", "N", 5, 0 } }

   aStructADRIMPACTEES := { { "adresse", "C", 47, 0 }, ;
      { "nb_fois", "N", 5, 0 }, ;
      { "Montant", "N", 15, 0 }, ;
      { "TimeStamp", "C", 14, 0 } }

   aStructAdr_non_nul := { ;
      { "adresse", "C", 34, 0 }, ;
      { "Montant", "N", 14, 0 }, ;
      { "first_in", "C", 14, 0 }, ;
      { "last_in", "C", 14, 0 }, ;
      { "first_out", "C", 14, 0 }, ;
      { "last_out", "C", 14, 0 }, ;
      { "last_modif", "C", 14, 0 }, ;
      { "Nb_tr_IN", "N", 7, 0 }, ;
      { "Nb_tr_OUT", "N", 7, 0 }, ;
      { "Nb_transac", "N", 7, 0 } }

   aStructID_TRANS := { { "ID_TRANS", "N", 14, 0 } }

   cls
   SET DATE french
   hb_cdpSelect( "UTF8" ) // Pour obtenir les caractères accentués

   SET DBFLOCKSCHEME TO DB_DBFLOCK_XHB64

   bufContenu_block = Space( 4194304 )  // Taille max d'un bloc (4mo)(Peut être à revoir à la hausse)

   SSL_init()
   OpenSSL_add_all_algorithms()  // adds all algorithms SSL to the table (digests and ciphers).

   hb_threadStart( @Show_Time() )  // Affichage de l'heure en haut à droite

   IF File( "ID_TRANS.dbf" ) = .F.
      dbCreate( "ID_TRANS", aStructID_TRANS, "SIXCDX", .T., "ID_TRANS" )
      USE ID_TRANS
      APPEND BLANK
      USE
      ID_TRANSACTION_EN_COURS = 0
   ELSE
      USE ID_TRANS
      ID_TRANSACTION_EN_COURS = ID_TRANS->ID_TRANS
      USE
   ENDIF

   // ?hb_DateTime()
   @0, 0 SAY "Bitcoin Blockchain Balances PARSER for Windows"

   // Dossier de base des fichiers .DAT provenant de Bitcoin Core
   Dossier_de_base = GetEnv( "APPDATA" ) + "\Bitcoin\blocks"
   IF File( Dossier_de_base + "\blk*.dat" ) = .F.
      IF File( "blk*.dat" ) = .T.
         Dossier_de_base = "."
      ELSE
         IF File( "e:\blockchain\blocks\blk*.dat" ) = .T.
            Dossier_de_base = "e:\blockchain\blocks"
         ELSE
            ?
            ?"Blockchain non trouvée dans le dossier par défaut ou dans le dossier courant :"
            SET COLOR TO BG +/ N
            ?Dossier_de_base
            SET COLOR TO
            ?
            ?"Il n'y a aucun fichier blkXXXXX.dat dans ce dossier"
            ?"Téléchargez bitcoin-core pour synchroniser complètement la blockchain"
            ?"=> https://bitcoin.org/fr/telecharger"
            ?"Puis relancez ce programme."
            ?
            ?
            QUIT
         ENDIF
      ENDIF
   ENDIF

   // Parametre pour le montant minimum des soldes à sélectionner
   IF PCount() == 1
      Montants_a_partir_de = Val( hb_PValue( 1 ) )
      sMontant = LTrim( Str( Montants_a_partir_de / 100000000, 15, 12 ) )
      i = Len( sMontant )
      DO WHILE SubStr( smontant, i, 1 ) = "0"
         i--
      ENDDO
      IF SubStr( smontant, i, 1 ) = "."
         i--
      ENDIF
      sMontant = Left( smontant, i )
      ?"Adresses non nulles a partir de : " + LTrim( Str( Montants_a_partir_de ) ) + " satoshis (" + sMontant + " Btc)"
   ELSE
      Montants_a_partir_de = 0
   ENDIF

   // Création automatique des Fichiers DBF et index NTX
   // Fichier des blocks de la blockchain
   IF File( "Blocks.DBF" ) = .F.
      dbCreate( "blocks", aStructBlocks, "SIXCDX", .T., "Blocks" )
      USE blocks
      INDEX ON blocks->num_bloc TO B_num_bloc
      INDEX ON Blocks->TimeStamp TO B_TimeStamp
      INDEX ON Str( Blocks->new_bloc, 1 ) + Str( Blocks->num_bloc, 10 ) TO B_NewBloc_NumBloc
      INDEX ON Blocks->Fichier + Str( Blocks->pos_bloc, 9 ) TO B_Fichier_Position
      INDEX ON Blocks->hash_bloc TO B_Hash_bloc
      USE
   ENDIF

   // Fichier des transactions
   IF File( "Transactions.dbf" ) = .F.
      dbCreate( "Transactions", aStructTransactions, "SIXCDX", .T., "Transactions" )
   ENDIF

   // Fichier des inputs
   IF File( "INPUTS.DBF" ) = .F.
      dbCreate( "Inputs", aStructINPUTS, "SIXCDX", .T., "Inputs" )
      USE Inputs
      INDEX ON INPUTS->ID_TRANS TO I_id_trans
      // INDEX ON INPUTS->NUM_BLOC TO I_num_bloc
      // INDEX ON INPUTS->adresse TO I_Adresse
      USE
   ENDIF

   // Fichier des adresses_impactees
   IF File( "adresses_impactees.DBF" ) = .F.
      dbCreate( "adresses_impactees", aStructADRIMPACTEES, "SIXCDX", .T., "adresses_impactees" )
      USE adresses_impactees
      INDEX ON adresses_impactees->adresse TO AI_Adresse
      USE
   ENDIF

   // Fichier des outputs
   IF File( "OUTPUTS.DBF" ) = .F.
      dbCreate( "Outputs", aStructOUTPUTS, "SIXCDX", .T., "Outputs" )
      USE Outputs
      INDEX ON OUTPUTS->tx_hash + Str( OUTPUTS->nu_output, 5 ) TO O_TxHash
      INDEX ON OUTPUTS->ID_TRANS TO O_id_trans
      // INDEX ON OUTPUTS->adresse TO O_Adresse
      USE
   ENDIF

   // FIchier final des adresses utilisées dans la blockchain
   IF File( "Adresses_non_nulles.DBF" ) = .F.
      dbCreate( "Adresses_non_nulles", aStructAdr_non_nul, "SIXCDX", .T., "Adresses_non_nulles" )
      USE adresses_non_nulles
      // index on adresses_non_nulles->num_bloc to AD_num_bloc
      INDEX ON adresses_non_nulles->adresse TO AD_adresse
      USE
   ENDIF

   /*
   // Fichier des adresses qui sont passées de >0 à 0
   IF File( "Reserve.DBF" ) = .F.
      dbCreate( "Reserve", aStructAdr_non_nul, "SIXCDX", .T., "Reserve" )
      USE reserve
      INDEX ON reserve->adresse TO R_adresse
      USE
   ENDIF
   */

   USE blocks INDEX B_num_bloc, B_TimeStamp, B_NewBloc_NumBloc, B_Fichier_position, B_Hash_bloc
   IF RecCount() > 0
      SEEK 999999999  // Si ça a buggé précédemment lors de la recherche de nouveaux blocs, on nettoie.
      IF Found()
         DELETE WHILE ! Eof()
         PACK
      ENDIF
      GO BOTT
      SAI_dernier_block = blocks->num_bloc
      SET ORDER TO TAG B_NewBloc_NumBloc
      SEEK Str( 0, 1 )
      IF Found()
         SAI_A_partir_du_block = blocks->num_bloc
      ELSE
         SAI_A_partir_du_block = SAI_dernier_block
      ENDIF
      @2, 0 SAY "Dernier Bloc : " + Str( SAI_Dernier_Block )
      @2, 28 SAY "Bloc a traiter : " + Str( SAI_A_partir_du_block )
      @4, 0
   ELSE
      SAI_dernier_block = 0
      SAI_A_partir_du_block = 0
      @2, 0 SAY "Dernier Bloc : " + Str( SAI_Dernier_Block )
      @2, 28 SAY "Bloc a traiter : " + Str( SAI_A_partir_du_block )
   ENDIF

   SET DELETED ON
   USE blocks INDEX B_fichier_position
   GO BOTT
   bFlag_trouve_new_bloc = .F.
   position_depart_block = Blocks->pos_bloc
   nUmero_fichier = Val( SubStr( Blocks->fichier, 4, 5 ) )
   nom_fichier = Dossier_de_base + "\blk" + StrZero( numero_fichier, 5 ) + ".dat"
   USE

   USE blocks INDEX B_num_bloc
   GO BOTT
   IF File( nom_fichier ) = .T.
      Taille_fichier = FileSize( nom_fichier )
      IF ( position_depart_block + Blocks->TailleBloc ) >= Taille_fichier
         position_depart_block = 0
         numero_fichier++
         nom_fichier = Dossier_de_base + "\blk" + StrZero( numero_fichier, 5 ) + ".dat"
      ELSE
         IF Blocks->Taillebloc > 0
            position_depart_block = Blocks->pos_bloc + Blocks->TailleBloc + 8  // Position du Prochain block dans le fichier .DAT
         ENDIF
      ENDIF
      IF File( nom_fichier ) = .T.
         @8, 0 SAY "Phase 1/4 : Recensement des nouveaux blocs..."
         SAI_NumBlock = 999999999
         DO WHILE .T.
            chemin_fichier = Dossier_de_base + "\blk" + StrZero( numero_fichier, 5 ) + ".dat"
            IF File( chemin_fichier ) = .F.
               EXIT
            ENDIF
            SAI_Nom_Fichier = chemin_fichier
            @5, 0 SAY "Nom du fichier   : blk" + StrZero( numero_fichier, 5 ) + ".dat"
            Taille_fichier = FileSize( chemin_fichier )
            nCanal = FOpen( chemin_fichier, 0 )
            Nom_fichier = "blk" + StrZero( numero_fichier, 5 ) + ".dat"
            IF position_depart_block <> 0
               FSeek( nCanal, position_depart_block, FP_DEBUT )
               position_depart_block = 0
            ENDIF
            position_block = FSeek( nCanal, 0, FP_COURANT )
            DO WHILE position_block < Taille_fichier   // *********** Lecture du fichier blkXXXXX.dat
               FRead( nCanal, @bufContenu_block, 88 )
               Hash_Block = HashChaine( HA_SHA_256, SubStr( bufContenu_block, 9, 80 ) )
               Hash_Block = HashChaine( HA_SHA_256, Hash_Block )  // Hash du block en cours.
               SAI_Time_Stamp = TimeStampVersDateHeure( SubStr( bufContenu_Block, 77, 4 ) )
               @6, 0 SAY "TimeStamp        : " + hb_TToC( hb_SToT( SAI_Time_Stamp ), "DD/MM/YYYY", "HH:MM:SS" )
               // @7,0 say "Taille Fichier   : "+str(Taille_fichier)
               // @8,0 say "Pos Bloc         : "+str(position_block)
               IF SubStr( bufContenu_Block, 1, 4 ) = MAGIC_CODE
                  bFlag_trouve_new_bloc = .T.
                  nBdiff = Asc( SubStr( bufContenu_Block, 81, 1 ) ) + Asc( SubStr( bufContenu_Block, 82, 1 ) ) * 256 + Asc( SubStr( bufContenu_Block, 83, 1 ) ) * 65536
                  pdiff = Asc( SubStr( bufContenu_Block, 84, 1 ) )
                  rDifficulty = 2.695953529101 * 10 ^ 67 / ( nBdiff * 2 ^ ( 8 * ( pdiff - 3 ) ) ) // Difficulté actuelle
                  APPEND BLANK
                  REPLACE Blocks->Num_bloc   WITH 999999999 // Numero du bloc
                  REPLACE Blocks->fichier    WITH nom_fichier
                  REPLACE Blocks->pos_bloc   WITH position_block
                  REPLACE Blocks->hash_bloc  WITH hb_StrToHex( reverse( Hash_block ) )
                  REPLACE Blocks->hashPbloc  WITH hb_StrToHex( reverse( SubStr( bufContenu_Block, 13, 32 ) ) )
                  REPLACE Blocks->MerkleRoot WITH hb_StrToHex( reverse( SubStr( bufContenu_Block, 45, 32 ) ) )
                  REPLACE Blocks->TimeStamp  WITH SAI_Time_Stamp
                  REPLACE Blocks->Nb_transac WITH 0
                  REPLACE Blocks->Difficulte WITH rDifficulty // Difficulté du bloc
                  REPLACE Blocks->TailleBloc WITH TAILLE_DU_BLOC
                  REPLACE Blocks->Version     WITH Asc( SubStr( bufContenu_Block, 9, 1 ) ) + Asc( SubStr( bufContenu_Block, 10, 1 ) ) * 256 + Asc( SubStr( bufContenu_Block, 11, 1 ) ) * 65536 + Asc( SubStr( bufContenu_Block, 12, 1 ) ) * 16777216
                  REPLACE Blocks->Nonce      WITH Asc( SubStr( bufContenu_Block, 85, 1 ) ) + Asc( SubStr( bufContenu_Block, 86, 1 ) ) * 256 + Asc( SubStr( bufContenu_Block, 87, 1 ) ) * 65536 + Asc( SubStr( bufContenu_Block, 88, 1 ) ) * 16777216
                  IF ( position_block + Blocks->TailleBloc + 8 ) < Taille_fichier
                     position_block = FSeek( nCanal, position_block + Blocks->TailleBloc + 8, FP_DEBUT )
                  ELSE
                     EXIT
                  ENDIF
               ELSE
                  EXIT
               ENDIF
            ENDDO
            FClose( nCanal )
            numero_fichier++
         ENDDO
      ENDIF

      // bFlag_trouve_new_bloc=.T.
      IF bFlag_trouve_new_bloc = .T.
         USE blocks INDEX B_num_bloc, B_TimeStamp, B_NewBloc_NumBloc, B_Fichier_position, B_Hash_bloc
         REINDEX
         USE blocks INDEX B_TimeStamp, B_Hash_bloc
         @8, 0 SAY "Phase 2/4 : Suppression des Blocs orphelins..."
         // On repart de la fin pour éliminer les orphans blocks
         SET ORDER TO TAG B_TimeStamp
         GO BOTTOM // Dernier block connu récupéré de la blockchain
         gnNnum_block = 2000000000

         DO WHILE Blocks->Num_bloc >= 999999999
            @6, 0 SAY "TimeStamp        : " + hb_TToC( hb_SToT( Blocks->TimeStamp ), "DD/MM/YYYY", "HH:MM:SS" )
            REPLACE blocks->num_bloc WITH gnNnum_block
            Hash_previous_Block = blocks->hashPbloc
            gnNnum_block--
            SKIP -1
            IF blocks->hash_bloc != Hash_previous_Block
               SET ORDER TO TAG B_Hash_Bloc
               SEEK Hash_previous_block
               IF ! Found()
                  IF Val( Hash_previous_block ) <> 0
                     // ?"Au bloc N "+str((gnNnum_block+1))
                     ?"BUG : Il manque le bloc dans les fichiers .dat dont le hash est : "
                     ?Hash_previous_Block
                     ?"Attendre la synchro complete du client bitcoin-core"
                     ?"puis relancez le programme"
                     ?
                     QUIT
                  ENDIF
               ELSE
                  numenr = RecNo()
                  SET ORDER TO TAG B_TimeStamp
                  GO numenr
               ENDIF
            ENDIF
         ENDDO

         // set deleted ON
         SET SOFTSEEK ON
         INDEX ON blocks->num_bloc TO B_num_bloc
         @8, 0 SAY "Phase 3/4 : Suppression des Blocs orphelins..."
         SET ORDER TO TAG B_num_bloc
         SEEK 999999999
         SKIP -1
         IF Bof()
            numero_dernier_block =-1
         ELSE
            numero_dernier_block = Blocks->Num_bloc
         ENDIF

         SEEK 999999999
         DO WHILE Blocks->Num_bloc = 999999999 .AND. !Eof()
            dbDelete() // Blocks orphelins
            SKIP
         ENDDO

         @8, 0 SAY "Phase 4/4 : Renommage des Blocs ...             "
         numero_dernier_block++
         DO WHILE !Eof()
            Blocks->Num_bloc := numero_dernier_block
            numero_dernier_block++
            SKIP
         ENDDO

         SET UNIQUE ON
         INDEX ON blocks->fichier TO funique
         nU_fichier = 0
         GO TOP
         DO WHILE !Eof()
            IF Blocks->fichier <> "blk" + StrZero( nU_fichier, 5 ) + ".dat"
               ?"Le fichier blk" + StrZero( nU_fichier, 5 ) + ".dat n'a pas été exploré"
               ?"Verifiez sa présence dans les fichiers du dossier blocks"
               ?
               QUIT
            END
            numero_dernier_block = blocks->num_bloc
            nU_fichier++
            dbSkip()
         ENDDO
         SET UNIQUE OFF
         SET SOFTSEEK OFF

         USE blocks INDEX B_num_bloc, B_TimeStamp, B_NewBloc_NumBloc, B_Fichier_position, B_Hash_bloc
         PACK  // Reconstruction des index
      ENDIF
   ELSE
      ?"Fichier " + Dossier_de_base + "\blk" + StrZero( numero_fichier, 5 ) + ".dat Introuvable !"
      ?"Vérifiez que tous les fichiers .DAT soient présents"
      ?"Et relancez le programme"
      IF SAI_A_partir_du_block < blocks->num_bloc
         IF reponse2( "On continue quand même l'analyse à partir du bloc " + LTrim( Str( SAI_A_partir_du_block ) ) + " ?", Row() + 2, 0, "O" ) = "N"
            ?
            QUIT
         ENDIF
         @4, 0 clear
      ENDIF
   ENDIF

   CLOSE ALL

   SET DELETED OFF
   flag_phase2 = .F.

   DO WHILE .T.
      @4, 0 clear
      IF flag_phase2 = .T.
         EXIT
      ENDIF

      // *******************************************
      // -------------------------------------------
      // Lancement de l'analyse des blocs
      // -------------------------------------------
      // *******************************************
      // USE Reserve INDEX R_adresse NEW

      nbre_etapes = "4"

      USE transactions NEW

      USE Inputs INDEX  I_id_trans NEW // I_num_bloc, I_adresse new

      USE Outputs INDEX O_TxHash, O_id_trans NEW // , O_adresse new

      USE blocks INDEX B_num_bloc, B_NewBloc_NumBloc NEW // ,TimeStamp,Fichier_position,Hash_bloc
      GO BOTT
      nMax_block = Blocks->Num_bloc // Dernier bloc connu à traiter

      SET ORDER TO TAG B_NewBloc_NumBloc
      GO TOP  // Blocs non encore analysés : 0xxxxxxxxxx
      IF Blocks->new_bloc <> 0
         Flag_phase2 = .T.  // plus de bloc à Analyser
         ?"Plus de bloc à traiter"
         ?
         ?
         Exit_user = .T.
         CLOSE ALL
         EXIT
      ENDIF

      SetColor( "BG+/N" )
      @4, 0 SAY "Etape 1/" + nbre_etapes + " Récupération des transactions Inputs/outputs.."
      SET COLOR TO

      IF flag_phase2 = .F.
         position_depart_block = Blocks->pos_bloc
         nUmero_fichier = Val( SubStr( Blocks->fichier, 4, 5 ) )
         nom_fichier = Dossier_de_base + "\blk" + StrZero( numero_fichier, 5 ) + ".dat"

         @6, 0 clear
         @2, 0 SAY  "Dernier Bloc : " + Str( nMax_block )
         gnBloc_depart = Blocks->Num_bloc
         @2, 28 SAY "Bloc a traiter : " + Str( gnBloc_depart )
         gnBloc_actuel = gnBloc_depart
         nUmero_fichier_actu =-1
         nCanal = 0
         nb_bloc_traites = 0

         // Test address : 1KYSZEzUFzBUFWt37waNBmLqUebXSq2ddG

         SELE BLOCKS
         SET ORDER TO TAG B_num_bloc
         SEEK gnBloc_depart

         // t1 := hb_DateTime()
         GnMoyenne = 0 ; SAI_duree = ""
         exit_user = .F.
         pThID = hb_threadStart( @Ajout_traites(), @gnBloc_actuel, @gnBloc_depart, @GnMoyenne, @nMax_block, @SAI_duree )

         @6,  0 SAY "Bloc Actu : "
         @7,  0 SAY "TimeStamp : "
         @8,  0 SAY "Nb Trans  : "
         @9,  0 SAY "Effectué  : "
         @10, 0 SAY "Blocs/Mn  : "

         DO WHILE ! Eof() // Recupere les blocks non traités
            // Nom du fichier .DAT à ouvrir
            gnNnum_block = Blocks->Num_bloc  // N° du bloc en cours de traitement
            SAI_Time_Stamp = Blocks->TimeStamp
            gnBloc_actuel = gnNnum_block
            pos_depart_block = Blocks->pos_bloc // Position du bloc dans le fichier

            IF Val( SubStr( Blocks->fichier, 4, 5 ) ) <> nUmero_fichier_actu
               nUmero_fichier_actu = Val( SubStr( Blocks->fichier, 4, 5 ) )
               chemin_fichier = Dossier_de_base + "\blk" + StrZero( nUmero_fichier_actu, 5 ) + ".dat"
               IF File( chemin_fichier ) = .F.
                  EXIT
               ENDIF
               SAI_Nom_Fichier = chemin_fichier
               IF nCanal <> 0
                  FClose( nCanal )
               ENDIF
               nCanal = FOpen( chemin_fichier, 0 )
               @5, 0 SAY "Fihier    : " + chemin_fichier
            ENDIF

            @6, 12 SAY Str( gnNnum_block )
            @7, 12 SAY hb_TToC( hb_SToT( Blocks->TimeStamp ), "DD/MM/YYYY", "HH:MM:SS" )
            @9, 12 SAY Str( ( Blocks->Num_bloc * 100 / nMax_block ), 6, 2 ) + " % (" + LTrim( Str( nMax_Block - gnNnum_block ) ) + " blocs restants)      "

            position_block = FSeek( nCanal, pos_depart_block, FP_DEBUT ) // On se position au début du bloc à recuperer

            SAI_NumBlock = gnNnum_block  // N° du block en cours de traitement
            FRead( nCanal, @bufContenu_block, 88 )
            nPointeur_fichier = FSeek( nCanal, 0, FP_COURANT ) // Pointeur au niveau de transaction Count
            IF SubStr( bufContenu_Block, 1, 4 ) = MAGIC_CODE // Magic ID
               nB_transac_segwit = 0
               rPourcent_segwit = 0
               FRead( nCanal, @bufContenu_block, TAILLE_DU_BLOC -80 ) // On lit tout le contenu du bloc en mémoire.
               nPtr = 1
               nb_transactions = Variable_length_integer( bufContenu_block, @nPtr ) // **B9** Nbre de transactions
               @8, 12 SAY Str( nb_transactions )

               // *********************************************
               // TRANSACTIONS
               // *********************************************
               FOR nu_trans = 1 TO nb_transactions
                  nPtrDebut_transaction = nPtr       // Pointeur sur le 1er octet de la transaction
                  nadresse_debut_transaction = nPtr
                  // Transaction_version_number=recup_chiffre_4_octets(@bufContenu_block,nPtr)
                  nPtr += 4 // **T1** Transaction version Number
                  bFlagSegwit = .F.
                  nB_input_transactions = Variable_length_integer( bufContenu_block, @nPtr ) // **T2** Nbre d'inputs dans la transaction

                  IF nB_input_transactions = 0 // C'est un bloc Segwit
                     nTemp = Asc( SubStr( bufContenu_block, nPtr, 1 ) )
                     IF ntemp = 1   // Flag Segwit Transaction !!! Block 481824
                        nPtr++
                        nB_input_transactions = Variable_length_integer( @bufContenu_block, @nPtr ) // **T2** Nbre d'inputs dans la transaction
                        bFlagSegwit = .T.
                        nB_transac_segwit++
                        // @7,23 say "(Segwit : "+str(nB_transac_segwit,4)+")"
                     ENDIF
                  ENDIF
                  // Text_IO = ltrim(str(nB_input_transactions))+" I/"

                  ID_transaction_en_cours++

                  SELE TRANSACTIONS
                  APPEND BLANK
                  REPLACE transactions->ID_trans WITH ID_transaction_en_cours // N° transaction Unique
                  REPLACE Transactions->Num_bloc WITH gnNnum_block

                  // *********************************************
                  // INPUT TRANSACTIONS
                  // *********************************************
                  FOR i = 1 TO nB_input_transactions
                     position_debut_input_transaction = nPtr
                     Transaction_Hash = SubStr( bufContenu_block, nPtr, 32 )   // **I1** Previous output Transaction Hash (32 octets)
                     nPtr += 32
                     nTransaction_index = recup_chiffre_4_octets( @bufContenu_block, nPtr ) // **I2** Transaction Index -> N° d'output dans la transaction précédente
                     nPtr += 4
                     IF nTransaction_index = 0xFFFFFFFF  // No previous output, New mined Block
                        nTransaction_index =-1
                        Flag_New_mined_Block = 1
                     ELSE
                        Flag_New_mined_Block = 0
                     ENDIF

                    /*
    if nTransaction_index>99999
       ?
       ?"Probleme TR_Index >99999"
       ?"Position fichier : 0x"+Ntoc((nPointeur_fichier+(position_debut_input_transaction-1)),16)
       ?"No transaction : "
       ??nu_trans
       ?"No input : "
       ??i
       ?"Transaction Hash Input : "
       ??hb_StrToHex(reverse(Transaction_Hash))
       ?"Transaction index : "
       ??ntransaction_index
       wait "STOP"
    endif
                    */

                     nScript_length = Variable_length_integer( bufContenu_block, @nPtr ) // **I3** Longueur du script qui suit

                     IF nScript_length > 10000
                        ?"Bug Input très longue, 'bufScript_table' pas assez large (>10000 octets : " + Str( nScript_length ) + " octets !)"
                        ?"Block N°" + Str( gnNnum_block ) + " N° transaction=" + Str( nu_trans ) + " N° input=" + Str( i )
                        ?
                        QUIT
                     ENDIF
                     // bufScript_table=substr(bufContenu_block,nPtr,nScript_length)  //**I4** Raw byte code for the input Script
                     nPtr += nScript_length
                     // Sequence_number=recup_chiffre_4_octets(@bufContenu_block,nPtr) //**I5** N° sequence =0XFFFFFFFF
                     nPtr += 4

                     tx_Hash_clair = hb_StrToHex( reverse( Transaction_Hash ) )  // Hash de la transaction input précédente en clair

                     IF nTransaction_index <> -1
                        SELE INPUTS
                        APPEND BLANK // Ajout caracteristiques de l'input ds le fichier
                        REPLACE inputs->ID_trans  WITH id_transaction_en_cours
                        REPLACE INPUTS->num_bloc  WITH gnNnum_block
                        REPLACE INPUTS->TimeStamp WITH SAI_Time_Stamp
                        REPLACE INPUTS->tx_hash   WITH tx_hash_clair
                        REPLACE INPUTS->tr_index  WITH nTransaction_index
                     ENDIF
                  NEXT // Next transaction INPUT

                  nb_outputs_transactions = Variable_length_integer( bufContenu_block, @nPtr ) // **T3** Nbre d'Outputs

                  // *********************************************
                  // OUTPUTS TRANSACTIONS
                  // *********************************************
                  FOR nB_output = 1 TO nb_outputs_transactions
                     position_debut_output_transaction = nPtr
                     nMontant_transaction = recup_chiffre_8_octets( @bufContenu_block, nPtr )
                     nPtr += 8   // **O1** Montant de la transaction en Satoshis 100 000 000 satoshis = 1 BTC

                     nScript_length = Variable_length_integer( bufContenu_block, @nPtr ) // **O2** Longueur du script qui suit
                     IF nScript_length > 4050
                        ?"Bug Transaction output tres longue, 'bufScript_table' pas assez large (>4050 octets : " + Str( nScript_length ) + " octets !)"
                        ?"Block N°" + Str( gnNnum_block ) + " N° transaction=" + Str( nb_trans ) + " Output " + Str( nB_output )
                        ?
                        QUIT
                     ELSE
                        bufScript_table = SubStr( bufContenu_block, nPtr, nScript_length )
                        nPtr += nScript_length // **O3** Raw byte code for the input Script (contient la clé publique de sortie)
                     ENDIF
                     DO CASE
                     CASE nScript_length = 67 // Format 1 Output public Key sur 65 octets
                        IF SubStr( bufScript_table, 1, 1 ) = Chr( 0x41 )
                           Public_key_65 = SubStr( bufScript_table, 2, 65 )
                           format_public_key = HEXA_65
                           IF SubStr( bufScript_table, 67, 1 ) <> Chr( 0xAC )
                              format_public_key = HEXA_ERR
                           ENDIF
                        ELSE
                           format_public_key = HEXA_ERR
                        ENDIF
                     CASE nScript_length = 35 // Format Compressé de la public Key sur 33 octets
                        Public_key_33 = SubStr( bufScript_table, 2, 33 )
                        format_public_key = HEXA_33
                        IF SubStr( bufScript_table, 35, 1 ) <> Chr( 0xAC )
                           format_public_key = HEXA_ERR
                        ENDIF
                     CASE nScript_length = 66 // Techniquement invalide car pas d'OP en début de script
                        format_public_key = HEXA_ERR
                     OTHERWISE
                        IF SubStr( bufScript_table, 1, 1 ) = Chr( 0xA9 ) .AND. SubStr( bufScript_table, 2, 1 ) = Chr( 0x14 )  // OP_HASH160 20-byte hash OP_EQUAL
                           format_public_key = HEXA_20_HASH160 // 20 octets hashés : first with SHA-256 and then with RIPEMD-160.
                           Public_key_20 = SubStr( bufScript_table, 3, 20 )
                           IF SubStr( bufScript_table, 23, 1 ) = Chr( 0x87 ) // OP_EQUAL
                              // OK
                           ELSE
                              format_public_key = HEXA_ERR // 20 octets
                           ENDIF
                        ELSE
                           // Format 3-4-5 Output Public Key
                           IF SubStr( bufScript_table, 1, 1 ) = Chr( 0x76 ) .AND. SubStr( bufScript_table, 2, 1 ) = Chr( 0xA9 ) // OP_DUP+OP_HASH160 <pubkey 20 octets> OP_CHECKSIG
                              DO CASE
                              CASE SubStr( bufScript_table, 3, 1 ) = Chr( 0x14 ) // Taille de la public Key 20 octets
                                 format_public_key = HEXA_20 // 20 octets
                                 Public_key_20 = SubStr( bufScript_table, 4, 20 )
                                 IF SubStr( bufScript_table, 24, 1 ) = Chr( 0x88 ) // OP_EQUALVERIFY
                                    IF SubStr( bufScript_table, 25, 1 ) = Chr( 0xAC ) // OP_CHECKSIG
                                       IF nScript_length > 25 .AND. SubStr( bufScript_table, 26, 1 ) = Chr( 0xAC ) .AND. SubStr( bufScript_table, 27, 1 ) = Chr( 0xAC )
                                          format_public_key = HEXA_ERR // Non Standard Script (BUG Block N° 71036)
                                       ELSE
                                          // OK
                                       ENDIF
                                    ENDIF
                                 ENDIF
                              CASE SubStr( bufScript_table, 3, 1 ) = Chr( 0x00 ) // Erreur Päs de public Key, impossible à décoder
                                 format_public_key = HEXA_ERR // 20 octets
                              ENDCASE
                           ELSE
                              IF SubStr( bufScript_table, 1, 1 ) = Chr( 0x4C ) // OP_PUSHDATA1
                                 IF SubStr( bufScript_table, 2, 1 ) <> Chr( 0x76 ) .AND. SubStr( bufScript_table, 3, 1 ) <> Chr( 0xA9 ) // Si on a pas OP_DUP+OP_HASH160 => Erreur Public Key
                                    format_public_key = HEXA_ERR
                                 ELSE
                                    DO CASE
                                    CASE SubStr( bufScript_table, 4, 1 ) = Chr( 0x14 ) // Taille de la public Key 20 octets
                                       format_public_key = HEXA_20 // 20 octets
                                       Public_key_20 = SubStr( bufScript_table, 4, 20 )
                                       IF SubStr( bufScript_table, 25, 1 ) = Chr( 0x88 ) // OP_EQUALVERIFY
                                          IF SubStr( bufScript_table, 26, 1 ) = Chr( 0xAC ) // OP_CHECKSIG
                                             IF SubStr( bufScript_table, 27, 1 ) = Chr( 0xAC ) .AND. SubStr( bufScript_table, 28, 1 ) = Chr( 0xAC )
                                                format_public_key = HEXA_ERR // Non Standard Script (BUG Block N° 71036)
                                             ELSE
                                                // OK
                                             ENDIF
                                          ENDIF
                                       ENDIF
                                    CASE SubStr( bufScript_table, 4, 1 ) = Chr( 0x00 ) // Erreur Päs de public Key, impossible à décoder
                                       format_public_key = HEXA_ERR // 20 octets
                                    ENDCASE
                                 ENDIF
                              ELSE
                                 IF SubStr( bufScript_table, 1, 1 ) < Chr( 0x4C )
                                    format_public_key = HEXA_ERR // 20 octets
                                 ELSE
                                    format_public_key = HEXA_ERR // Clé publique non décodable ?
                                 ENDIF
                              ENDIF
                           ENDIF
                        ENDIF
                     ENDCASE
                     DO CASE
                     CASE format_public_key = HEXA_ERR
                        AAdd( table_transactions, { nMontant_transaction, "", format_public_key } )
                     CASE format_public_key = HEXA_20
                        AAdd( table_transactions, { nMontant_transaction, Public_key_20, format_public_key } )
                     CASE format_public_key = HEXA_33
                        AAdd( table_transactions, { nMontant_transaction, Public_key_33, format_public_key } )
                     CASE format_public_key = HEXA_65
                        AAdd( table_transactions, { nMontant_transaction, Public_key_65, format_public_key } )
                     CASE format_public_key = HEXA_20_HASH160
                        AAdd( table_transactions, { nMontant_transaction, Public_key_20, format_public_key } )
                     ENDCASE
                  NEXT // Next Transaction OUTPUT
                  IF bFlagSegwit = VRAI
                     nPtrDebut_Witness = nPtr  // Pointeur sur le 1er octet des champs witness
                     // Voir explications sur https://bitcoincore.org/en/segwit_wallet_dev/
                     // Structure :
                     // <Nbre de witness fields>
                     // <Taille du champ Witness field>
                     // <Data correspondant à la taille du champ>
                     // ... n champs
                     // <Taille Witness field>
                     // <Data correspondant à la taille du champ>
                     FOR i = 1 TO nB_input_transactions // Il y a autant de champs witnes que d'inputs transactions.
                        nb_witness_fields = Variable_length_integer( bufContenu_block, @nPtr ) // Nbre de champs witness pour la transaction intput
                        IF nb_witness_fields > 0
                           FOR nB_witness = 1 TO nb_witness_fields
                              Taille_witness_fields = Variable_length_integer( bufContenu_block, @nPtr )
                              // Transfert(&bufScript_table,nPtr,nScript_length) ;
                              nPtr += Taille_witness_fields
                           NEXT
                        ENDIF
                     NEXT
                  ENDIF

                  // nTransaction_Lock_Time=recup_chiffre_4_octets(@bufContenu_block,nPtr)  //**T4** Transaction Lock Time
                  nPtr += 4
                  nPtrFin_transaction = nPtr

                  // IF (nPtrFin_transaction-nPtrDebut_transaction)>200000
                  // ?"Taille transaction Atypique N°"+str(nb_trans)+" Output N°"+str(nb_trans)+" ("+str(nPtrFin_transaction-nPtrDebut_transaction)+" octets!) Position fichier O1: 0x"+right(EntierVersHexa(nPointeur_fichier+(position_debut_output_transaction-&bufContenu_block)),7))
                  // ENDIF
                  IF ( nPtrFin_transaction - nPtrDebut_transaction ) > 1048000
                     ?"Taille transaction N°" + Str( nb_trans ) + " Output N°" + Str( nb_trans ) + "  >1048000   octets (" + Str( nPtrFin_transaction - nPtrDebut_transaction ) + ")"
                     ?"Position fichier O1: 0x" + NToC( ( nPointeur_fichier + ( position_debut_output_transaction -1 ) ), 16 )
                     ?"STOP"
                     QUIT
                  ELSE
                     // Calcul du TX HASH de la transaction OUTPUT en cours
                     sfTransaction_buffer = SubStr( bufContenu_block, nPtrDebut_transaction, nPtrFin_transaction - nPtrDebut_transaction )
                     IF bFlagSegwit = VRAI
                        // Pour calculer le hash de la transaction,
                        // On ne garde que les datas originaux de la transaction => On extrait des datas le champ Flag segwit (2 octets) ET les champs Witness Field
                        sCore_data = Left( sfTransaction_buffer, nPtrFin_transaction - nPtrDebut_transaction ) // Datas bruts avec flag segwit et champs segwit
                        sCore_data = Stuff( sCore_data, ( nPtrDebut_Witness - nPtrDebut_transaction + 1 ), ( nPtrFin_transaction - nPtrDebut_Witness -4 ), "" ) // Suppression des champs witness
                        sCore_data = Stuff( sCore_data, 5, 2, "" ) // Suppression du Champ Flag Segwit
                        // Double Hash 256 des datas restants de la transaction
                        Hash_Block = HashChaine( HA_SHA_256, sCore_data )
                        Hash_Block = HashChaine( HA_SHA_256, Hash_Block )  // Hash du block en cours.
                        tx_Hash_clair = hb_StrToHex( reverse( Hash_Block ) )  // Transaction Hash de la transaction en clair
                     ELSE
                        Hash_Block = HashChaine( HA_SHA_256, Left( sfTransaction_buffer, nPtrFin_transaction - nPtrDebut_transaction ) )
                        // Double Hash 256 des datas de la transaction
                        Hash_Block = HashChaine( HA_SHA_256, Hash_Block )  // Hash du block en cours.
                        tx_Hash_clair = hb_StrToHex( reverse( Hash_Block ) ) // Transaction Hash de la transaction en clair
                     ENDIF
                  ENDIF

                  numero_output = 0 // Permet de faire la correspondance avec les transactions input via le Transaction_Index
                  FOR i = 1 TO Len( table_transactions )
                     adresse_bitcoin = Base58_encode( Table_transactions[ i, 2 ], Table_transactions[ i, 3 ] )

                     SELE OUTPUTS
                     APPEND BLANK
                     REPLACE Outputs->ID_trans   WITH id_transaction_en_cours
                     REPLACE OUTPUTS->num_bloc   WITH gnNnum_block
                     REPLACE OUTPUTS->TimeStamp  WITH SAI_Time_Stamp
                     REPLACE OUTPUTS->tx_hash    WITH tx_hash_clair
                     REPLACE OUTPUTS->nu_output  WITH numero_output
                     REPLACE OUTPUTS->adresse    WITH adresse_bitcoin
                     REPLACE OUTPUTS->montant    WITH Table_transactions[ i, 1 ]

                     numero_output++
                  NEXT
                  Table_transactions := {}
               NEXT  // Next Transactions
            ELSE
               ?"Magic Code non trouvé !!!"
               ?"Fichier .dat corrompu ?? : " + SAI_Nom_Fichier
               ?"Impossible de poursuivre le traitement"
               ?"Traitement stoppé"
               ?
               QUIT
            ENDIF

            SELE BLOCKS
            REPLACE Blocks->nb_transac WITH nb_transactions
            REPLACE Blocks->New_bloc   WITH 1 // Indique que le bloc est traité

            dernier_bloc_traite = Blocks->num_bloc

            IF GnMoyenne > 0
               @10, 12 SAY Str( GnMoyenne, 7, 1 ) + ", reste " + SAI_duree + "  "
            ENDIF

            SELE Inputs
            IF RecCount() > 15000000   // On sort tous les 15 000 000 d'adresses sorties pour limiter la taille des fichier I/O
               EXIT
            ENDIF

            SELE BLOCKS
            SKIP   // Passe au bloc suivant

            Inkey()
            IF LastKey() = 27
               SET COLOR TO "GR+/R"
               @1, 70 SAY "Exit User"
               SET COLOR TO
               exit_user = .T.
               KEYBOARD Chr( 0 )
               // @10, 0
               EXIT
            ENDIF

         ENDDO
         lOk := hb_threadQuitRequest( pThID )

      ENDIF
      CLOSE ALL

      // Adresse test : 1NvNvZT4JUgsA3QdDDwFscDYX2zrseeDog

      // -------------------------------------------------
      // -------------------------------------------------
      // Phase 2
      // -------------------------------------------------
      // -------------------------------------------------
      SET DELETED OFF

      @10, 0
      SetColor( "BG+/N" )
      @11, 0 SAY "Etape 2/" + nbre_etapes + "... Balayage des Transactions I/O.."
      SET COLOR TO

      USE adresses_impactees INDEX AI_Adresse NEW
      ZAP

      USE transactions NEW

      USE Outputs INDEX O_id_trans, O_TxHash NEW

      USE Inputs INDEX I_id_trans NEW

      // USE adresses_non_nulles INDEX AD_adresse NEW
      // USE Reserve INDEX R_adresse NEW

      KEYBOARD Chr( 0 )
      nb_transac = 0
      @12, 0 SAY "Bloc Actu :"
      @13, 0 SAY "Blocs/Mn  :"

      SELE transactions
      GO BOTT
      nMax_block = transactions->num_bloc
      GO TOP
      gnBloc_actuel = transactions->num_bloc

      GnMoyenne = 0
      SAI_duree = ""
      gnBloc_depart = gnBloc_actuel
      pThID = hb_threadStart( @Ajout_traites(), @gnBloc_actuel, @gnBloc_depart, @GnMoyenne, @nMax_block, @SAI_duree )

      DO WHILE ! Eof()
         IF gnBloc_actuel <> transactions->num_bloc
            gnBloc_actuel = transactions->num_bloc
            @12, 12 SAY Str( gnBloc_actuel ) + " (" + LTrim( Str( nMax_Block - gnBloc_actuel ) ) + " blocs restants) "
            IF GnMoyenne > 0
               @13, 12 SAY Str( GnMoyenne, 7, 1 ) + ", reste " + SAI_duree + "  "
               GnMoyenne = 0
            ENDIF
         ENDIF

         SELE Outputs
         SET ORDER TO TAG o_txhash

         SELE INPUTS
         SEEK transactions->id_trans
         DO WHILE ! Eof() .AND. transactions->id_trans = inputs->id_trans
            SELE OUTPUTS
            SEEK INPUTS->TX_HASH + Str( INPUTS->TR_INDEX, 5 ) // Recherche de la transaction précédente dans les OUTPUTS
            IF Found()
               Montant_retire =- OUTPUTS->MONTANT
               REPLACE OUTPUTS->MONTANT WITH 0    // RAZ du montant
               DELETE  // Delete logique

               SELE adresses_impactees
               SEEK Str( transactions->id_trans, 10 ) + "-I-" + outputs->adresse
               IF ! Found()
                  APPEND BLANK
                  REPLACE adresses_impactees->adresse   WITH Str( transactions->id_trans, 10 ) + "-I-" + outputs->adresse
                  REPLACE adresses_impactees->TimeStamp WITH inputs->timestamp
                  REPLACE adresses_impactees->nb_fois   WITH 1
                  REPLACE adresses_impactees->Montant   WITH Montant_retire
               ELSE
                  REPLACE adresses_impactees->nb_fois   WITH adresses_impactees->nb_fois + 1
                  REPLACE adresses_impactees->Montant   WITH adresses_impactees->Montant + Montant_retire
               ENDIF
            ELSE
               ?"BUG ! : Crédit à sortir non trouvé dans le fichier OUTPUTS : "
               ?"Tx Hash : " + INPUTS->TX_HASH
               ?"Tr index : " + Str( INPUTS->TR_INDEX, 5 )
               WAIT "Stop"
            ENDIF

            SELE INPUTS
            SKIP
         ENDDO

         SELE Outputs
         SET ORDER TO TAG o_id_trans
         SEEK transactions->id_trans
         DO WHILE ! Eof() .AND. transactions->id_trans = outputs->id_trans
            SELE adresses_impactees
            SEEK Str( transactions->id_trans, 10 ) + "-O-" + outputs->adresse
            IF ! Found()
               APPEND BLANK
               REPLACE adresses_impactees->adresse   WITH Str( transactions->id_trans, 10 ) + "-O-" + outputs->adresse
               REPLACE adresses_impactees->TimeStamp WITH outputs->timestamp
               REPLACE adresses_impactees->Montant   WITH outputs->Montant
               REPLACE adresses_impactees->nb_fois   WITH 1
            ELSE
               REPLACE adresses_impactees->nb_fois   WITH adresses_impactees->nb_fois + 1
               REPLACE adresses_impactees->Montant   WITH adresses_impactees->Montant + outputs->Montant
            ENDIF

            SELE OUTPUTS
            SKIP
         ENDDO

         // SELE INPUTS
         // REPLACE INPUTS->adresse WITH OUTPUTS->adresse

         Inkey()
         IF LastKey() = 27
            SET COLOR TO "GR+*/R"
            @1, 70 SAY "Exit User"
            SET COLOR TO
            exit_user = .T.
            KEYBOARD Chr( 0 )
            // @20, 0 SAY "FIN : Arrêt Utilisateur"
            // QUIT
         ENDIF

         SELE transactions
         SKIP
      ENDDO
      lOk := hb_threadQuitRequest( pThID )
      CLOSE ALL

      // -------------------------------------------------
      // -------------------------------------------------
      // Phase 3 Calcul des soldes
      // -------------------------------------------------
      // -------------------------------------------------
      SetColor( "BG+/N" )
      @15, 0 SAY "Etape 3/" + nbre_etapes + "... Calcul des soldes, FI, LI, FO, LO, Nb Transactions"
      SET COLOR TO
      @16, 0 SAY "N° Trans  :"
      @18, 0 SAY "Trans/mn  :"

      // USE INPUTS INDEX NEW
      // USE OUTPUTS INDEX O_adresse NEW

      USE adresses_non_nulles INDEX AD_adresse NEW

      USE adresses_impactees INDEX AI_Adresse NEW
      GO BOTT
      Max_transaction = LTrim( Left( adresses_impactees->adresse, 10 ) )
      GO TOP

      GnMoyenne = 0
      SAI_duree = ""
      Transac_depart = 1
      Transac_Actuelle = 1
      nMax_Block = RecCount()
      pThID = hb_threadStart( @Ajout_traites(), @Transac_actuelle, @Transac_depart, @GnMoyenne, @nMax_block, @SAI_duree )

      Transac_actuelle = 0
      @16, 22 SAY "/" + Max_transaction
      @17, 0 SAY "Effectue  : "
      DO WHILE ! Eof()  // Balayage des adresses impactées dans le dernier traitement
         numero_transaction = Left( adresses_impactees->adresse, 10 )
         @16, 12 SAY numero_transaction
         TimeStamp = adresses_impactees->TimeStamp
         Table_adresses := {}
         // 3QzciaMyDbw5RX4sX8rkoK5PR7MpBhXZUn Tests
         // 1Jhk2DHosaaZx1E4CbnTGcKM7FC88YHYv9
         DO WHILE Left( adresses_impactees->adresse, 10 ) = numero_transaction  // On balaye toutes les adresses de la transaction
            Transac_actuelle++

            adresse_bitcoin = SubStr( adresses_impactees->adresse, 14 )
            input_output = SubStr( adresses_impactees->adresse, 12, 1 )
            Montant = adresses_impactees->Montant
            IF AScan( Table_adresses, adresse_bitcoin ) = 0
               AAdd( Table_adresses, adresse_bitcoin )
               Flag_ajoute_transaction = .T.
            ELSE
               Flag_ajoute_transaction = .F.
            ENDIF

            SELE adresses_non_nulles
            SEEK adresse_bitcoin
            IF ! Found()
               APPEND BLANK
               REPLACE adresses_non_nulles->adresse    WITH adresse_bitcoin
               IF input_output = "O"
                  REPLACE adresses_non_nulles->first_in   WITH TIMESTAMP
                  REPLACE adresses_non_nulles->last_in    WITH TIMESTAMP
                  REPLACE adresses_non_nulles->Nb_tr_IN   WITH 1
               ELSE
                  REPLACE adresses_non_nulles->first_out  WITH TIMESTAMP
                  REPLACE adresses_non_nulles->last_out   WITH TIMESTAMP
                  REPLACE adresses_non_nulles->Nb_tr_OUT  WITH 1
               ENDIF
               REPLACE adresses_non_nulles->MONTANT    WITH Montant
               REPLACE adresses_non_nulles->last_modif WITH TIMESTAMP
               REPLACE adresses_non_nulles->Nb_transac WITH 1
            ELSE
               IF input_output = "O"
                  REPLACE adresses_non_nulles->last_in    WITH TIMESTAMP
                  REPLACE adresses_non_nulles->MONTANT    WITH adresses_non_nulles->MONTANT + Montant
                  REPLACE adresses_non_nulles->Nb_tr_IN   WITH adresses_non_nulles->Nb_tr_IN + adresses_impactees->NB_fois
               ELSE
                  IF adresses_non_nulles->first_out = " "
                     REPLACE adresses_non_nulles->first_out WITH TIMESTAMP
                  ENDIF
                  REPLACE adresses_non_nulles->last_out   WITH TIMESTAMP
                  REPLACE adresses_non_nulles->Nb_tr_OUT  WITH adresses_non_nulles->Nb_tr_OUT + adresses_impactees->NB_fois
                  REPLACE adresses_non_nulles->MONTANT    WITH adresses_non_nulles->MONTANT + Montant
               ENDIF
               REPLACE adresses_non_nulles->last_modif WITH TIMESTAMP
               IF Flag_ajoute_transaction = .T.
                  REPLACE adresses_non_nulles->Nb_transac WITH adresses_non_nulles->Nb_transac + 1
               ENDIF
            ENDIF
            SELE adresses_impactees
            SKIP
         ENDDO

         Rpourcent = Str( ( Transac_actuelle * 100 / RecCount() ), 5, 1 )
         IF Rpourcent_actu <> Rpourcent
            @17, 12 SAY Rpourcent + " %"
            IF GnMoyenne > 0
               @18, 12 SAY Str( GnMoyenne, 7 ) + ", reste " + SAI_duree + "             "
            ENDIF
            Rpourcent_actu = RPourcent
         ENDIF

         SELE adresses_impactees

         Inkey()
         IF LastKey() = 27
            SET COLOR TO "GR+*/R"
            @1, 70 SAY "Exit User"
            SET COLOR TO
            exit_user = .T.
            KEYBOARD Chr( 0 )
         ENDIF

      ENDDO
      lOk := hb_threadQuitRequest( pThID )

      CLOSE ALL

      ligne_depart = 20

      SetColor( "BG+/N" )
      @ligne_depart, 0
      @ligne_depart, 0 SAY "Suppression des enregistrements inutiles dans les fichiers..."
      SET COLOR TO
      USE inputs
      ZAP
      INDEX ON INPUTS->ID_TRANS TO I_id_trans
      USE

      @ligne_depart + 1, 0
      @ligne_depart + 1, 0 SAY "Outputs, suppression des transactions received à 0.."
      USE outputs
      PACK
      @ligne_depart + 1, 0
      @ligne_depart + 1, 0 SAY "Outputs, Reconstruction de l'index 1..."
      INDEX ON OUTPUTS->tx_hash + Str( OUTPUTS->nu_output, 5 ) TO O_TxHash
      // @ligne_depart + 1, 0 SAY "Outputs, Reconstruction de l'index 2..."
      // INDEX ON OUTPUTS->adresse TO O_Adresse
      @ligne_depart + 1, 0 SAY "Outputs, Reconstruction de l'index 2..."
      INDEX ON OUTPUTS->ID_TRANS TO O_id_trans
      USE

      USE transactions
      ZAP

      CLOSE ALL
      IF exit_user = .T.
         EXIT
      ENDIF
   ENDDO

   USE ID_trans
   REPLACE ID_TRANS->ID_TRANS WITH ID_TRANSACTION_EN_COURS
   USE

   IF exit_user = .T.
      IF Reponse2( "Exportation des adresses dans le fichier soldes.csv ?", Row(), 0, "O" ) = "N"
         ?
         QUIT
      ENDIF
      @Row(), 0
   ENDIF

   SetColor( "BG+/N" )
   @ligne_depart, 0 clear
   IF Montants_a_partir_de = 0
      @ligne_depart, 0 SAY "Étape " + iif( nbre_etapes = "4", "4", "5" ) + "/" + nbre_etapes + "... Exportation vers soldes.csv pour les montants>0 satoshis"
   ELSE
      @ligne_depart, 0 SAY "Étape " + iif( nbre_etapes = "4", "4", "5" ) + "/" + nbre_etapes + "... Exportation vers soldes.csv pour les montants>=" + LTrim( Str( Montants_a_partir_de ) ) + " satoshis"
   ENDIF
   SET COLOR TO
   USE adresses_non_nulles
   IF Montants_a_partir_de > 0
      COPY FIELDS adresse, montant, last_modif TO soldes.csv FOR adresses_non_nulles->MONTANT >= Montants_a_partir_de delimited with ( { Chr( 34 ), ";", ";" } )
   ELSE
      COPY FIELDS adresse, montant, last_modif TO soldes.csv FOR adresses_non_nulles->MONTANT > Montants_a_partir_de delimited with ( { Chr( 34 ), ";", ";" } )
   ENDIF
   USE

   SET COLOR TO
   ?
   ?"FIN !!"
   ?

   // ********************************************************
   // Affiche Calcul du nombre de blocs traités / mn
   // ********************************************************

FUNCTION Ajout_traites( gnBloc_actuel, gnBloc_depart, GnMoyenne, Dernier_Bloc, SAI_duree )

   LOCAL i, total
   LOCAL Tourne := "-\|/"
   LOCAL table_traites := {}
   LOCAL jours := 0, heures, nMinutes, secondes, Nb_blocs_restant, rDuree_heure, Nb_blocs_traites

   hb_idleSleep( 60 )
   DO WHILE .T.
      Nb_blocs_traites = gnBloc_actuel - gnBloc_depart
      AAdd( table_traites, Nb_blocs_traites )
      IF Len( table_traites ) > 60
         hb_ADel( table_traites, 0, .T. )  // Supprime le 1er élément du tableau
      ENDIF
      total = 0
      // @15,0
      // ?len(table_traites)
      FOR i = 1 TO Len( table_traites )
         total += table_traites[ i ]
         // ??table_traites[i]
      NEXT
      GnMoyenne = total / Len( table_traites )

      IF GnMoyenne > 0
         Jours = 0
         Nb_blocs_restant = Dernier_bloc - gnBloc_actuel
         rDuree_heure = ( Nb_blocs_restant / GnMoyenne ) / 60
         nMinutes = Int( ( rDuree_heure - Int( rDuree_heure ) ) * 60 )
         // secondes = Int(  ( ( rDuree_heure - Int( rDuree_heure ) ) * 60 - nMinutes ) * 60 )
         heures = Int( rDuree_heure )

         IF heures >= 24
            jours = Int( heures / 24 )
            heures = Mod( heures, 24 )
         ENDIF
         IF jours > 0
            SAI_duree = LTrim( Str( jours, 3, 0 ) ) + "j " + LTrim( Str( heures, 3, 0 ) ) + "h "
         ELSE
            IF heures > 0
               SAI_duree = LTrim( Str( heures, 3, 0 ) ) + "h " + LTrim( Str( nMinutes, 3, 0 ) ) + "mn "
            ELSE
               IF nMinutes > 0
                  SAI_duree = LTrim( Str( nMinutes, 3, 0 ) ) + "mn "
               ELSE
                  SAI_duree = "Moins d'1 minute "
               ENDIF
            ENDIF
         ENDIF
      ENDIF

      gnBloc_depart = gnBloc_actuel
      hb_idleSleep( 60 )
   ENDDO

   RETURN NIL

// ********************************************************
// Affiche la date et l'heure en haut à droite
// ********************************************************
FUNCTION Show_Time()

   LOCAL cTime

   DO WHILE .T.
      cTime := DToC( Date() ) + " " + Left( Time(), 5 )
      hb_DispOutAt( 0, MaxCol() - Len( cTime ) + 1, cTime, "GR+/N" )
      hb_idleSleep( 60 )
   ENDDO

   RETURN NIL

// -----------------------------------------------------------------------------
// Saisie d'une reponse (Oui ou Non)
// -----------------------------------------------------------------------------
// !*****************************************************************************
// !
// !       Fonction: REPONSE2(Message,Ligne,Colonne,"O"/"N")
// !
// !***************************************************************************
FUNCTION reponse2( MESSAGE, ligne, COL, PARAM )

   LOCAL i

   IF Len( Trim( MESSAGE ) ) <> 0
      @ligne, COL CLEAR TO ligne, col + Len( message )
      // @ligne,COL
   ENDIF
   @ligne, COL SAY Trim( MESSAGE )
   COL = COL + Len( Trim( MESSAGE ) ) + 1
   PARAM = SubStr( Upper( PARAM ), 1, 1 )

   @ligne, COL SAY iif( PARAM = "O", "Oui", iif( PARAM = "N", "Non", iif( param = "A", "Abandon", " " ) ) )
   i = 0
   DO WHILE .T.
      @ligne, COL SAY ""
      KEYBOARD ""
      i = 0
      DO WHILE i <> 111 .AND. i <> 110 .AND. i <> 78 .AND. i <> 79 .AND. i <> 13 .AND. i <> 65 .AND. i <> 97
         i = Inkey()
      ENDDO
      IF i = 13
         IF PARAM = "N" .OR. PARAM = "O" .OR. param = "A"
            EXIT
         ENDIF
      ELSE
         PARAM = Upper( Chr( i ) )
         @ligne, COL SAY Space( 7 )
         @ligne, COL SAY iif( PARAM = "O", "Oui", iif( PARAM = "N", "Non", iif( param = "A", "Abandon", " " ) ) )
      ENDIF
   ENDDO

   RETURN ( PARAM )

// ********************************************************
// Recup chiffre dans le buffer, sur 4 octets
// ********************************************************
FUNCTION recup_chiffre_4_octets( buffer, position )
   RETURN Asc( SubStr( buffer, position, 1 ) ) + Asc( SubStr( buffer, position + 1, 1 ) ) * 256 + Asc( SubStr( buffer, position + 2, 1 ) ) * 65536 + Asc( SubStr( buffer, position + 3, 1 ) ) * 16777216

// ********************************************************
// Recup chiffre dans le buffer, sur 8 octets
// ********************************************************
FUNCTION recup_chiffre_8_octets( buffer, position )
   RETURN Asc( SubStr( buffer, position, 1 ) ) + Asc( SubStr( buffer, position + 1, 1 ) ) * 256 + Asc( SubStr( buffer, position + 2, 1 ) ) * 65536 + Asc( SubStr( buffer, position + 3, 1 ) ) * 16777216 + Asc( SubStr( buffer, position + 4, 1 ) ) * 256 ^ 4 + Asc( SubStr( buffer, position + 5, 1 ) ) * 256 ^ 5 + Asc( SubStr( buffer, position + 6, 1 ) ) * 256 ^ 6 + Asc( SubStr( buffer, position + 7, 1 ) ) * 256 ^ 7

// here is a function that read one text line from an open file
// nH = file handle obtained from FOpen()
// cB = a string buffer passed-by-reference to hold the result
// nMaxLine = maximum number of bytes to read
/*
STATIC FUNCTION FReadLn( nH, cB, nMaxLine )
   LOCAL cLine, nSavePos, nEol, nNumRead
   cLine := Space( nMaxLine )
   cB := ""
   nSavePos := FSeek( nH, 0, FS_RELATIVE )
   nNumRead := FRead( nH, @cLine, nMaxLine )
   IF ( nEol := hb_BAt( hb_eol(), hb_BLeft( cLine, nNumRead ) ) ) == 0
      cB := cLine
   ELSE
      cB := hb_BLeft( cLine, nEol - 1 )
      FSeek( nH, nSavePos + nEol + 1, FS_SET )
   ENDIF
   RETURN nNumRead != 0
*/

// The way the variable length integer works is:
// Look at the first byte
// If that first byte is less than 253, use the byte literally
// If that first byte is 253, read the next two bytes as a little endian 16-bit number (total bytes read = 3)
// If that first byte is 254, read the next four bytes as a little endian 32-bit number (total bytes read = 5)
// If that first byte is 255, read the next eight bytes as a little endian 64-bit number (total bytes read = 9)
//
FUNCTION Variable_length_integer( buffer, nPtr )

   LOCAL nVariable // est un entier sans signe sur 8 octet
   LOCAL nTemp     // est un entier sans signe sur 1 octet
   LOCAL nPointeur

   nTemp = Asc( SubStr( buffer, nPtr, 1 ) )

   nVariable = 0
   IF nTemp < 0xFD
      nVariable = nTemp
      nPointeur = 1
   ELSE
      IF nTemp = 0xFD
         nVariable = Asc( SubStr( buffer, nPtr + 1, 1 ) ) + Asc( SubStr( buffer, nPtr + 2, 1 ) ) * 256
         nPointeur = 3
      ELSE
         IF nTemp = 0xFE
            nVariable = Asc( SubStr( buffer, nPtr + 1, 1 ) ) + Asc( SubStr( buffer, nPtr + 2, 1 ) ) * 256 + Asc( SubStr( buffer, nPtr + 3, 1 ) ) * 65536 + Asc( SubStr( buffer, nPtr + 4, 1 ) ) * 16777216
            nPointeur = 5
         ELSE
            nVariable = Asc( SubStr( buffer, nPtr + 1, 1 ) ) + Asc( SubStr( buffer, nPtr + 2, 1 ) ) * 256 + Asc( SubStr( buffer, nPtr + 3, 1 ) ) * 65536 + Asc( SubStr( buffer, nPtr + 4, 1 ) ) * 16777216 + Asc( SubStr( buffer, nPtr + 5, 1 ) ) * 256 ^ 4 + Asc( SubStr( buffer, nPtr + 6, 1 ) ) * 256 ^ 5 + Asc( SubStr( buffer, nPtr + 7, 1 ) ) * 256 ^ 6 + Asc( SubStr( buffer, nPtr + 8, 1 ) ) * 256 ^ 7
            nPointeur = 9
         ENDIF
      ENDIF
   ENDIF
   nPtr += nPointeur

   RETURN nVariable

// Renvoie le timestamp format unix sous la forme AAAAMMJJHHMMSS
// ****************************************
FUNCTION TimeStampVersDateHeure( nTimeStamp )
   RETURN Left( hb_TToS( { ^ 1970 / 01 / 01 00:00:00 } + ( Asc( SubStr( nTimeStamp, 4, 1 ) ) * 16777216 + Asc( SubStr( nTimeStamp, 3, 1 ) ) * 65536 + Asc( SubStr( nTimeStamp, 2, 1 ) ) * 256 + Asc( SubStr( nTimeStamp, 1, 1 ) ) ) / 86400 ), 14 )

// Inverse une chaine
// *****************************
FUNCTION reverse( a )

   LOCAL b := "", i

   FOR i = Len( a ) TO 1 STEP -1
      b += SubStr( a, i, 1 )
   NEXT i

   RETURN b

// Hash 256 d'une chaine
// *******************************
FUNCTION HashChaine( type_hashage, chaine )

   LOCAL hash := ""
   LOCAL ctx

   IF type_hashage = 0  // SHA 256
      ctx := EVP_MD_CTX_create()
      EVP_MD_CTX_init( ctx )

      EVP_DigestInit_ex( ctx, "SHA256" )
      EVP_DigestUpdate( ctx, chaine )
      EVP_DigestFinal( ctx, @hash )
   ENDIF

   RETURN hash

// ---------------------------------------------
// Retourne l'adresse Btc correspondante au hash
// ---------------------------------------------
FUNCTION Base58_encode( chaine1, type_conv )

   LOCAL ctx

   LOCAL i
   LOCAL sEncoded
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
         chaine2 += Chr( hb_HexToNum( SubStr( chaine1, ( i - 1 ) * 2 + 1, 2 ) ) )
      NEXT
      type_conv = type_conv -5
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

// ---------------------------------------------------------
// Convertion rapide de la chaine Hexa en entrée en base 58
// Module en c pour gagner en rapidité (*10)
// ---------------------------------------------------------
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
