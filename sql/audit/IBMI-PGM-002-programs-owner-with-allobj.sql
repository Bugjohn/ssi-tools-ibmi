-- ============================================================================
-- SSI_TOOLS – IBM i Security Toolkit
-- ============================================================================
-- CHECK_ID      : IBMI-PGM-002
-- NOM           : Programmes possédés par un owner avec *ALLOBJ
-- DOMAINE       : PGM / AUTH
-- CLASSIFICATION: SAFE
-- TYPE          : AUDIT / PRIVILEGE EXPOSURE
-- EXECUTION     : ACS - Run SQL Scripts
--
-- OBJECTIF
-- --------
-- Identifier les programmes applicatifs dont le propriétaire possède
-- l’autorité spéciale *ALLOBJ.
--
-- Pourquoi ?
-- Parce qu’un programme IBM i peut adopter les droits de son owner.
-- Si cet owner possède *ALLOBJ, le programme peut devenir un raccourci
-- extrêmement puissant vers tout le système.
--
-- Phrase simple :
--   Owner *ALLOBJ + programme USRPRF(*OWNER) =
--   cocktail maison façon “admin invisible dans un programme métier”.
--
--
-- RISQUE SSI
-- ----------
-- *ALLOBJ est l’une des autorités les plus sensibles sur IBM i.
--
-- Un profil avec *ALLOBJ peut accéder à quasiment tous les objets du système.
-- C’est parfois nécessaire pour certains profils d’administration.
-- Mais ce n’est normalement PAS un modèle sain pour un owner applicatif.
--
-- Risques classiques :
--   - élévation de privilèges indirecte ;
--   - contournement des droits objets ;
--   - programme métier transformé en point d’entrée admin ;
--   - difficulté à expliquer les droits réels en audit ;
--   - exposition majeure si le programme est modifiable ;
--   - impact fort en cas de compromission d’un compte applicatif.
--
--
-- RAPPEL TERRAIN IBM i
-- -------------------
-- Historiquement, certains environnements ont utilisé des owners très puissants
-- pour “que l’application fonctionne”.
--
-- Traduction exploitation :
--   “On lui met *ALLOBJ, comme ça on n’a plus d’erreur d’autorité.”
--
-- Traduction SSI :
--   “On a remplacé un problème de droits par un problème d’audit.”
--
-- Ça marche.
-- Jusqu’au jour où on veut passer niveau 40, auditer proprement,
-- réduire *PUBLIC, ou expliquer les accès à un auditeur externe.
--
--
-- IMPACT NIVEAU 40
-- ----------------
-- En préparation niveau 40, les programmes doivent être revus avec attention :
--
--   - le programme adopte-t-il les droits owner ?
--   - l’owner est-il technique ?
--   - l’owner possède-t-il *ALLOBJ ?
--   - le programme est-il modifiable par *PUBLIC ?
--   - les objets appelés sont-ils correctement protégés ?
--
-- Modèle cible :
--   - owner technique dédié ;
--   - droits minimaux nécessaires ;
--   - *PUBLIC *EXCLUDE ;
--   - accès via groupes ;
--   - droits centralisés par *AUTL ;
--   - *ALLOBJ réservé à quelques profils admin clairement documentés.
--
--
-- PRE-CHECK
-- ---------
-- Lecture seule.
-- Ce script croise :
--   - QSYS2.OBJECT_STATISTICS pour les programmes ;
--   - QSYS2.USER_INFO pour les autorités spéciales du propriétaire.
--
--
-- DRYRUN
-- ------
-- Non applicable : audit uniquement.
--
--
-- EXECUTE
-- -------
-- Exécuter dans ACS / Run SQL Scripts.
--
--
-- LOGGING
-- -------
-- Aucun logging applicatif.
-- Export CSV recommandé pour dossier SSI / niveau 40.
--
--
-- ROLLBACK
-- --------
-- Non applicable : aucune modification.
--
--
-- EXPORT CSV
-- ----------
-- ACS :
-- clic droit sur le résultat -> Export Results -> CSV.
-- ============================================================================


-- ============================================================================
-- 1. PRE-CHECK – Vérifier les programmes applicatifs
-- ============================================================================

SELECT *
FROM TABLE(QSYS2.OBJECT_STATISTICS('*ALLUSR', '*PGM')) AS P
FETCH FIRST 10 ROWS ONLY;


-- ============================================================================
-- 2. PRE-CHECK – Vérifier les owners avec *ALLOBJ
-- ============================================================================
-- Cette requête permet de voir les profils possédant *ALLOBJ.
-- Elle aide à comprendre pourquoi certains programmes vont ressortir ensuite.
-- ============================================================================

SELECT
    AUTHORIZATION_NAME,
    STATUS,
    USER_CLASS_NAME,
    GROUP_PROFILE_NAME,
    SPECIAL_AUTHORITIES
FROM QSYS2.USER_INFO
WHERE SPECIAL_AUTHORITIES LIKE '%*ALLOBJ%'
ORDER BY AUTHORIZATION_NAME;


-- ============================================================================
-- 3. AUDIT – Programmes dont l’owner possède *ALLOBJ
-- ============================================================================
-- À traiter en priorité si :
--   - le programme est en USRPRF(*OWNER) ;
--   - le programme est dans une bibliothèque applicative critique ;
--   - le programme est modifiable par trop de monde ;
--   - l’owner est un profil humain ;
--   - l’owner est désactivé ou mal documenté.
--
-- Ce script n’affirme pas que le programme est exploitable.
-- Il identifie une combinaison dangereuse à qualifier.
-- ============================================================================

SELECT
    P.OBJLIB                    AS PROGRAM_LIBRARY,
    P.OBJNAME                   AS PROGRAM_NAME,
    P.OBJTYPE                   AS OBJECT_TYPE,
    P.OBJATTRIBUTE              AS PROGRAM_ATTRIBUTE,
    P.OBJOWNER                  AS PROGRAM_OWNER,
    P.TEXT_DESCRIPTION          AS TEXT_DESCRIPTION,

    U.STATUS                    AS OWNER_STATUS,
    U.USER_CLASS_NAME           AS OWNER_USER_CLASS,
    U.GROUP_PROFILE_NAME        AS OWNER_GROUP_PROFILE,
    U.SPECIAL_AUTHORITIES       AS OWNER_SPECIAL_AUTHORITIES,

    'CRITICAL'                  AS SEVERITY,

    'Programme possédé par un profil *ALLOBJ : vérifier adopted authority, droits *PUBLIC et justification owner.'
                                AS SSI_COMMENT

FROM TABLE(QSYS2.OBJECT_STATISTICS('*ALLUSR', '*PGM')) AS P

JOIN QSYS2.USER_INFO U
    ON U.AUTHORIZATION_NAME = P.OBJOWNER

WHERE U.SPECIAL_AUTHORITIES LIKE '%*ALLOBJ%'

ORDER BY
    PROGRAM_LIBRARY,
    PROGRAM_NAME;