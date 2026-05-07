-- ============================================================================
-- SSI_TOOLS – IBM i Security Toolkit
-- ============================================================================
-- CHECK_ID      : IBMI-PGM-001
-- NOM           : Programmes possédés par des profils utilisateurs
-- DOMAINE       : PGM
-- CLASSIFICATION: SAFE
-- TYPE          : AUDIT / GOVERNANCE
-- EXECUTION     : ACS - Run SQL Scripts
--
-- OBJECTIF
-- --------
-- Identifier les programmes applicatifs dont le propriétaire semble être
-- un profil utilisateur nominatif plutôt qu’un profil technique maîtrisé.
--
-- Pourquoi ?
-- Parce qu’un programme IBM i n’est pas qu’un fichier exécutable.
-- Son owner peut influencer :
--   - les droits effectifs ;
--   - l’adopted authority ;
--   - le comportement applicatif ;
--   - la sécurité niveau 40 ;
--   - la maintenabilité.
--
-- Et quand un programme critique appartient encore à JEANDUPONT,
-- parti depuis 2014, on n’est plus dans l’héritage applicatif.
-- On est dans l’archéologie opérationnelle 😅
--
--
-- RISQUE SSI
-- ----------
-- Un programme possédé par un profil humain pose plusieurs problèmes :
--
--   1. Départ du collaborateur
--      Le profil peut être désactivé, supprimé ou modifié.
--
--   2. Droits imprévisibles
--      Si le programme adopte les droits de son owner, il peut hériter
--      de droits non documentés.
--
--   3. Owner trop puissant
--      Si le profil possède *ALLOBJ, le programme peut devenir un vecteur
--      d’élévation de privilèges.
--
--   4. Gouvernance faible
--      Il devient difficile d’expliquer pourquoi ce programme appartient
--      à ce profil.
--
--
-- IMPACT NIVEAU 40
-- ----------------
-- En préparation niveau 40, le modèle recommandé est :
--
--   Programmes applicatifs -> owner technique dédié
--   Owner technique        -> droits minimaux nécessaires
--   Utilisateurs           -> groupes
--   Objets                 -> *PUBLIC *EXCLUDE
--   Gouvernance            -> *AUTL
--
-- Objectif :
-- remplacer progressivement les owners humains par des profils techniques
-- documentés : APP_OWNER, FIN_OWNER, BATCH_OWNER, etc.
--
--
-- PRE-CHECK
-- ---------
-- Lecture seule.
-- Aucune modification.
--
-- DRYRUN
-- ------
-- Non applicable.
--
-- EXECUTE
-- -------
-- Exécuter dans ACS / Run SQL Scripts.
--
-- LOGGING
-- -------
-- Aucun logging applicatif.
-- Export CSV recommandé.
--
-- ROLLBACK
-- --------
-- Non applicable.
--
-- EXPORT CSV
-- ----------
-- ACS -> clic droit -> Export Results -> CSV.
-- ============================================================================


-- ============================================================================
-- 1. PRE-CHECK – Voir quelques programmes applicatifs
-- ============================================================================

SELECT *
FROM TABLE(QSYS2.OBJECT_STATISTICS('*ALLUSR', '*PGM')) AS P
FETCH FIRST 10 ROWS ONLY;


-- ============================================================================
-- 2. AUDIT – Programmes possédés par des profils non système
-- ============================================================================
-- Cette requête liste les programmes dont l’owner ne commence pas par Q.
--
-- Ce n’est PAS automatiquement une anomalie.
-- Il faut qualifier :
--   - owner humain ?
--   - owner technique ?
--   - profil encore actif ?
--   - possède-t-il *ALLOBJ ?
--   - programme en USRPRF(*OWNER) ?
--   - bibliothèque critique ?
-- ============================================================================

SELECT
    P.OBJLIB                    AS PROGRAM_LIBRARY,
    P.OBJNAME                   AS PROGRAM_NAME,
    P.OBJTYPE                   AS OBJECT_TYPE,
    P.OBJOWNER                  AS PROGRAM_OWNER,
    P.OBJATTRIBUTE              AS PROGRAM_ATTRIBUTE,
    P.TEXT_DESCRIPTION          AS TEXT_DESCRIPTION,

    U.STATUS                    AS OWNER_STATUS,
    U.USER_CLASS_NAME           AS OWNER_USER_CLASS,
    U.GROUP_PROFILE_NAME        AS OWNER_GROUP_PROFILE,
    U.SPECIAL_AUTHORITIES       AS OWNER_SPECIAL_AUTHORITIES,

    CASE
        WHEN U.SPECIAL_AUTHORITIES LIKE '%*ALLOBJ%' THEN 'CRITICAL'
        WHEN U.STATUS = '*DISABLED' THEN 'HIGH'
        ELSE 'MEDIUM'
    END                         AS SEVERITY,

    CASE
        WHEN U.SPECIAL_AUTHORITIES LIKE '%*ALLOBJ%' THEN
            'Owner avec *ALLOBJ : risque majeur si programme avec droits adoptés.'
        WHEN U.STATUS = '*DISABLED' THEN
            'Owner désactivé : dette historique ou profil humain probable.'
        ELSE
            'Owner non système : vérifier s’il s’agit d’un profil technique documenté.'
    END                         AS SSI_COMMENT

FROM TABLE(QSYS2.OBJECT_STATISTICS('*ALLUSR', '*PGM')) AS P

LEFT JOIN QSYS2.USER_INFO U
    ON U.AUTHORIZATION_NAME = P.OBJOWNER

WHERE P.OBJOWNER NOT LIKE 'Q%'

ORDER BY
    SEVERITY,
    PROGRAM_LIBRARY,
    PROGRAM_NAME;