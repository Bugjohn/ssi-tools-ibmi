-- ============================================================================
-- SSI_TOOLS – IBM i Security Toolkit
-- ============================================================================
-- CHECK_ID      : IBMI-OBJ-002
-- NOM           : Programmes adoptant les droits de leur owner
-- DOMAINE       : OBJ / PGM
-- CLASSIFICATION: SAFE
-- TYPE          : AUDIT / INVENTORY
-- EXECUTION     : ACS - Run SQL Scripts
--
-- OBJECTIF
-- --------
-- Identifier les programmes IBM i configurés avec USRPRF(*OWNER).
--
-- Pourquoi c’est important ?
-- Parce qu’un programme USRPRF(*OWNER) n’exécute pas seulement avec les droits
-- de l’utilisateur qui le lance. Il adopte aussi les droits de son propriétaire.
--
-- Phrase à retenir :
--   Le programme qui adopte les droits de son owner devient une extension
--   des privilèges de cet owner.
--
-- Et là, sur IBM i, on entre dans la zone “ça marche depuis 20 ans, donc
-- personne n’ose toucher”
--
--
-- RISQUE SSI
-- ----------
-- Sur IBM i, un programme peut être configuré de deux grandes manières :
--
--   USRPRF(*USER)
--     Le programme s’exécute avec les droits de l’utilisateur appelant.
--     C’est le comportement le plus simple à comprendre.
--
--   USRPRF(*OWNER)
--     Le programme adopte les droits du profil propriétaire du programme.
--     Cela permet à un utilisateur de réaliser une action sans avoir lui-même
--     les droits directs sur les objets appelés.
--
-- Exemple terrain :
--   - l’utilisateur JEAN lance un programme de facturation ;
--   - JEAN n’a pas directement accès aux fichiers sensibles ;
--   - le programme appartient à APP_OWNER ;
--   - le programme est en USRPRF(*OWNER) ;
--   - le programme peut accéder aux fichiers via les droits de APP_OWNER.
--
-- Ce mécanisme peut être légitime.
-- Mais s’il est mal maîtrisé, il devient une élévation de privilèges.
--
-- Points dangereux :
--   - owner avec *ALLOBJ ;
--   - owner profil humain au lieu d’un profil technique ;
--   - owner supprimé ou historique ;
--   - programme modifiable par trop de monde ;
--   - *PUBLIC avec *CHANGE ou *ALL sur le programme ;
--   - absence de groupe ou de liste d’autorisation (*AUTL) ;
--   - dépendance implicite qui casse lors du passage au niveau 40.
--
--
-- IMPACT NIVEAU 40
-- ----------------
-- Le niveau 40 renforce le respect des autorités objets.
-- Ce qui “passait par magie” en niveau 20 peut échouer en niveau 40.
--
-- Les programmes adoptant les droits doivent donc être revus avant migration :
--   - owner correct ?
--   - droits explicites ?
--   - *PUBLIC maîtrisé ?
--   - groupes cohérents ?
--   - *AUTL utilisée ?
--   - programme modifiable uniquement par les bons profils ?
--
-- Objectif cible :
--   Utilisateurs  -> Groupes
--   Groupes       -> Droits sur objets
--   Objets        -> *PUBLIC *EXCLUDE
--   Droits        -> centralisés via *AUTL
--   Programmes    -> owner technique maîtrisé
--
--
-- PRE-CHECK
-- ---------
-- Ce script utilise QSYS2.OBJECT_STATISTICS.
-- Il est en lecture seule.
-- Aucune modification n’est effectuée.
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
-- Exporter le résultat CSV pour analyse SSI / niveau 40.
--
--
-- ROLLBACK
-- --------
-- Non applicable : aucune action corrective.
--
--
-- EXPORT CSV
-- ----------
-- Dans ACS :
-- clic droit sur le résultat -> Export Results -> CSV.
-- ============================================================================


-- ============================================================================
-- 1. PRE-CHECK – Vérifier les colonnes disponibles
-- ============================================================================
-- Selon la version IBM i / TR, certaines colonnes peuvent varier.
-- On commence donc par inspecter la structure retournée par OBJECT_STATISTICS.
-- ============================================================================

SELECT *
FROM TABLE(QSYS2.OBJECT_STATISTICS('*ALLUSR', '*PGM')) AS P
FETCH FIRST 10 ROWS ONLY;


-- ============================================================================
-- 2. AUDIT – Programmes adoptant les droits du propriétaire
-- ============================================================================
-- Cette requête liste les programmes applicatifs avec USRPRF(*OWNER).
--
-- À analyser en priorité :
--   - programmes dont le propriétaire possède *ALLOBJ ;
--   - programmes possédés par un profil utilisateur nominatif ;
--   - programmes anciens ou sans description ;
--   - programmes modifiables par *PUBLIC ou par trop de profils ;
--   - programmes situés dans des bibliothèques applicatives critiques.
--
-- Attention :
-- USRPRF(*OWNER) n’est pas forcément une erreur.
-- C’est un mécanisme IBM i historique et parfois nécessaire.
-- Le problème, c’est l’absence de gouvernance autour.
-- ============================================================================

SELECT
    OBJLIB              AS PROGRAM_LIBRARY,
    OBJNAME             AS PROGRAM_NAME,
    OBJTYPE             AS OBJECT_TYPE,
    OBJOWNER            AS PROGRAM_OWNER,
    OBJATTRIBUTE        AS PROGRAM_ATTRIBUTE,
    TEXT_DESCRIPTION    AS TEXT_DESCRIPTION,

    CASE
        WHEN OBJOWNER LIKE 'Q%' THEN 'MEDIUM'
        ELSE 'HIGH'
    END                 AS SEVERITY,

    CASE
        WHEN OBJOWNER LIKE 'Q%' THEN
            'Programme USRPRF(*OWNER) possédé par un profil système : à vérifier avec prudence.'
        ELSE
            'Programme USRPRF(*OWNER) : vérifier owner, droits, *PUBLIC, groupes et *AUTL.'
    END                 AS SSI_COMMENT

FROM TABLE(QSYS2.OBJECT_STATISTICS('*ALLUSR', '*PGM')) AS P

WHERE USER_PROFILE = '*OWNER'

ORDER BY
    PROGRAM_LIBRARY,
    PROGRAM_NAME;