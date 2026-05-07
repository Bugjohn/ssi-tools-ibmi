-- ============================================================================
-- SSI_TOOLS – IBM i Security Toolkit
-- ============================================================================
-- CHECK_ID      : IBMI-OBJ-001
-- NOM           : Objets exposés à *PUBLIC
-- DOMAINE       : OBJ
-- CLASSIFICATION: SAFE
-- TYPE          : AUDIT / INVENTORY
-- EXECUTION     : ACS - Run SQL Scripts
--
-- OBJECTIF
-- --------
-- Identifier les objets IBM i sur lesquels *PUBLIC possède une autorité
-- excessive : *CHANGE ou *ALL.
--
-- RISQUE SSI
-- ----------
-- Sur IBM i, le vrai danger n’est pas uniquement la bibliothèque ouverte :
-- c’est surtout l’objet métier à l’intérieur.
--
-- Une bibliothèque en *PUBLIC *CHANGE, c’est déjà la porte du garage ouverte.
-- Un fichier, un programme ou une table en *PUBLIC *ALL, c’est la clé sur le
-- contact avec un petit mot : "soyez raisonnables".
--
-- Ce contrôle est important pour :
-- - réduire la dette historique IBM i ;
-- - préparer un passage progressif vers un modèle niveau 40 ;
-- - identifier les objets à rattacher à des groupes ou à des listes
--   d’autorisation (*AUTL) ;
-- - documenter les corrections avant toute remédiation.
--
-- PRE-CHECK
-- ---------
-- Ce script utilise QSYS2.OBJECT_PRIVILEGES.
-- Il est en lecture seule.
-- Aucune modification n’est effectuée.
--
-- DRYRUN
-- ------
-- Non applicable : ce script est uniquement un SELECT.
--
-- EXECUTE
-- -------
-- Exécuter tel quel dans ACS / Run SQL Scripts.
--
-- LOGGING
-- -------
-- Aucun logging applicatif : audit en lecture seule.
-- Exporter les résultats en CSV pour conservation SSI.
--
-- ROLLBACK
-- --------
-- Non applicable : aucune action corrective.
--
-- EXPORT CSV
-- ----------
-- Dans ACS :
-- clic droit sur le résultat -> Export Results -> CSV.
-- ============================================================================


-- ============================================================================
-- 1. PRE-CHECK – Vérifier les colonnes disponibles
-- ============================================================================
-- Selon les versions IBM i / TR, certaines colonnes peuvent varier.
-- Cette requête permet de confirmer la structure exacte de la vue.
-- ============================================================================

SELECT
    COLUMN_NAME
FROM QSYS2.SYSCOLUMNS
WHERE TABLE_SCHEMA = 'QSYS2'
  AND TABLE_NAME   = 'OBJECT_PRIVILEGES'
ORDER BY ORDINAL_POSITION;


-- ============================================================================
-- 2. AUDIT – Objets exposés à *PUBLIC avec *CHANGE ou *ALL
-- ============================================================================
-- Cette requête liste tous les objets pour lesquels *PUBLIC dispose d’un droit
-- élevé.
--
-- Interprétation rapide :
-- - *ALL    : critique, contrôle total sur l’objet.
-- - *CHANGE : fort risque, modification possible.
--
-- Attention :
-- certains objets peuvent être volontairement ouverts pour des raisons
-- applicatives historiques. On ne corrige PAS brutalement.
-- On analyse, on qualifie, on documente, puis seulement ensuite on remédie.
-- ============================================================================

SELECT
    SYSTEM_OBJECT_SCHEMA              AS OBJECT_LIBRARY,
    SYSTEM_OBJECT_NAME                AS OBJECT_NAME,
    OBJECT_TYPE                       AS OBJECT_TYPE,
    AUTHORIZATION_NAME                AS GRANTEE,
    OBJECT_AUTHORITY                  AS OBJECT_AUTHORITY,

    OWNER                             AS OWNER,
    PRIMARY_GROUP                     AS PRIMARY_GROUP,
    AUTHORIZATION_LIST                AS AUTHORIZATION_LIST,

    OBJECT_OPERATIONAL                AS OBJECT_OPERATIONAL,
    OBJECT_MANAGEMENT                 AS OBJECT_MANAGEMENT,
    OBJECT_EXISTENCE                  AS OBJECT_EXISTENCE,
    OBJECT_ALTER                      AS OBJECT_ALTER,
    OBJECT_REFERENCE                  AS OBJECT_REFERENCE,

    DATA_READ                         AS DATA_READ,
    DATA_ADD                          AS DATA_ADD,
    DATA_UPDATE                       AS DATA_UPDATE,
    DATA_DELETE                       AS DATA_DELETE,
    DATA_EXECUTE                      AS DATA_EXECUTE,

    TEXT_DESCRIPTION                  AS TEXT_DESCRIPTION,

    CASE
        WHEN OBJECT_AUTHORITY = '*ALL'
            THEN 'CRITICAL'
        WHEN OBJECT_AUTHORITY = '*CHANGE'
            THEN 'HIGH'
        ELSE 'INFO'
    END                               AS SEVERITY,

    CASE
        WHEN OBJECT_AUTHORITY = '*ALL'
            THEN 'PUBLIC dispose de *ALL : contrôle très large sur l''objet.'
        WHEN OBJECT_AUTHORITY = '*CHANGE'
            THEN 'PUBLIC dispose de *CHANGE : modification possible, à qualifier.'
        ELSE 'Autorité non prioritaire.'
    END                               AS SSI_COMMENT

FROM QSYS2.OBJECT_PRIVILEGES

WHERE AUTHORIZATION_NAME = '*PUBLIC'
  AND OBJECT_AUTHORITY IN ('*CHANGE', '*ALL')

ORDER BY
    CASE
        WHEN OBJECT_AUTHORITY = '*ALL' THEN 1
        WHEN OBJECT_AUTHORITY = '*CHANGE' THEN 2
        ELSE 9
    END,
    SYSTEM_OBJECT_SCHEMA,
    SYSTEM_OBJECT_NAME,
    OBJECT_TYPE;