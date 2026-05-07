-- ============================================================================
-- SSI_TOOLS – IBM i Security Toolkit
-- Check ID      : IBMI-INV-006
-- Nom           : Inventory batch & technical dependencies
-- Domaine       : INV
-- Niveau        : SAFE
-- Type          : Inventory / PRA-PCA / Gouvernance
-- Exécution     : ACS / Run SQL Scripts
--
-- Objectif :
--   Identifier les dépendances batch visibles depuis SQL :
--   - jobs actifs non interactifs ;
--   - profils techniques utilisés par les jobs ;
--   - files de jobs ;
--   - jobs planifiés si les vues QSYS2 sont disponibles ;
--   - profils batch potentiellement critiques pour le PRA/PCA.
--
-- Pourquoi c’est important :
--   En IBM i, beaucoup de flux métiers reposent sur des batchs historiques.
--   Si on désactive un compte, change un mot de passe, coupe FTP/FTPS/SFTP,
--   modifie Kerberos ou bascule en PRA sans connaître ces dépendances :
--
--     LPAR OK, DB2 OK, sauvegarde OK... mais traitement métier KO.
--
--   Le grand classique : “ça tourne depuis 15 ans, personne ne sait pourquoi”.
--   Traduction SSI : dépendance fantôme.
--
-- Risque SSI :
--   - comptes techniques trop puissants ;
--   - batchs lancés avec profils utilisateurs humains ;
--   - jobs dépendants d’AD/Kerberos ;
--   - absence de cartographie PRA ;
--   - difficulté forensic après incident.
--
-- Impact niveau 40 :
--   En niveau 40, les droits implicites ou mal maîtrisés cassent plus vite.
--   Un batch doit avoir :
--   - un profil clair ;
--   - des droits explicites ;
--   - un owner maîtrisé ;
--   - des accès objets / IFS / certificats documentés.
--
-- Sécurité :
--   SAFE : uniquement SELECT.
--   Aucune modification.
--   Aucun QCMDEXC.
-- ============================================================================


-- ============================================================================
-- 1. Jobs actifs non interactifs
-- ============================================================================
-- Objectif :
--   Voir les traitements batch / serveurs / jobs techniques actuellement actifs.
--
-- Usage :
--   Export CSV depuis ACS pour construire la cartographie PRA/PCA.
-- ============================================================================

SELECT
    JOB_NAME,
    AUTHORIZATION_NAME        AS JOB_USER,
    JOB_TYPE,
    SUBSYSTEM,
    JOB_STATUS,
    FUNCTION_TYPE,
    FUNCTION,
    JOB_QUEUE_LIBRARY,
    JOB_QUEUE_NAME,
    ELAPSED_TOTAL_DISK_IO_COUNT,
    ELAPSED_CPU_PERCENTAGE,
    TEMPORARY_STORAGE
FROM QSYS2.ACTIVE_JOB_INFO
WHERE JOB_TYPE <> 'INTERACTIVE'
ORDER BY
    JOB_TYPE,
    AUTHORIZATION_NAME,
    JOB_NAME;


-- ============================================================================
-- 2. Profils utilisés par des jobs actifs non interactifs
-- ============================================================================
-- Objectif :
--   Identifier les comptes qui exécutent réellement des traitements.
--
-- Lecture SSI :
--   Si un profil apparaît ici, il ne doit jamais être désactivé ou modifié
--   sans validation OPS + métier.
-- ============================================================================

SELECT
    AUTHORIZATION_NAME        AS JOB_USER,
    COUNT(*)                  AS ACTIVE_JOB_COUNT,
    LISTAGG(DISTINCT JOB_TYPE, ', ')
        WITHIN GROUP (ORDER BY JOB_TYPE) AS JOB_TYPES,
    LISTAGG(DISTINCT SUBSYSTEM, ', ')
        WITHIN GROUP (ORDER BY SUBSYSTEM) AS SUBSYSTEMS
FROM QSYS2.ACTIVE_JOB_INFO
WHERE JOB_TYPE <> 'INTERACTIVE'
GROUP BY AUTHORIZATION_NAME
ORDER BY ACTIVE_JOB_COUNT DESC, JOB_USER;


-- ============================================================================
-- 3. Croisement profils batch actifs + posture sécurité du profil
-- ============================================================================
-- Objectif :
--   Voir si les comptes utilisés par les batchs sont :
--   - locaux ou dépendants AD/Kerberos ;
--   - à privilèges élevés ;
--   - sans groupe principal ;
--   - avec mot de passe non expirant.
--
-- PRA/PCA :
--   Un batch critique dépendant AD peut casser si AD/Kerberos est indisponible.
-- ============================================================================

WITH BATCH_USERS AS (
    SELECT DISTINCT
        AUTHORIZATION_NAME AS USER_NAME
    FROM QSYS2.ACTIVE_JOB_INFO
    WHERE JOB_TYPE <> 'INTERACTIVE'
)
SELECT
    U.AUTHORIZATION_NAME,
    U.STATUS,
    U.USER_CLASS_NAME,
    U.GROUP_PROFILE_NAME,
    U.SUPPLEMENTAL_GROUP_LIST,
    U.LOCAL_PASSWORD_MANAGEMENT,
    U.PASSWORD_EXPIRATION_INTERVAL,
    U.SPECIAL_AUTHORITIES,
    U.HOME_DIRECTORY,
    CASE
        WHEN U.LOCAL_PASSWORD_MANAGEMENT = 'NO'
            THEN 'AD/Kerberos dependent - PRA attention'
        WHEN U.LOCAL_PASSWORD_MANAGEMENT = 'YES'
            THEN 'Local IBM i password'
        ELSE 'Unknown'
    END AS PRA_AUTH_RISK,
    CASE
        WHEN U.SPECIAL_AUTHORITIES LIKE '%*ALLOBJ%'
          OR U.SPECIAL_AUTHORITIES LIKE '%*SECADM%'
            THEN 'HIGH PRIVILEGE'
        ELSE 'STANDARD / TO REVIEW'
    END AS SECURITY_RISK
FROM BATCH_USERS B
JOIN QSYS2.USER_INFO U
    ON U.AUTHORIZATION_NAME = B.USER_NAME
ORDER BY
    SECURITY_RISK DESC,
    PRA_AUTH_RISK,
    U.AUTHORIZATION_NAME;


-- ============================================================================
-- 4. Jobs actifs lancés avec des profils humains potentiels
-- ============================================================================
-- Objectif :
--   Détecter les batchs qui tournent sous des profils utilisateurs classiques.
--
-- Pourquoi :
--   Un batch sous compte nominatif = dette technique + risque forensic.
--   Le jour où la personne part, change de mot de passe, ou est désactivée :
--   “surprise du lundi matin”.
-- ============================================================================

SELECT
    A.JOB_NAME,
    A.AUTHORIZATION_NAME AS JOB_USER,
    A.JOB_TYPE,
    A.SUBSYSTEM,
    A.FUNCTION_TYPE,
    A.FUNCTION,
    U.USER_CLASS_NAME,
    U.GROUP_PROFILE_NAME,
    U.LOCAL_PASSWORD_MANAGEMENT,
    U.SPECIAL_AUTHORITIES,
    U.HOME_DIRECTORY
FROM QSYS2.ACTIVE_JOB_INFO A
JOIN QSYS2.USER_INFO U
    ON U.AUTHORIZATION_NAME = A.AUTHORIZATION_NAME
WHERE A.JOB_TYPE <> 'INTERACTIVE'
  AND SUBSTR(A.AUTHORIZATION_NAME, 1, 1) <> 'Q'
  AND U.GROUP_PROFILE_NAME = '*NONE'
ORDER BY
    A.AUTHORIZATION_NAME,
    A.JOB_NAME;


-- ============================================================================
-- 5. Files de jobs utilisées par les traitements actifs
-- ============================================================================
-- Objectif :
--   Identifier les JOBQ réellement utilisées.
--
-- PRA/PCA :
--   Une restauration technique sans JOBQ, subsystem ou autorité associée
--   peut empêcher les traitements de repartir.
-- ============================================================================

SELECT
    JOB_QUEUE_LIBRARY,
    JOB_QUEUE_NAME,
    COUNT(*) AS ACTIVE_JOBS,
    LISTAGG(DISTINCT AUTHORIZATION_NAME, ', ')
        WITHIN GROUP (ORDER BY AUTHORIZATION_NAME) AS JOB_USERS
FROM QSYS2.ACTIVE_JOB_INFO
WHERE JOB_TYPE <> 'INTERACTIVE'
  AND JOB_QUEUE_NAME IS NOT NULL
GROUP BY
    JOB_QUEUE_LIBRARY,
    JOB_QUEUE_NAME
ORDER BY
    ACTIVE_JOBS DESC,
    JOB_QUEUE_LIBRARY,
    JOB_QUEUE_NAME;


-- ============================================================================
-- 6. Synthèse PRA/PCA des dépendances batch visibles
-- ============================================================================
-- Objectif :
--   Obtenir une vue rapide pour comité SSI / PRA.
-- ============================================================================

SELECT
    CASE
        WHEN U.LOCAL_PASSWORD_MANAGEMENT = 'NO'
            THEN 'Batch dépendant AD/Kerberos'
        WHEN U.SPECIAL_AUTHORITIES LIKE '%*ALLOBJ%'
          OR U.SPECIAL_AUTHORITIES LIKE '%*SECADM%'
            THEN 'Batch avec profil privilégié'
        WHEN U.GROUP_PROFILE_NAME = '*NONE'
            THEN 'Batch sans groupe principal'
        ELSE 'Batch standard à documenter'
    END AS DEPENDENCY_CATEGORY,
    COUNT(DISTINCT A.AUTHORIZATION_NAME) AS DISTINCT_USERS,
    COUNT(*) AS ACTIVE_JOBS
FROM QSYS2.ACTIVE_JOB_INFO A
JOIN QSYS2.USER_INFO U
    ON U.AUTHORIZATION_NAME = A.AUTHORIZATION_NAME
WHERE A.JOB_TYPE <> 'INTERACTIVE'
GROUP BY
    CASE
        WHEN U.LOCAL_PASSWORD_MANAGEMENT = 'NO'
            THEN 'Batch dépendant AD/Kerberos'
        WHEN U.SPECIAL_AUTHORITIES LIKE '%*ALLOBJ%'
          OR U.SPECIAL_AUTHORITIES LIKE '%*SECADM%'
            THEN 'Batch avec profil privilégié'
        WHEN U.GROUP_PROFILE_NAME = '*NONE'
            THEN 'Batch sans groupe principal'
        ELSE 'Batch standard à documenter'
    END
ORDER BY ACTIVE_JOBS DESC;