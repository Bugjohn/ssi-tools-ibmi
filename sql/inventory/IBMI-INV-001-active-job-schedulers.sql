------------------------------------------------------------------------------
-- CHECK ID     : IBMI-INV-001
-- CHECK NAME   : Active Job Schedulers Inventory
-- DOMAIN       : OPS
-- LEVEL        : SAFE
--
-- DESCRIPTION
-- -----------
-- Inventaire des jobs planifiés IBM i.
--
-- OBJECTIFS SSI
-- --------------
-- - Identifier batchs critiques
-- - Identifier dépendances PRA/PCA
-- - Identifier automatisations oubliées
-- - Préparer forensic
--
-- CONTEXTE IBM i
-- ---------------
-- IBM i exécute énormément de traitements planifiés :
--
-- - batchs RPG
-- - exports
-- - EDI
-- - FTP/SFTP
-- - scripts shell
-- - synchronisations
--
-- Très fréquent :
--
-- personne ne sait :
-- - qui a créé le job ;
-- - pourquoi il tourne ;
-- - ce qu’il transfère 😅
--
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- SECTION 1
-- Inventaire WRKJOBSCDE
------------------------------------------------------------------------------
--
-- Les job schedulers IBM i sont souvent :
--
-- - critiques métier ;
-- - très anciens ;
-- - peu documentés.
--
------------------------------------------------------------------------------

SELECT
    SCHEDULED_JOB_NAME                  AS JOB_NAME,
    JOB_DESCRIPTION_LIBRARY_NAME       AS JOBD_LIB,
    JOB_DESCRIPTION_NAME               AS JOBD,
    SCHEDULED_DATE,
    SCHEDULED_TIME,
    USER_PROFILE_FOR_SUBMITTED_JOB     AS RUN_AS_USER,
    SCHEDULED_BY,
    STATUS,
    COMMAND_STRING
FROM QSYS2.SCHEDULED_JOB_INFO
ORDER BY SCHEDULED_DATE, SCHEDULED_TIME;

------------------------------------------------------------------------------
-- SECTION 2
-- Recherche jobs sensibles
------------------------------------------------------------------------------
--
-- Recherche :
-- - FTP
-- - QSH
-- - STRQSH
-- - scripts shell
-- - transferts
--
------------------------------------------------------------------------------

SELECT
    SCHEDULED_JOB_NAME          AS JOB_NAME,
    SCHEDULED_BY,
    USER_PROFILE_FOR_SUBMITTED_JOB AS RUN_AS_USER,
    STATUS,
    JOB_QUEUE_LIBRARY_NAME      AS JOBQ_LIB,
    JOB_QUEUE_NAME              AS JOBQ,
    NEXT_SUBMISSION_DATE,
    LAST_SUCCESSFUL_SUBMISSION_TIMESTAMP,
    COMMAND_STRING
FROM QSYS2.SCHEDULED_JOB_INFO
WHERE UPPER(COMMAND_STRING) LIKE '%FTP%'
   OR UPPER(COMMAND_STRING) LIKE '%QSH%'
   OR UPPER(COMMAND_STRING) LIKE '%STRQSH%'
   OR UPPER(COMMAND_STRING) LIKE '%SFTP%'
ORDER BY SCHEDULED_JOB_NAME;
------------------------------------------------------------------------------
-- SECTION 3
-- Risques SSI
------------------------------------------------------------------------------
--
-- Vérifier :
--
-- 1. Job encore utile ?
-- 2. Flux documenté ?
-- 3. Compte technique connu ?
-- 4. Dépendance FTP ?
-- 5. Dépendance SSH ?
-- 6. Dépendance certificat ?
--
-- Cas classique :
--
-- vieux batch :
-- - personne ne connait le script ;
-- - mais si on le coupe :
--   production KO 😅
--
--
-- DEBUG
-- Il se peut que sur votre machine le nom des colonnes diffèrent ou sont absentes
-- dans ce cas, il suffit de lancer :
SELECT COLUMN_NAME
FROM QSYS2.SYSCOLUMNS
WHERE TABLE_SCHEMA = 'QSYS2'
  AND TABLE_NAME = 'SCHEDULED_JOB_INFO'
ORDER BY ORDINAL_POSITION;
--
--Puis adapter votre requête
------------------------------------------------------------------------------