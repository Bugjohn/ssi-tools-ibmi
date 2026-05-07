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
    JOB_NAME,
    JOB_DESCRIPTION_LIBRARY,
    JOB_DESCRIPTION,
    SCHEDULE_DATE,
    SCHEDULE_TIME,
    USER_NAME,
    COMMAND_TO_RUN
FROM QSYS2.SCHEDULED_JOB_INFO
ORDER BY SCHEDULE_DATE, SCHEDULE_TIME;

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
    JOB_NAME,
    USER_NAME,
    COMMAND_TO_RUN
FROM QSYS2.SCHEDULED_JOB_INFO
WHERE UPPER(COMMAND_TO_RUN) LIKE '%FTP%'
   OR UPPER(COMMAND_TO_RUN) LIKE '%QSH%'
   OR UPPER(COMMAND_TO_RUN) LIKE '%STRQSH%'
   OR UPPER(COMMAND_TO_RUN) LIKE '%SFTP%'
ORDER BY JOB_NAME;

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
------------------------------------------------------------------------------