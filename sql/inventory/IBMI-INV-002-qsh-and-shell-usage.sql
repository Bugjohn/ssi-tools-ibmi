------------------------------------------------------------------------------
-- CHECK ID     : IBMI-INV-002
-- CHECK NAME   : QSH and Shell Usage Inventory
-- DOMAIN       : OPS
-- LEVEL        : SAFE
--
-- DESCRIPTION
-- -----------
-- Inventaire des usages QSH / STRQSH / shell.
--
-- OBJECTIFS SSI
-- --------------
-- - Identifier scripts shell
-- - Identifier dépendances Linux/PASE
-- - Préparer migration SSH/SFTP
-- - Préparer forensic
--
-- CONTEXTE IBM i
-- ---------------
-- IBM i peut exécuter :
--
-- - QShell
-- - PASE
-- - bash
-- - scripts shell Linux
--
-- Beaucoup d’admins Windows découvrent ça avec surprise 😅
--
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- SECTION 1
-- Jobs actifs utilisant QSH
------------------------------------------------------------------------------

SELECT
    JOB_NAME,
    JOB_USER,
    JOB_STATUS,
    SUBSYSTEM,
    FUNCTION_TYPE,
    FUNCTION
FROM TABLE(QSYS2.ACTIVE_JOB_INFO()) AS A
WHERE UPPER(FUNCTION) LIKE '%QSH%'
   OR UPPER(FUNCTION) LIKE '%PASE%'
ORDER BY JOB_NAME;

------------------------------------------------------------------------------
-- SECTION 2
-- Jobs planifiés utilisant shell
------------------------------------------------------------------------------

SELECT
    SCHEDULED_JOB_NAME AS JOB_NAME,
    STATUS,
    USER_PROFILE_FOR_SUBMITTED_JOB AS RUN_AS_USER,
    SCHEDULED_BY,
    JOB_QUEUE_LIBRARY_NAME AS JOBQ_LIB,
    JOB_QUEUE_NAME AS JOBQ,
    NEXT_SUBMISSION_DATE,
    COMMAND_STRING
FROM QSYS2.SCHEDULED_JOB_INFO
WHERE UPPER(COMMAND_STRING) LIKE '%QSH%'
   OR UPPER(COMMAND_STRING) LIKE '%STRQSH%'
   OR UPPER(COMMAND_STRING) LIKE '%SH %'
   OR UPPER(COMMAND_STRING) LIKE '%BASH%'
ORDER BY SCHEDULED_JOB_NAME;

------------------------------------------------------------------------------
-- SECTION 3
-- Risques SSI
------------------------------------------------------------------------------
--
-- Vérifier :
--
-- 1. Scripts documentés ?
-- 2. Scripts sauvegardés PRA ?
-- 3. Comptes techniques protégés ?
-- 4. Clés SSH présentes ?
-- 5. Scripts externes montés via NFS/QNTC ?
--
-- Cas fréquent :
--
-- script shell critique :
-- - dans /home
-- - sans sauvegarde ;
-- - créé par ancien presta 😅
--
------------------------------------------------------------------------------