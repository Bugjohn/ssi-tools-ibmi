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
    AUTHORIZATION_NAME,
    FUNCTION,
    SUBSYSTEM
FROM TABLE(QSYS2.ACTIVE_JOB_INFO())
WHERE FUNCTION LIKE '%QSH%'
   OR FUNCTION LIKE '%PASE%'
ORDER BY JOB_NAME;

------------------------------------------------------------------------------
-- SECTION 2
-- Jobs planifiés utilisant shell
------------------------------------------------------------------------------

SELECT
    JOB_NAME,
    USER_NAME,
    COMMAND_TO_RUN
FROM QSYS2.SCHEDULED_JOB_INFO
WHERE UPPER(COMMAND_TO_RUN) LIKE '%QSH%'
   OR UPPER(COMMAND_TO_RUN) LIKE '%STRQSH%'
   OR UPPER(COMMAND_TO_RUN) LIKE '%SH %'
   OR UPPER(COMMAND_TO_RUN) LIKE '%BASH%'
ORDER BY JOB_NAME;

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