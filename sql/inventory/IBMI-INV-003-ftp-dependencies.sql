------------------------------------------------------------------------------
-- CHECK ID     : IBMI-INV-003
-- CHECK NAME   : FTP Dependencies Inventory
-- DOMAIN       : NET
-- LEVEL        : SAFE
--
-- DESCRIPTION
-- -----------
-- Inventaire des dépendances FTP IBM i.
--
-- OBJECTIFS SSI
-- --------------
-- - Préparer migration FTPS/SFTP
-- - Identifier flux historiques
-- - Préparer PRA/PCA
-- - Réduire surface d’attaque
--
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- SECTION 1
-- Jobs planifiés utilisant FTP
------------------------------------------------------------------------------

SELECT
    JOB_NAME,
    USER_NAME,
    COMMAND_TO_RUN
FROM QSYS2.SCHEDULED_JOB_INFO
WHERE UPPER(COMMAND_TO_RUN) LIKE '%FTP%'
ORDER BY JOB_NAME;

------------------------------------------------------------------------------
-- SECTION 2
-- Jobs actifs FTP
------------------------------------------------------------------------------

SELECT
    JOB_NAME,
    AUTHORIZATION_NAME,
    FUNCTION,
    SUBSYSTEM
FROM TABLE(QSYS2.ACTIVE_JOB_INFO())
WHERE FUNCTION LIKE '%FTP%'
ORDER BY JOB_NAME;

------------------------------------------------------------------------------
-- SECTION 3
-- Comptes potentiellement utilisés
------------------------------------------------------------------------------

SELECT
    AUTHORIZATION_NAME,
    STATUS,
    PASSWORD_CHANGE_DATE,
    PREVIOUS_SIGNON
FROM QSYS2.USER_INFO
WHERE STATUS = '*ENABLED'
AND (
       AUTHORIZATION_NAME LIKE 'FTP%'
    OR AUTHORIZATION_NAME LIKE 'EDI%'
    OR AUTHORIZATION_NAME LIKE 'BATCH%'
)
ORDER BY AUTHORIZATION_NAME;

------------------------------------------------------------------------------
-- SECTION 4
-- Risques SSI
------------------------------------------------------------------------------
--
-- Très fréquent :
--
-- FTP :
-- - utilisé depuis 20 ans ;
-- - plus documenté ;
-- - mots de passe jamais changés ;
-- - dépendances inconnues.
--
-- Vérifier :
--
-- 1. Flux métier critiques ?
-- 2. Prestataires impliqués ?
-- 3. Scripts shell associés ?
-- 4. Certificats FTPS prêts ?
-- 5. SFTP possible ?
--
------------------------------------------------------------------------------