------------------------------------------------------------------------------
-- CHECK ID     : IBMI-NET-006
-- CHECK NAME   : FTPS/SFTP Migration Candidates
-- DOMAIN       : NET
-- LEVEL        : SAFE
--
-- DESCRIPTION
-- -----------
-- Préparation migration FTP -> FTPS/SFTP.
--
-- OBJECTIFS SSI
-- --------------
-- - Identifier dépendances FTP
-- - Préparer migration sécurisée
-- - Support PRA/PCA
-- - Réduction surface d’attaque
--
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- SECTION 1
-- Serveur FTP actif
------------------------------------------------------------------------------

SELECT
    SERVER_NAME,
    SERVER_STATUS,
    PORT_NUMBER,
    SECURE_CONNECTION
FROM QSYS2.NETSTAT_SERVER_INFO
WHERE UPPER(SERVER_NAME) = 'FTP';

------------------------------------------------------------------------------
-- SECTION 2
-- Comptes potentiellement utilisés pour flux
------------------------------------------------------------------------------
--
-- Très utile :
--
-- - comptes batch
-- - comptes interfaces
-- - comptes techniques
--
-- Souvent :
-- FTP tourne avec :
-- - vieux mots de passe
-- - comptes partagés
-- - scripts oubliés
--
------------------------------------------------------------------------------

SELECT
    AUTHORIZATION_NAME,
    STATUS,
    HOME_DIRECTORY,
    PASSWORD_CHANGE_DATE,
    LOCAL_PASSWORD_MANAGEMENT
FROM QSYS2.USER_INFO
WHERE STATUS = '*ENABLED'
AND (
    AUTHORIZATION_NAME LIKE 'FTP%'
    OR AUTHORIZATION_NAME LIKE 'SFTP%'
    OR AUTHORIZATION_NAME LIKE 'BATCH%'
    OR HOME_DIRECTORY LIKE '/home/%'
)
ORDER BY AUTHORIZATION_NAME;

------------------------------------------------------------------------------
-- SECTION 3
-- Points PRA/PCA
------------------------------------------------------------------------------
--
-- Questions importantes :
--
-- 1. Quels flux FTP existent encore ?
-- 2. Qui connait les batchs ?
-- 3. Certificats DCM présents ?
-- 4. FTPS testé ?
-- 5. SFTP testé ?
-- 6. PRA valide-t-il les flux sécurisés ?
--
-- Cas classique :
--
-- "Le PRA fonctionne"
--
-- MAIS :
--
-- - flux EDI KO
-- - API KO
-- - certificats expirés
-- - SFTP oublié
--
------------------------------------------------------------------------------