------------------------------------------------------------------------------
-- CHECK ID     : IBMI-IFS-003
-- CHECK NAME   : Home Directory Permissions
-- DOMAIN       : IFS
-- LEVEL        : SAFE
--
-- DESCRIPTION
-- -----------
-- Audit des HOME_DIRECTORY utilisateurs IBM i.
--
-- OBJECTIFS SSI
-- --------------
-- - Identifier exposition IFS
-- - Préparer SSH/SFTP
-- - Vérifier isolation utilisateurs
-- - Préparer PRA/PCA
--
-- CONTEXTE IBM i
-- ---------------
-- Les HOME_DIRECTORY servent souvent pour :
--
-- - SSH
-- - SFTP
-- - clés SSH
-- - scripts shell
-- - tickets Kerberos
--
-- Mauvaise sécurisation :
--
-- = fuite clés SSH
-- = fuite tickets Kerberos
-- = exposition batch
--
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- SECTION 1
-- Inventaire HOME_DIRECTORY
------------------------------------------------------------------------------

SELECT
    AUTHORIZATION_NAME,
    STATUS,
    HOME_DIRECTORY,
    LOCAL_PASSWORD_MANAGEMENT
FROM QSYS2.USER_INFO
WHERE HOME_DIRECTORY IS NOT NULL
AND HOME_DIRECTORY <> ''
ORDER BY HOME_DIRECTORY;

------------------------------------------------------------------------------
-- SECTION 2
-- Comptes AD/Kerberos avec HOME_DIRECTORY
------------------------------------------------------------------------------

SELECT
    AUTHORIZATION_NAME,
    STATUS,
    HOME_DIRECTORY,
    LOCAL_PASSWORD_MANAGEMENT
FROM QSYS2.USER_INFO
WHERE LOCAL_PASSWORD_MANAGEMENT = 'NO'
AND HOME_DIRECTORY LIKE '/home/%'
ORDER BY AUTHORIZATION_NAME;

------------------------------------------------------------------------------
-- SECTION 3
-- Risques SSI
------------------------------------------------------------------------------
--
-- Vérifier :
--
-- 1. Permissions IFS correctes ?
-- 2. Tickets Kerberos présents ?
-- 3. Clés SSH protégées ?
-- 4. Répertoires orphelins ?
-- 5. Comptes désactivés encore présents ?
--
-- Cas fréquent :
--
-- ancien prestataire :
-- - compte supprimé
-- - clés SSH encore présentes 😅
--
------------------------------------------------------------------------------