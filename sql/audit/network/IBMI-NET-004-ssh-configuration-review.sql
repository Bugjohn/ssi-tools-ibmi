------------------------------------------------------------------------------
-- CHECK ID     : IBMI-NET-004
-- CHECK NAME   : SSH Configuration Review
-- DOMAIN       : NET
-- LEVEL        : SAFE
--
-- DESCRIPTION
-- -----------
-- Audit du serveur SSH IBM i.
--
-- OBJECTIFS SSI
-- --------------
-- - Vérifier présence SSH
-- - Préparer migration SFTP
-- - Identifier dépendances batch/API
-- - Vérifier exposition SSH
--
-- CONTEXTE IBM i
-- ---------------
-- SSH devient central :
--
-- - SFTP
-- - automatisation
-- - PRA/PCA
-- - DevOps
-- - APIs
--
-- MAIS :
-- mal configuré = énorme surface d’attaque.
--
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- SECTION 1
-- Etat du serveur SSH
------------------------------------------------------------------------------

SELECT
    SERVER_NAME,
    PORT_NUMBER,
    SERVER_STATUS,
    SECURE_CONNECTION,
    LOCAL_ADDRESS
FROM QSYS2.NETSTAT_SERVER_INFO
WHERE UPPER(SERVER_NAME) LIKE '%SSH%';

------------------------------------------------------------------------------
-- SECTION 2
-- Jobs SSH actifs
------------------------------------------------------------------------------

SELECT
    JOB_NAME,
    AUTHORIZATION_NAME,
    SUBSYSTEM,
    FUNCTION
FROM TABLE(QSYS2.ACTIVE_JOB_INFO())
WHERE FUNCTION LIKE '%SSH%'
ORDER BY JOB_NAME;

------------------------------------------------------------------------------
-- SECTION 3
-- Utilisateurs avec HOME_DIRECTORY
------------------------------------------------------------------------------
--
-- Pourquoi ?
--
-- SSH/SFTP utilisent souvent :
-- - HOME_DIRECTORY
-- - clés SSH
-- - répertoires /home
--
-- Très utile pour :
-- - migration FTP -> SFTP
-- - PRA/PCA
-- - audit sécurité SSH
--
------------------------------------------------------------------------------

SELECT
    AUTHORIZATION_NAME,
    STATUS,
    HOME_DIRECTORY,
    LOCAL_PASSWORD_MANAGEMENT
FROM QSYS2.USER_INFO
WHERE HOME_DIRECTORY LIKE '/home/%'
ORDER BY AUTHORIZATION_NAME;

------------------------------------------------------------------------------
-- SECTION 4
-- Points d’attention SSI
------------------------------------------------------------------------------
--
-- Vérifier :
--
-- 1. Clés SSH protégées ?
-- 2. Comptes batch utilisés ?
-- 3. Comptes AD/Kerberos impliqués ?
-- 4. Scripts QSH/STRQSH présents ?
-- 5. Flux SFTP documentés ?
-- 6. PRA/PCA teste-t-il SSH ?
--
-- Très fréquent :
--
-- SSH actif
-- MAIS :
-- - personne ne connait les clés
-- - personne ne connait les batchs
-- - personne ne connait les dépendances 😅
--
------------------------------------------------------------------------------