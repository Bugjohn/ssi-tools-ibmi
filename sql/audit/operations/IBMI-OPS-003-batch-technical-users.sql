------------------------------------------------------------------------------
-- CHECK ID     : IBMI-OPS-003
-- CHECK NAME   : Batch and Technical Users
-- DOMAIN       : OPS
-- LEVEL        : SAFE
--
-- DESCRIPTION
-- -----------
-- Identification des comptes batch et techniques.
--
-- OBJECTIFS SSI
-- --------------
-- - Identifier comptes techniques
-- - Préparer PRA/PCA
-- - Identifier comptes critiques
-- - Réduire comptes oubliés
--
-- CONTEXTE IBM i
-- ---------------
-- Les comptes batch IBM i :
--
-- - exécutent interfaces
-- - pilotent EDI
-- - exécutent APIs
-- - réalisent transferts FTP/SFTP
--
-- Souvent :
--
-- personne ne sait :
-- - qui les utilise ;
-- - quels jobs les utilisent ;
-- - quels flux dépendent d’eux 😅
--
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- SECTION 1
-- Comptes techniques potentiels
------------------------------------------------------------------------------

SELECT
    AUTHORIZATION_NAME,
    STATUS,
    USER_CLASS_NAME,
    HOME_DIRECTORY,
    PASSWORD_CHANGE_DATE,
    PREVIOUS_SIGNON,
    LOCAL_PASSWORD_MANAGEMENT
FROM QSYS2.USER_INFO
WHERE STATUS = '*ENABLED'
  AND (
       AUTHORIZATION_NAME LIKE 'BATCH%'
    OR AUTHORIZATION_NAME LIKE 'FTP%'
    OR AUTHORIZATION_NAME LIKE 'API%'
    OR AUTHORIZATION_NAME LIKE 'EDI%'
    OR AUTHORIZATION_NAME LIKE 'SRV%'
  )
ORDER BY AUTHORIZATION_NAME;

------------------------------------------------------------------------------
-- SECTION 2
-- Comptes sans connexion récente
------------------------------------------------------------------------------
--
-- Très fréquent :
--
-- vieux compte technique :
-- - jamais utilisé
-- - mais toujours actif
-- - avec droits élevés
--
------------------------------------------------------------------------------

SELECT
    AUTHORIZATION_NAME,
    STATUS,
    PREVIOUS_SIGNON,
    SPECIAL_AUTHORITIES
FROM QSYS2.USER_INFO
WHERE STATUS = '*ENABLED'
AND PREVIOUS_SIGNON < CURRENT_TIMESTAMP - 180 DAYS
AND (
       AUTHORIZATION_NAME LIKE 'BATCH%'
    OR AUTHORIZATION_NAME LIKE 'FTP%'
    OR AUTHORIZATION_NAME LIKE 'API%'
)
ORDER BY PREVIOUS_SIGNON;

------------------------------------------------------------------------------
-- SECTION 3
-- Questions SSI
------------------------------------------------------------------------------
--
-- Vérifier :
--
-- 1. Qui possède le compte ?
-- 2. Quel batch l’utilise ?
-- 3. Quel flux dépend du compte ?
-- 4. Compte documenté ?
-- 5. Mot de passe tourné ?
-- 6. Utilisable interactif ?
--
------------------------------------------------------------------------------