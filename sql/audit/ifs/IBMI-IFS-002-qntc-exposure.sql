------------------------------------------------------------------------------
-- CHECK ID     : IBMI-IFS-002
-- CHECK NAME   : QNTC Exposure Review
-- DOMAIN       : IFS
-- LEVEL        : SAFE
--
-- DESCRIPTION
-- -----------
-- Audit des usages QNTC et dépendances SMB/Windows.
--
-- OBJECTIFS SSI
-- --------------
-- - Identifier dépendances Windows
-- - Préparer niveau 40
-- - Identifier flux SMB
-- - Aider PRA/PCA
--
-- CONTEXTE IBM i
-- ---------------
-- QNTC permet accès :
--
-- IBM i -> partages Windows
--
-- Très pratique.
--
-- Très dangereux aussi 😅
--
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- SECTION 1
-- Utilisateurs avec HOME_DIRECTORY réseau
------------------------------------------------------------------------------

SELECT
    AUTHORIZATION_NAME,
    HOME_DIRECTORY,
    STATUS,
    LOCAL_PASSWORD_MANAGEMENT
FROM QSYS2.USER_INFO
WHERE HOME_DIRECTORY LIKE '/QNTC/%'
ORDER BY AUTHORIZATION_NAME;

------------------------------------------------------------------------------
-- SECTION 2
-- Risques SSI
------------------------------------------------------------------------------
--
-- QNTC dépend souvent :
--
-- - AD
-- - SMB
-- - mots de passe
-- - mapping utilisateurs
-- - Kerberos
--
-- En PRA :
--
-- IBM i peut être UP
-- MAIS :
--
-- - QNTC KO
-- - partages Windows KO
-- - batchs KO
--
-- => PRA technique OK
-- => PRA métier KO
--
------------------------------------------------------------------------------