------------------------------------------------------------------------------
-- CHECK ID     : IBMI-NET-008
-- CHECK NAME   : Database Network Exposure
-- DOMAIN       : NET
-- LEVEL        : SAFE
--
-- DESCRIPTION
-- -----------
-- Audit de l’exposition réseau DB2 / DRDA / ODBC.
--
-- OBJECTIFS SSI
-- --------------
-- - Identifier exposition DB2
-- - Vérifier accès ODBC/DRDA
-- - Préparer cloisonnement réseau
-- - Préparer niveau 40
--
-- CONTEXTE IBM i
-- ---------------
-- IBM i expose souvent DB2 via :
--
-- - ODBC
-- - DRDA
-- - JDBC
-- - Access Client Solutions
--
-- Très pratique.
--
-- Très dangereux aussi si :
-- - trop ouvert ;
-- - mal cloisonné ;
-- - comptes puissants ;
-- - mots de passe faibles.
--
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- SECTION 1
-- Services DB2 exposés
------------------------------------------------------------------------------

SELECT
    SERVER_NAME,
    PORT_NUMBER,
    SERVER_STATUS,
    SECURE_CONNECTION
FROM QSYS2.NETSTAT_SERVER_INFO
WHERE UPPER(SERVER_NAME) IN (
    'DRDA',
    'DDM',
    'ODBC'
)
ORDER BY SERVER_NAME;

------------------------------------------------------------------------------
-- SECTION 2
-- Comptes puissants potentiellement exposés
------------------------------------------------------------------------------
--
-- Pourquoi ?
--
-- ACS/ODBC/JDBC utilisent souvent :
--
-- - profils utilisateurs IBM i
-- - parfois profils trop puissants
--
-- Très fréquent :
--
-- développeur = *ALLOBJ 😅
--
------------------------------------------------------------------------------

SELECT
    AUTHORIZATION_NAME,
    STATUS,
    SPECIAL_AUTHORITIES,
    USER_CLASS,
    LOCAL_PASSWORD_MANAGEMENT
FROM QSYS2.USER_INFO
WHERE STATUS = '*ENABLED'
AND (
    SPECIAL_AUTHORITIES LIKE '%*ALLOBJ%'
    OR SPECIAL_AUTHORITIES LIKE '%*SECADM%'
)
ORDER BY AUTHORIZATION_NAME;

------------------------------------------------------------------------------
-- SECTION 3
-- Risques SSI
------------------------------------------------------------------------------
--
-- Risques typiques :
--
-- - extraction massive DB2
-- - ransomware
-- - vol données RH/finance
-- - pivot AD -> IBM i
--
-- Vérifier :
--
-- 1. Cloisonnement VLAN
-- 2. MFA accès ACS
-- 3. Journalisation ODBC
-- 4. Comptes de service
-- 5. Comptes partagés
--
------------------------------------------------------------------------------