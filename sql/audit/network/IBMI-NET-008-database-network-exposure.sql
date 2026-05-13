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

/* =========================================================
   AUDIT DRDA / DDM / ODBC IBM i
   Compatible systèmes sans NETSTAT_SERVER_INFO
   Basé sur QSYS2.NETSTAT_INFO
   ========================================================= */

SELECT
    LOCAL_ADDRESS,
    LOCAL_PORT,
    LOCAL_PORT_NAME,
    PROTOCOL,
    TCP_STATE,
    CONNECTION_OPEN_TYPE,
    BIND_USER,
    NUMBER_OF_ASSOCIATED_JOBS,
    CONNECTION_TRANSPORT_LAYER,

    CASE
        WHEN LOCAL_PORT = 446
            THEN 'DRDA / DDM SECURISE POTENTIEL'
        WHEN LOCAL_PORT IN (8471, 8476)
            THEN 'SERVICE IBM i DISTANT'
        ELSE 'SERVICE SQL / ODBC A ANALYSER'
    END AS SERVICE_TYPE,

    CASE
        WHEN LOCAL_ADDRESS = '0.0.0.0'
            THEN 'EXPOSE SUR TOUTES LES INTERFACES'
        ELSE 'LIE A UNE IP SPECIFIQUE'
    END AS EXPOSURE_LEVEL,

    CASE
        WHEN TCP_STATE = 'TCPLISTEN'
            THEN 'SERVICE EN ECOUTE'
        ELSE 'CONNEXION ACTIVE'
    END AS CONNECTION_STATUS

FROM QSYS2.NETSTAT_INFO

WHERE PROTOCOL = 'TCP'
AND LOCAL_PORT IN (
    446,   -- DRDA / DB2
    447,   -- DDM
    448,   -- AS-DATABASE
    8471,  -- IBM i Remote Command
    8476   -- IBM i Database Host Server
)

ORDER BY LOCAL_PORT, LOCAL_ADDRESS;

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
    USER_CLASS_NAME,
    LOCAL_PASSWORD_MANAGEMENT,
    GROUP_PROFILE_NAME,
    SUPPLEMENTAL_GROUP_LIST,
    SPECIAL_AUTHORITIES,

    CASE
        WHEN SPECIAL_AUTHORITIES LIKE '%*ALLOBJ%'
         AND SPECIAL_AUTHORITIES LIKE '%*SECADM%'
            THEN 'CRITIQUE - ALLOBJ + SECADM'
        WHEN SPECIAL_AUTHORITIES LIKE '%*ALLOBJ%'
            THEN 'CRITIQUE - ALLOBJ'
        WHEN SPECIAL_AUTHORITIES LIKE '%*SECADM%'
            THEN 'ELEVE - SECADM'
        ELSE 'A ANALYSER'
    END AS SSI_STATUS

FROM QSYS2.USER_INFO
WHERE STATUS = '*ENABLED'
  AND (
        SPECIAL_AUTHORITIES LIKE '%*ALLOBJ%'
     OR SPECIAL_AUTHORITIES LIKE '%*SECADM%'
      )
ORDER BY
    SSI_STATUS,
    AUTHORIZATION_NAME;

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