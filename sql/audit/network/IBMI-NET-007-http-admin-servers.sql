------------------------------------------------------------------------------
-- CHECK ID     : IBMI-NET-007
-- CHECK NAME   : HTTP Admin Servers Exposure
-- DOMAIN       : NET
-- LEVEL        : SAFE
--
-- DESCRIPTION
-- -----------
-- Audit des serveurs HTTP/HTTPS IBM i.
--
-- OBJECTIFS SSI
-- --------------
-- - Identifier serveurs HTTP actifs
-- - Vérifier usage HTTPS
-- - Identifier exposition administration IBM i
-- - Préparer PRA/PCA SSL
--
-- CONTEXTE IBM i
-- ---------------
-- IBM i utilise Apache HTTP Server intégré.
--
-- Souvent utilisé pour :
--
-- - IBM Navigator for i
-- - APIs REST
-- - applications métiers
-- - administration
-- - interfaces web historiques
--
-- Très fréquent :
--
-- "Le serveur HTTP tourne depuis 12 ans"
-- ... mais personne ne sait ce qu’il héberge 😅
--
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- SECTION 1
-- Serveurs HTTP/HTTPS actifs
------------------------------------------------------------------------------

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
        WHEN LOCAL_PORT IN (80, 2001, 2010)
            THEN 'HTTP NON CHIFFRE'
        WHEN LOCAL_PORT IN (443, 2002, 2011)
            THEN 'HTTPS / SECURISE A VERIFIER'
        ELSE 'AUTRE'
    END AS SECURITY_STATUS,

    CASE
        WHEN LOCAL_ADDRESS = '0.0.0.0'
            THEN 'EXPOSE SUR TOUTES LES INTERFACES'
        ELSE 'LIE A UNE IP SPECIFIQUE'
    END AS EXPOSURE_LEVEL

FROM QSYS2.NETSTAT_INFO

WHERE PROTOCOL = 'TCP'
AND LOCAL_PORT IN (
    80,     -- HTTP
    443,    -- HTTPS
    2001,   -- IBM i Admin HTTP
    2002,   -- IBM i Admin HTTPS
    2010,
    2011
)

ORDER BY LOCAL_PORT, LOCAL_ADDRESS;

------------------------------------------------------------------------------
-- SECTION 2
/* =========================================================
   AUDIT HTTP / ADMIN IBM i
   Objectif :
   - détecter les services HTTP/admin exposés
   - identifier les ports non chiffrés
   - préparer le passage niveau 40
   ========================================================= */

SELECT
    LOCAL_ADDRESS,
    LOCAL_PORT,
    LOCAL_PORT_NAME,
    TCP_STATE,
    BIND_USER,
    NUMBER_OF_ASSOCIATED_JOBS,

    CASE
        WHEN LOCAL_PORT IN (80, 2001, 2010)
            THEN 'CRITIQUE - HTTP NON CHIFFRE'
        WHEN LOCAL_PORT IN (443, 2002, 2011)
            THEN 'HTTPS / ADMIN SECURISE A VERIFIER'
        ELSE 'INCONNU'
    END AS SSI_STATUS,

    CASE
        WHEN LOCAL_ADDRESS = '0.0.0.0'
            THEN 'EXPOSE SUR TOUTES LES INTERFACES'
        ELSE 'LIE A UNE IP SPECIFIQUE'
    END AS EXPOSURE_LEVEL

FROM QSYS2.NETSTAT_INFO

WHERE PROTOCOL = 'TCP'
  AND LOCAL_PORT IN (80, 443, 2001, 2002, 2010, 2011)

ORDER BY LOCAL_PORT, LOCAL_ADDRESS;
------------------------------------------------------------------------------
-- SECTION 3
-- Risques SSI
------------------------------------------------------------------------------
--
-- Vérifier :
--
-- 1. Navigator for i exposé ?
-- 2. HTTPS obligatoire ?
-- 3. Certificats DCM valides ?
-- 4. APIs REST documentées ?
-- 5. Reverse proxy présent ?
-- 6. TLS 1.2+ activé ?
--
-- Cas fréquent :
--
-- - vieux Apache IBM i
-- - interface admin oubliée
-- - HTTP interne "temporaire"
-- - devenu permanent depuis 2011 😅
--
------------------------------------------------------------------------------