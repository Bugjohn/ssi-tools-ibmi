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
    SERVER_NAME,
    SERVER_STATUS,
    PORT_NUMBER,
    SECURE_CONNECTION,
    LOCAL_ADDRESS
FROM QSYS2.NETSTAT_SERVER_INFO
WHERE UPPER(SERVER_NAME) LIKE '%HTTP%'
   OR UPPER(SERVER_NAME) LIKE '%HTTPS%'
ORDER BY PORT_NUMBER;

------------------------------------------------------------------------------
-- SECTION 2
-- Vérification exposition HTTP non sécurisé
------------------------------------------------------------------------------
--
-- HTTP non sécurisé :
--
-- - authentification potentiellement en clair
-- - cookies non protégés
-- - administration exposée
--
------------------------------------------------------------------------------

SELECT
    SERVER_NAME,
    PORT_NUMBER,
    SERVER_STATUS
FROM QSYS2.NETSTAT_SERVER_INFO
WHERE (
        UPPER(SERVER_NAME) LIKE '%HTTP%'
     OR UPPER(SERVER_NAME) LIKE '%ADMIN%'
)
AND SECURE_CONNECTION = 'NO'
ORDER BY PORT_NUMBER;

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