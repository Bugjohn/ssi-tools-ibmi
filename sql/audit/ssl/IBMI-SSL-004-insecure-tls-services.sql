------------------------------------------------------------------------------
-- CHECK ID     : IBMI-SSL-004
-- CHECK NAME   : Insecure TLS Services
-- DOMAIN       : SSL
-- LEVEL        : SAFE
--
-- DESCRIPTION
-- -----------
-- Identification des services réseau sans TLS.
--
-- OBJECTIFS SSI
-- --------------
-- - Cartographier flux non chiffrés
-- - Préparer migration TLS
-- - Support PRA/PCA
-- - Préparation audit SSI
--
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- SECTION 1
-- Services non sécurisés
------------------------------------------------------------------------------

SELECT
    SERVER_NAME,
    PORT_NUMBER,
    SERVER_STATUS,
    SECURE_CONNECTION
FROM QSYS2.NETSTAT_SERVER_INFO
WHERE SECURE_CONNECTION = 'NO'
ORDER BY SERVER_NAME;

------------------------------------------------------------------------------
-- SECTION 2
-- Focus services critiques
------------------------------------------------------------------------------

SELECT
    SERVER_NAME,
    PORT_NUMBER,
    SERVER_STATUS
FROM QSYS2.NETSTAT_SERVER_INFO
WHERE SECURE_CONNECTION = 'NO'
AND (
       UPPER(SERVER_NAME) LIKE '%FTP%'
    OR UPPER(SERVER_NAME) LIKE '%TELNET%'
    OR UPPER(SERVER_NAME) LIKE '%HTTP%'
)
ORDER BY SERVER_NAME;

------------------------------------------------------------------------------
-- SECTION 3
-- Risques SSI
------------------------------------------------------------------------------
--
-- Flux non chiffrés :
--
-- - interception credentials
-- - sniffing réseau
-- - vol données
-- - pivot interne
--
-- En 2026 :
--
-- "c’est dans le LAN"
--
-- n’est plus une stratégie sécurité 😅
--
------------------------------------------------------------------------------