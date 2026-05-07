------------------------------------------------------------------------------
-- CHECK ID     : IBMI-NET-005
-- CHECK NAME   : Insecure Network Services Summary
-- DOMAIN       : NET
-- LEVEL        : SAFE
--
-- DESCRIPTION
-- -----------
-- Vue synthétique des services réseau non sécurisés.
--
-- OBJECTIFS SSI
-- --------------
-- - Cartographie exposition réseau
-- - Support RSSI/SOC
-- - Support PRA/PCA
-- - Préparation niveau 40
--
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- SECTION 1
-- Services TCP/IP sans connexion sécurisée
------------------------------------------------------------------------------

SELECT
    SERVER_NAME,
    PORT_NUMBER,
    SERVER_STATUS,
    SECURE_CONNECTION,
    LOCAL_ADDRESS
FROM QSYS2.NETSTAT_SERVER_INFO
WHERE SECURE_CONNECTION = 'NO'
ORDER BY PORT_NUMBER;

------------------------------------------------------------------------------
-- SECTION 2
-- Focus protocoles legacy
------------------------------------------------------------------------------

SELECT
    SERVER_NAME,
    PORT_NUMBER,
    SERVER_STATUS
FROM QSYS2.NETSTAT_SERVER_INFO
WHERE UPPER(SERVER_NAME) IN (
    'FTP',
    'TELNET',
    'REXEC',
    'RLOGIN'
)
ORDER BY SERVER_NAME;

------------------------------------------------------------------------------
-- SECTION 3
-- Risque SSI
------------------------------------------------------------------------------
--
-- Services historiques = souvent :
--
-- - oubliés
-- - non documentés
-- - non supervisés
-- - non testés PRA
--
-- En audit :
--
-- "Le service tourne encore"
--
-- ne veut PAS dire :
--
-- "Le service est encore utile" 😅
--
------------------------------------------------------------------------------