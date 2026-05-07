------------------------------------------------------------------------------
-- CHECK ID     : IBMI-OPS-002
-- CHECK NAME   : Autostart Network Servers
-- DOMAIN       : OPS
-- LEVEL        : SAFE
--
-- DESCRIPTION
-- -----------
-- Vérification des serveurs réseau démarrés automatiquement.
--
-- OBJECTIFS SSI
-- --------------
-- - Identifier exposition automatique
-- - Préparer PRA/PCA
-- - Réduire surface d’attaque
--
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- SECTION 1
-- Etat des serveurs réseau
------------------------------------------------------------------------------

SELECT
    SERVER_NAME,
    SERVER_TYPE,
    SERVER_STATUS,
    PORT_NUMBER
FROM QSYS2.NETSTAT_SERVER_INFO
ORDER BY SERVER_NAME;

------------------------------------------------------------------------------
-- SECTION 2
-- Questions importantes
------------------------------------------------------------------------------
--
-- Après IPL :
--
-- quels serveurs redémarrent automatiquement ?
--
-- Très important pour :
--
-- - PRA/PCA
-- - sécurité
-- - réduction surface d’attaque
--
-- Beaucoup d’environnements :
--
-- démarrent :
-- - FTP
-- - ODBC
-- - TELNET
-- automatiquement
--
-- ... sans justification métier réelle 😅
--
------------------------------------------------------------------------------