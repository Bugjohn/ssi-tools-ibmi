------------------------------------------------------------------------------
-- CHECK ID     : IBMI-NET-002
-- CHECK NAME   : Network Servers Status
-- DOMAIN       : NET
-- LEVEL        : SAFE
--
-- DESCRIPTION
-- -----------
-- Inventaire des serveurs réseau IBM i potentiellement exposés.
--
-- OBJECTIFS SSI
-- --------------
-- - Identifier les services réseau actifs
-- - Détecter les protocoles non chiffrés
-- - Préparer migration FTP -> FTPS/SFTP
-- - Identifier exposition TELNET
-- - Aider PRA/PCA
-- - Préparer niveau 40
--
-- PUBLIC CIBLE
-- -------------
-- - Admin IBM i
-- - SOC
-- - RSSI
-- - Junior Windows/Linux découvrant IBM i
--
-- IMPACT
-- ------
-- SAFE
-- Lecture seule.
-- Aucun impact système.
--
-- EXECUTION
-- ----------
-- ACS -> Run SQL Scripts
--
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- SECTION 1
-- Présentation pédagogique
------------------------------------------------------------------------------
--
-- IBM i possède plusieurs serveurs réseau historiques.
--
-- Certains sont aujourd’hui considérés comme sensibles :
--
-- - FTP      -> non chiffré
-- - TELNET   -> très risqué
-- - ODBC     -> souvent trop exposé
--
-- D’autres deviennent critiques dans un SI moderne :
--
-- - SSH/SFTP
-- - HTTPS
-- - DDM/DRDA
--
-- Important :
-- un service actif ne veut PAS dire :
-- "service encore utile".
--
-- Beaucoup de systèmes IBM i gardent des serveurs actifs :
-- "parce qu’ils ont toujours été là" 😅
--
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- SECTION 2
-- Etat des serveurs TCP/IP IBM i
------------------------------------------------------------------------------
--
-- La vue NETSTAT_SERVER_INFO permet de voir :
--
-- - les serveurs démarrés
-- - le port
-- - le statut
-- - le type
--
-- Très utile pour :
-- - audit SSI
-- - PRA/PCA
-- - migration FTPS/SFTP
-- - préparation niveau 40
--
------------------------------------------------------------------------------

SELECT
    SERVER_TYPE,
    SERVER_NAME,
    PORT_NUMBER,
    SERVER_STATUS,
    SECURE_CONNECTION,
    IP_VERSION
FROM QSYS2.NETSTAT_SERVER_INFO
ORDER BY PORT_NUMBER;

------------------------------------------------------------------------------
-- SECTION 3
-- Focus services sensibles
------------------------------------------------------------------------------
--
-- Pourquoi ?
--
-- Certains protocoles sont fréquemment problématiques :
--
-- FTP :
--     - mots de passe potentiellement exposés
--     - flux historiques oubliés
--
-- TELNET :
--     - administration legacy
--     - souvent incompatible politique SSI moderne
--
-- ODBC :
--     - accès DB2 parfois ouverts à tout le LAN
--
------------------------------------------------------------------------------

SELECT
    SERVER_NAME,
    PORT_NUMBER,
    SERVER_STATUS,
    SECURE_CONNECTION
FROM QSYS2.NETSTAT_SERVER_INFO
WHERE UPPER(SERVER_NAME) IN (
    'FTP',
    'TELNET',
    'DRDA',
    'DDM',
    'ODBC'
)
ORDER BY SERVER_NAME;

------------------------------------------------------------------------------
-- SECTION 4
-- Détection services non sécurisés
------------------------------------------------------------------------------
--
-- SECURE_CONNECTION :
--
-- YES = TLS/SSL utilisé
-- NO  = flux potentiellement en clair
--
-- Attention :
-- certains vieux environnements IBM i :
-- "sont dans le LAN donc c’est bon"
--
-- Jusqu’au jour :
-- - où le VPN tombe,
-- - où un poste est compromis,
-- - où le SOC découvre du sniffing réseau 😅
--
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
-- SECTION 5
-- Points d’attention SSI
------------------------------------------------------------------------------
--
-- QUESTIONS IMPORTANTES :
--
-- 1. FTP est-il encore utilisé ?
-- 2. Peut-on migrer vers FTPS ?
-- 3. Peut-on migrer vers SFTP ?
-- 4. TELNET est-il encore nécessaire ?
-- 5. Quels batchs dépendent encore de FTP ?
-- 6. Quels comptes techniques utilisent ces flux ?
-- 7. Les certificats DCM existent-ils ?
-- 8. PRA/PCA valide-t-il les flux TLS ?
--
-- Beaucoup de PRA :
-- "LPAR OK"
--
-- MAIS :
-- - APIs KO
-- - FTPS KO
-- - certificats expirés
-- - batchs cassés
--
-- => PRA technique OK
-- => PRA métier KO
--
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- FIN DU CHECK
------------------------------------------------------------------------------