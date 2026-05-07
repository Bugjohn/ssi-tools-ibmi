------------------------------------------------------------------------------
-- CHECK ID     : IBMI-NET-003
-- CHECK NAME   : TELNET Exposure Review
-- DOMAIN       : NET
-- LEVEL        : SAFE
--
-- DESCRIPTION
-- -----------
-- Audit du serveur TELNET IBM i.
--
-- OBJECTIFS SSI
-- --------------
-- - Détecter exposition TELNET
-- - Identifier usage legacy
-- - Préparer suppression TELNET
-- - Réduire surface d’attaque
-- - Préparer niveau 40
--
-- RISQUE SSI
-- -----------
-- TELNET :
-- - protocole historique
-- - souvent non chiffré
-- - fréquemment oublié
-- - utilisé par vieux outils/scripts
--
-- Très souvent :
-- "on ne sait plus pourquoi c'est actif" 😅
--
-- IMPACT
-- ------
-- SAFE
-- Lecture seule.
--
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- SECTION 1
-- Vérifier présence du serveur TELNET
------------------------------------------------------------------------------

SELECT
    SERVER_NAME,
    PORT_NUMBER,
    SERVER_STATUS,
    SECURE_CONNECTION,
    LOCAL_ADDRESS
FROM QSYS2.NETSTAT_SERVER_INFO
WHERE UPPER(SERVER_NAME) LIKE '%TELNET%';

------------------------------------------------------------------------------
-- SECTION 2
-- Vérifier jobs TELNET actifs
------------------------------------------------------------------------------
--
-- Sur IBM i :
-- un serveur TCP/IP correspond souvent à des jobs actifs.
--
-- Cela aide à :
-- - comprendre activité réelle
-- - identifier utilisateurs connectés
-- - identifier dépendances applicatives
--
------------------------------------------------------------------------------

SELECT
    JOB_NAME,
    AUTHORIZATION_NAME,
    SUBSYSTEM,
    FUNCTION
FROM TABLE(QSYS2.ACTIVE_JOB_INFO())
WHERE FUNCTION LIKE '%TELNET%'
ORDER BY JOB_NAME;

------------------------------------------------------------------------------
-- SECTION 3
-- Points d’attention SSI
------------------------------------------------------------------------------
--
-- Questions importantes :
--
-- 1. TELNET est-il encore nécessaire ?
-- 2. Existe-t-il encore des terminaux 5250 legacy ?
-- 3. Des scripts utilisent-ils TELNET ?
-- 4. Peut-on migrer vers SSH ?
-- 5. Le flux traverse-t-il des VLAN sensibles ?
--
-- En environnement moderne :
--
-- TELNET devrait normalement :
-- - être désactivé
-- OU
-- - strictement cloisonné réseau.
--
------------------------------------------------------------------------------