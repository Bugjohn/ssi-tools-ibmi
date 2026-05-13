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
    LOCAL_ADDRESS,
    LOCAL_PORT,
    LOCAL_PORT_NAME,
    PROTOCOL,
    TCP_STATE,
    BIND_USER
FROM QSYS2.NETSTAT_INFO
WHERE TCP_STATE = 'LISTEN'
ORDER BY LOCAL_PORT;


/* ============================================================
   AUDIT RESEAU IBM i - SURFACE D'EXPOSITION TCP
   ------------------------------------------------------------
   OBJECTIF :
   - Identifier les ports en écoute
   - Détecter les services exposés sur toutes interfaces
   - Préparer audit SSI / niveau 40 / PRA-PCA
   - Cartographier rapidement l’exposition réseau IBM i

   COMPATIBLE :
   - IBM i avec QSYS2.NETSTAT_INFO disponible
   - ACS / Run SQL Scripts

   NIVEAU :
   SAFE / LECTURE SEULE
   ============================================================ */

SELECT
    CASE
        WHEN LOCAL_ADDRESS = '0.0.0.0'
            THEN 'EXPOSE_ALL_INTERFACES'

        WHEN LOCAL_ADDRESS = '127.0.0.1'
            THEN 'LOCALHOST_ONLY'

        ELSE 'BOUND_SPECIFIC_INTERFACE'
    END AS EXPOSURE_LEVEL,

    LOCAL_ADDRESS,
    LOCAL_PORT,
    LOCAL_PORT_NAME,

    PROTOCOL,
    TCP_STATE,

    BIND_USER,

    CASE
        WHEN LOCAL_PORT IN (21, 20)
            THEN 'FTP'

        WHEN LOCAL_PORT = 22
            THEN 'SSH/SFTP'

        WHEN LOCAL_PORT = 23
            THEN 'TELNET'

        WHEN LOCAL_PORT IN (80, 8080)
            THEN 'HTTP'

        WHEN LOCAL_PORT IN (443, 8443)
            THEN 'HTTPS'

        WHEN LOCAL_PORT = 8470
            THEN 'IBM i ADMIN'

        WHEN LOCAL_PORT = 8471
            THEN 'IBM i ADMIN SSL'

        WHEN LOCAL_PORT = 446
            THEN 'DRDA'

        ELSE 'AUTRE'
    END AS SERVICE_CATEGORY,

    CASE
        WHEN LOCAL_ADDRESS = '0.0.0.0'
             AND LOCAL_PORT IN (21,23,80)
            THEN 'CRITIQUE'

        WHEN LOCAL_ADDRESS = '0.0.0.0'
            THEN 'A_VERIFIER'

        ELSE 'OK'
    END AS SSI_LEVEL

FROM QSYS2.NETSTAT_INFO

WHERE TCP_STATE = 'LISTEN'

ORDER BY
    SSI_LEVEL DESC,
    LOCAL_PORT;

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