--------------------------------------------------------------------------------
-- CHECK ID
-- IBMI-SSL-002
--
-- TITRE
-- Audit DCM / Applications SSL-TLS / Mapping certificats IBM i
--
-- DOMAINE
-- SSL / NET / OPS
--
-- TYPE
-- AUDIT ONLY (SAFE)
--
-- NIVEAU
-- SAFE
--
-- OBJECTIF
--
-- Identifier :
--   - les applications IBM i utilisant SSL/TLS ;
--   - les certificats associés ;
--   - les stores DCM utilisés ;
--   - les incohérences possibles ;
--   - les services réseau potentiellement non protégés.
--
-- Ce script aide à comprendre :
--   - comment IBM i utilise TLS ;
--   - pourquoi certains batchs/API cassent ;
--   - pourquoi le niveau 40 révèle les anciens bricolages.
--
--------------------------------------------------------------------------------
-- POURQUOI CE CONTROLE EST IMPORTANT
--
-- Sur IBM i :
-- "avoir un certificat"
-- ne veut PAS dire :
-- "avoir du TLS fonctionnel".
--
-- Cas très fréquents :
--
--   ✔ certificat présent
--   ❌ mais jamais associé à une application
--
--   ✔ HTTPS actif
--   ❌ mais FTP toujours en clair
--
--   ✔ API REST fonctionne en interactif
--   ❌ mais échoue en batch
--
--   ✔ DCM configuré
--   ❌ mais CA expirée
--
--   ✔ FTPS prévu
--   ❌ mais store inaccessible au compte batch
--
--------------------------------------------------------------------------------
-- MINI-COURS IBM i
--
-- DCM = Digital Certificate Manager
--
-- Il permet :
--   - stocker les certificats ;
--   - gérer les CA ;
--   - associer certificats et applications ;
--   - gérer TLS côté serveur et client.
--
-- IMPORTANT :
--
-- Sur IBM i :
--
--   Certificat
--        ≠
--   Service sécurisé
--
-- Il faut :
--   1. un certificat valide ;
--   2. une CA de confiance ;
--   3. une association DCM ;
--   4. un service configuré ;
--   5. des droits corrects ;
--   6. parfois un restart serveur.
--
--------------------------------------------------------------------------------
-- RISQUE SSI
--
-- Risques principaux :
--
--   - flux en clair ;
--   - MITM ;
--   - mots de passe exposés ;
--   - APIs non fiables ;
--   - échec FTPS/API après incident ;
--   - PRA/PCA inutilisable ;
--   - dépendance AD/Kerberos non maîtrisée.
--
--------------------------------------------------------------------------------
-- IMPACT NIVEAU 40
--
-- Niveau 40 :
--
--   - renforce le respect des droits ;
--   - casse les accès implicites ;
--   - expose les erreurs DCM historiques ;
--   - révèle les comptes batch mal configurés.
--
-- Beaucoup de :
--   "ça marchait avant"
-- deviennent :
--   "SSL handshake failed"
--
--------------------------------------------------------------------------------
-- PRE-CHECK
--
-- Vérifier :
--   - ACS Run SQL Scripts ;
--   - droits lecture QSYS2 ;
--   - présence des vues SSL selon version IBM i/PTF.
--
--------------------------------------------------------------------------------
-- DRYRUN
--
-- SAFE :
-- aucune modification système.
--
--------------------------------------------------------------------------------
-- EXECUTE
--
-- Exécuter dans ACS :
-- Run SQL Scripts
--
--------------------------------------------------------------------------------
-- LOGGING
--
-- Aucun :
-- lecture seule.
--
--------------------------------------------------------------------------------
-- ROLLBACK
--
-- Aucun rollback nécessaire.
--
--------------------------------------------------------------------------------
-- EXPORT CSV
--
-- ACS :
-- clic droit -> Export Results
--
--------------------------------------------------------------------------------
-- HUMOUR TERRAIN IBM i
--
-- "On a HTTPS."
--
-- Oui.
--
-- Sur le portail d’admin.
--
-- Mais le FTP de prod tourne encore en clair depuis 2004 😅
--
--------------------------------------------------------------------------------



--------------------------------------------------------------------------------
-- 1. INVENTAIRE DES CERTIFICATS DCM
--
-- Objectif :
-- Voir :
--   - stores ;
--   - labels ;
--   - validité ;
--   - CA ;
--   - expiration.
--
--------------------------------------------------------------------------------

SELECT
    'IBMI-SSL-002'                            AS CHECK_ID,
    'SAFE'                                    AS SAFETY_LEVEL,
    'INFO'                                    AS SEVERITY,
    CERTIFICATE_STORE,
    CERTIFICATE_LABEL,
    SUBJECT,
    ISSUER,
    VALID_FROM,
    VALID_TO,

    CASE
        WHEN VALID_TO < CURRENT_TIMESTAMP
            THEN 'EXPIRED'

        WHEN VALID_TO < CURRENT_TIMESTAMP + 30 DAYS
            THEN 'EXPIRING_SOON'

        ELSE 'VALID'
    END                                       AS CERT_STATUS

FROM QSYS2.CERTIFICATE_INFO
ORDER BY CERTIFICATE_STORE, CERTIFICATE_LABEL;



--------------------------------------------------------------------------------
-- 2. INVENTAIRE APPLICATIONS SSL IBM i
--
-- Objectif :
-- Voir les applications IBM i associées à TLS.
--
-- Selon version/PTF :
-- certaines colonnes peuvent varier.
--
--------------------------------------------------------------------------------

SELECT
    'IBMI-SSL-002'                            AS CHECK_ID,
    'SAFE'                                    AS SAFETY_LEVEL,
    'INFO'                                    AS SEVERITY,

    APPLICATION_ID,
    APPLICATION_NAME,
    CERTIFICATE_STORE,
    CERTIFICATE_LABEL

FROM QSYS2.CERTIFICATE_APPLICATION_INFO
ORDER BY APPLICATION_NAME;



--------------------------------------------------------------------------------
-- 3. APPLICATIONS SANS CERTIFICAT ASSOCIE
--
-- Cas critique :
--
-- Application TLS déclarée
-- MAIS :
-- pas de certificat utilisable.
--
-- Typiquement :
--   - HTTPS KO ;
--   - FTPS KO ;
--   - API KO ;
--   - batch KO.
--
--------------------------------------------------------------------------------

SELECT
    'IBMI-SSL-002'                            AS CHECK_ID,
    'SAFE'                                    AS SAFETY_LEVEL,
    'HIGH'                                    AS SEVERITY,

    APPLICATION_ID,
    APPLICATION_NAME,

    'NO_CERTIFICATE_ASSOCIATED'               AS FINDING,

    'Application TLS sans certificat exploitable'
                                                  AS RISK,

    'Verifier DCM et mapping certificat'
                                                  AS ACTION

FROM QSYS2.CERTIFICATE_APPLICATION_INFO
WHERE CERTIFICATE_LABEL IS NULL
   OR TRIM(CERTIFICATE_LABEL) = ''
ORDER BY APPLICATION_NAME;



--------------------------------------------------------------------------------
-- 4. CERTIFICATS EXPIRES UTILISES PAR APPLICATIONS
--
-- Très fréquent :
-- le certificat existe toujours,
-- mais il est expiré.
--
-- Résultat :
--   - APIs cassées ;
--   - FTPS refusé ;
--   - SSL handshake failed.
--
--------------------------------------------------------------------------------

SELECT
    'IBMI-SSL-002'                            AS CHECK_ID,
    'SAFE'                                    AS SAFETY_LEVEL,
    'CRITICAL'                                AS SEVERITY,

    A.APPLICATION_NAME,
    A.CERTIFICATE_LABEL,

    C.VALID_TO,

    'APPLICATION_USES_EXPIRED_CERTIFICATE'
                                                  AS FINDING,

    'TLS potentiellement inutilisable'
                                                  AS RISK

FROM QSYS2.CERTIFICATE_APPLICATION_INFO A
JOIN QSYS2.CERTIFICATE_INFO C
    ON A.CERTIFICATE_LABEL = C.CERTIFICATE_LABEL
WHERE C.VALID_TO < CURRENT_TIMESTAMP
ORDER BY C.VALID_TO;



--------------------------------------------------------------------------------
-- 5. DETECTION STORES VIDES
--
-- Très pédagogique :
--
-- Beaucoup d’environnements :
--   - ont créé DCM ;
--   - mais n’ont jamais réellement configuré TLS.
--
--------------------------------------------------------------------------------

SELECT
    'IBMI-SSL-002'                            AS CHECK_ID,
    'SAFE'                                    AS SAFETY_LEVEL,
    'MEDIUM'                                  AS SEVERITY,

    CERTIFICATE_STORE,

    COUNT(*)                                  AS NB_CERTIFICATES,

    CASE
        WHEN COUNT(*) = 0
            THEN 'EMPTY_STORE'
        ELSE 'STORE_IN_USE'
    END                                       AS STORE_STATUS

FROM QSYS2.CERTIFICATE_INFO
GROUP BY CERTIFICATE_STORE
ORDER BY CERTIFICATE_STORE;



--------------------------------------------------------------------------------
-- 6. DETECTION "AUCUNE APPLICATION TLS"
--
-- Cas historique IBM i :
--
--   - DCM jamais utilisé ;
--   - HTTPS absent ;
--   - FTPS absent ;
--   - tout en clair dans le LAN.
--
--------------------------------------------------------------------------------

SELECT
    'IBMI-SSL-002'                                AS CHECK_ID,
    'SAFE'                                        AS SAFETY_LEVEL,
    'CRITICAL'                                    AS SEVERITY,

    'NO_TLS_APPLICATION_MAPPING'                  AS FINDING,

    'Aucune application IBM i liée à un certificat'
                                                    AS DETAILS,

    'TLS probablement non utilisé'
                                                    AS RISK,

    'Verifier DCM, HTTP ADMIN, FTPS, APIs'
                                                    AS ACTION

FROM SYSIBM.SYSDUMMY1
WHERE NOT EXISTS (
    SELECT 1
    FROM QSYS2.CERTIFICATE_APPLICATION_INFO
);



--------------------------------------------------------------------------------
-- 7. DETECTION SERVICES TLS MODERNES
--
-- Vérification complémentaire réseau.
--
--------------------------------------------------------------------------------

SELECT
    'IBMI-SSL-002'                            AS CHECK_ID,
    'SAFE'                                    AS SAFETY_LEVEL,
    'INFO'                                    AS SEVERITY,

    SERVER_NAME,
    PORT,
    STATUS,

    CASE
        WHEN PORT = 443
            THEN 'HTTPS_DETECTED'

        WHEN PORT = 990
            THEN 'FTPS_DETECTED'

        WHEN PORT = 22
            THEN 'SSH_OR_SFTP_DETECTED'

        ELSE 'OTHER_TLS_SERVICE'
    END                                       AS FINDING

FROM QSYS2.NETSTAT_SERVER_INFO
WHERE PORT IN (22,443,990)
ORDER BY PORT;



--------------------------------------------------------------------------------
-- 8. DETECTION SERVICES HISTORIQUES EN CLAIR
--
-- Très important pour migration FTPS/SFTP future.
--
--------------------------------------------------------------------------------

SELECT
    'IBMI-SSL-002'                            AS CHECK_ID,
    'SAFE'                                    AS SAFETY_LEVEL,
    'HIGH'                                    AS SEVERITY,

    SERVER_NAME,
    PORT,
    STATUS,

    CASE
        WHEN PORT = 21
            THEN 'FTP_IN_CLEAR'

        WHEN PORT = 23
            THEN 'TELNET_ACTIVE'

        WHEN PORT = 80
            THEN 'HTTP_IN_CLEAR'

        ELSE 'LEGACY_PROTOCOL'
    END                                       AS FINDING,

    'Flux potentiellement non chiffrés'
                                                  AS RISK

FROM QSYS2.NETSTAT_SERVER_INFO
WHERE PORT IN (21,23,80)
ORDER BY PORT;



--------------------------------------------------------------------------------
-- 9. RESUME PEDAGOGIQUE FINAL
--
-- Exportable CSV / comité SSI / audit.
--
--------------------------------------------------------------------------------

SELECT
    'IBMI-SSL-002'                            AS CHECK_ID,

    CASE
        WHEN EXISTS (
            SELECT 1
            FROM QSYS2.CERTIFICATE_INFO
        )
        THEN 'CERTIFICATES_PRESENT'

        ELSE 'NO_CERTIFICATES'
    END                                       AS CERTIFICATES,

    CASE
        WHEN EXISTS (
            SELECT 1
            FROM QSYS2.CERTIFICATE_APPLICATION_INFO
        )
        THEN 'TLS_APPLICATIONS_PRESENT'

        ELSE 'NO_TLS_APPLICATIONS'
    END                                       AS APPLICATION_MAPPING,

    CASE
        WHEN EXISTS (
            SELECT 1
            FROM QSYS2.NETSTAT_SERVER_INFO
            WHERE PORT IN (22,443,990)
        )
        THEN 'MODERN_SECURE_SERVICES_DETECTED'

        ELSE 'NO_MODERN_SECURE_SERVICES'
    END                                       AS MODERN_SERVICES,

    CASE
        WHEN EXISTS (
            SELECT 1
            FROM QSYS2.NETSTAT_SERVER_INFO
            WHERE PORT IN (21,23,80)
        )
        THEN 'LEGACY_CLEAR_PROTOCOLS_PRESENT'

        ELSE 'NO_LEGACY_CLEAR_PROTOCOLS'
    END                                       AS LEGACY_PROTOCOLS,

    CURRENT_TIMESTAMP                         AS AUDIT_TS

FROM SYSIBM.SYSDUMMY1;



--------------------------------------------------------------------------------
-- 10. MINI-COURS TERRAIN :
-- "POURQUOI CA MARCHE EN INTERACTIF MAIS PAS EN BATCH"
--
-- Cas réel extrêmement fréquent.
--
-- Interactif :
--   - profil admin ;
--   - accès DCM OK ;
--   - environnement chargé ;
--   - droits implicites.
--
-- Batch :
--   - autre user ;
--   - pas accès store ;
--   - pas accès IFS ;
--   - mapping absent ;
--   - certificat inaccessible.
--
-- Résultat :
--   SSL handshake failed
--
--------------------------------------------------------------------------------



--------------------------------------------------------------------------------
-- FIN DU CHECK
--
-- FUTURS CHECKS LIES
--
--   IBMI-SSL-003
--   -> audit expiration certificats avancé
--
--   IBMI-NET-002
--   -> audit services réseau exposés
--
--   IBMI-IFS-002
--   -> audit .ssh / clés / permissions
--
--   IBMI-OPS-001
--   -> audit comptes batch
--
--   IBMI-NET-003
--   -> migration FTP -> FTPS/SFTP
--
--------------------------------------------------------------------------------