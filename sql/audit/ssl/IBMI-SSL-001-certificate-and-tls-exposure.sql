--------------------------------------------------------------------------------
-- CHECK ID
-- IBMI-SSL-001
--
-- TITRE
-- Audit SSL/TLS - Certificats, DCM et exposition des flux IBM i
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
-- Identifier :
--   - si SSL/TLS semble utilisé sur IBM i ;
--   - si des certificats sont présents ;
--   - si des services réseau sécurisés existent ;
--   - si l’environnement semble fonctionner encore "en clair".
--
-- Ce script est volontairement pédagogique :
-- il sert autant d’outil SSI que de support de montée en compétence.
--
-- POURQUOI CE CONTROLE EST IMPORTANT
--
-- Beaucoup d’environnements IBM i historiques ont :
--   - FTP sans TLS,
--   - Telnet,
--   - APIs HTTP,
--   - vieux certificats expirés,
--   - DCM jamais configuré,
--   - batchs dépendants d’anciens flux non sécurisés.
--
-- Le classique :
--   "Pas besoin de SSL, on est dans le LAN."
--
-- Sauf qu’aujourd’hui :
--   - phishing,
--   - compromission VPN,
--   - rebond Active Directory,
--   - poste admin compromis,
--   - ransomware,
--   - mouvements latéraux,
-- transforment justement le LAN en terrain de jeu de l’attaquant.
--
-- En pratique :
-- "interne" ≠ "sécurisé".
--
-- RISQUE SSI
--
-- Sans TLS/SSL :
--   - identifiants exposés ;
--   - flux FTP lisibles ;
--   - APIs vulnérables ;
--   - interception réseau ;
--   - pivot interne simplifié ;
--   - non conformité SSI / ISO / RGPD.
--
-- IMPACT NIVEAU 40
--
-- Le niveau 40 ne force PAS SSL.
--
-- MAIS :
--   - les droits deviennent plus stricts ;
--   - les accès DCM/certificats doivent être corrects ;
--   - les vieux flux historiques cassent souvent ;
--   - les services batch/API doivent accéder explicitement aux stores.
--
-- PRE-CHECK
--
-- Vérifier :
--   - droits de lecture QSYS2 ;
--   - ACS Run SQL Scripts ;
--   - version IBM i compatible QSYS2.
--
-- DRYRUN
--
-- SAFE :
-- ce script ne modifie RIEN.
--
-- EXECUTE
--
-- Exécuter dans ACS :
-- Run SQL Scripts
--
-- LOGGING
--
-- Aucun logging :
-- audit lecture seule.
--
-- ROLLBACK
--
-- Aucun rollback nécessaire.
--
-- EXPORT CSV
--
-- ACS :
-- clic droit sur résultat -> Export Results
--
-- HUMOUR IBM i TERRAIN
--
-- "Le LAN est sécurisé."
-- -> phrase prononcée 14 minutes avant un ransomware.
--
--------------------------------------------------------------------------------


--------------------------------------------------------------------------------
-- MINI-COURS IBM i
--
-- DCM = Digital Certificate Manager
--
-- DCM permet :
--   - gérer les certificats ;
--   - gérer les CA ;
--   - associer certificats et applications IBM i ;
--   - gérer FTPS / HTTPS / APIs TLS.
--
-- Important :
-- avoir un certificat dans DCM
-- ≠
-- avoir réellement un service sécurisé.
--
-- Exemple classique :
--   "Oui on a SSL."
--
-- Puis :
--   - FTP = toujours en clair ;
--   - API = HTTP ;
--   - certificat expiré depuis 2022 ;
--   - batch incapable de lire le store.
--
--------------------------------------------------------------------------------


--------------------------------------------------------------------------------
-- 1. INVENTAIRE CERTIFICATS IBM i
--
-- Objectif :
-- Voir si le système expose des informations de certificats.
--
-- IMPORTANT :
-- Selon versions IBM i / PTF :
-- certaines vues peuvent ne pas exister.
--
--------------------------------------------------------------------------------

SELECT
    'IBMI-SSL-001'                            AS CHECK_ID,
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
ORDER BY VALID_TO;


--------------------------------------------------------------------------------
-- 2. DETECTION CERTIFICATS EXPIRES
--
-- Très fréquent sur IBM i historiques :
-- le certificat existe...
-- mais a expiré il y a longtemps.
--
--------------------------------------------------------------------------------

SELECT
    'IBMI-SSL-001'                            AS CHECK_ID,
    'SAFE'                                    AS SAFETY_LEVEL,
    'HIGH'                                    AS SEVERITY,
    CERTIFICATE_STORE,
    CERTIFICATE_LABEL,
    SUBJECT,
    VALID_TO,
    'CERTIFICATE_EXPIRED'                     AS FINDING,
    'SSL/TLS peut être inutilisable'          AS RISK
FROM QSYS2.CERTIFICATE_INFO
WHERE VALID_TO < CURRENT_TIMESTAMP
ORDER BY VALID_TO;


--------------------------------------------------------------------------------
-- 3. CERTIFICATS EXPIRANT BIENTOT
--
-- Anticipation PRA/PCA.
--
-- Beaucoup de crises IBM i :
-- "plus rien ne fonctionne"
-- = juste un certificat expiré vendredi soir.
--
--------------------------------------------------------------------------------

SELECT
    'IBMI-SSL-001'                            AS CHECK_ID,
    'SAFE'                                    AS SAFETY_LEVEL,
    'MEDIUM'                                  AS SEVERITY,
    CERTIFICATE_STORE,
    CERTIFICATE_LABEL,
    SUBJECT,
    VALID_TO,
    DAYS(VALID_TO - CURRENT_TIMESTAMP)        AS DAYS_LEFT,
    'CERTIFICATE_EXPIRING_SOON'               AS FINDING
FROM QSYS2.CERTIFICATE_INFO
WHERE VALID_TO BETWEEN CURRENT_TIMESTAMP
                  AND CURRENT_TIMESTAMP + 30 DAYS
ORDER BY VALID_TO;


--------------------------------------------------------------------------------
-- 4. DETECTION "AUCUN CERTIFICAT"
--
-- POINT SSI IMPORTANT :
--
-- Beaucoup d'environnements IBM i n'ont :
--   - aucun certificat ;
--   - aucun DCM configuré ;
--   - aucun flux TLS.
--
-- Ce SELECT permet de le SIGNALER explicitement.
--
--------------------------------------------------------------------------------

SELECT
    'IBMI-SSL-001'                                AS CHECK_ID,
    'SAFE'                                        AS SAFETY_LEVEL,
    'CRITICAL'                                    AS SEVERITY,
    'NO_CERTIFICATE_FOUND'                        AS FINDING,
    'Aucun certificat détecté dans QSYS2.CERTIFICATE_INFO'
                                                  AS DETAILS,
    'Flux potentiellement non chiffrés'           AS RISK,
    'Vérifier DCM, HTTPS, FTPS, APIs et TLS'
                                                  AS ACTION
FROM SYSIBM.SYSDUMMY1
WHERE NOT EXISTS (
    SELECT 1
    FROM QSYS2.CERTIFICATE_INFO
);


--------------------------------------------------------------------------------
-- 5. INVENTAIRE SERVICES RESEAU IBM i
--
-- Objectif :
-- Voir les services actifs.
--
-- Très utile pour :
--   - FTP ;
--   - Telnet ;
--   - SSH ;
--   - HTTP ;
--   - administration distante.
--
--------------------------------------------------------------------------------

SELECT
    'IBMI-SSL-001'                            AS CHECK_ID,
    'SAFE'                                    AS SAFETY_LEVEL,
    'INFO'                                    AS SEVERITY,
    SERVER_TYPE,
    SERVER_NAME,
    PORT,
    STATUS
FROM QSYS2.NETSTAT_SERVER_INFO
ORDER BY PORT;


--------------------------------------------------------------------------------
-- 6. DETECTION SERVICES HISTORIQUEMENT RISQUES
--
-- FTP/TELNET non chiffrés :
-- énorme classique IBM i.
--
--------------------------------------------------------------------------------

SELECT
    'IBMI-SSL-001'                            AS CHECK_ID,
    'SAFE'                                    AS SAFETY_LEVEL,
    'HIGH'                                    AS SEVERITY,
    SERVER_NAME,
    PORT,
    STATUS,
    CASE
        WHEN PORT = 21
            THEN 'FTP_NON_TLS_POTENTIEL'
        WHEN PORT = 23
            THEN 'TELNET_ACTIF'
        WHEN PORT = 80
            THEN 'HTTP_NON_TLS_POTENTIEL'
        ELSE 'SERVICE_A_VERIFIER'
    END                                       AS FINDING,
    'Flux potentiellement non chiffrés'       AS RISK
FROM QSYS2.NETSTAT_SERVER_INFO
WHERE PORT IN (21,23,80)
ORDER BY PORT;


--------------------------------------------------------------------------------
-- 7. DETECTION SSH / SFTP
--
-- Bonne pratique moderne IBM i.
--
-- Sujet futur important du projet :
-- migration FTP -> FTPS/SFTP.
--
--------------------------------------------------------------------------------

SELECT
    'IBMI-SSL-001'                            AS CHECK_ID,
    'SAFE'                                    AS SAFETY_LEVEL,
    'INFO'                                    AS SEVERITY,
    SERVER_NAME,
    PORT,
    STATUS,
    'SSH_OR_SFTP_DETECTED'                    AS FINDING
FROM QSYS2.NETSTAT_SERVER_INFO
WHERE PORT = 22
ORDER BY SERVER_NAME;


--------------------------------------------------------------------------------
-- 8. DETECTION "AUCUN SERVICE TLS MODERNE"
--
-- Si :
--   - pas HTTPS ;
--   - pas SSH ;
--   - pas FTPS connu ;
-- alors environnement probablement ancien / non durci.
--
--------------------------------------------------------------------------------

SELECT
    'IBMI-SSL-001'                                AS CHECK_ID,
    'SAFE'                                        AS SAFETY_LEVEL,
    'CRITICAL'                                    AS SEVERITY,
    'NO_MODERN_SECURE_SERVICE_DETECTED'           AS FINDING,
    'Aucun port HTTPS/SSH détecté'
                                                  AS DETAILS,
    'Environnement potentiellement en clair'
                                                  AS RISK,
    'Vérifier HTTPS, FTPS, SSH, DCM et TLS'
                                                  AS ACTION
FROM SYSIBM.SYSDUMMY1
WHERE NOT EXISTS (
    SELECT 1
    FROM QSYS2.NETSTAT_SERVER_INFO
    WHERE PORT IN (22,443,990)
);


--------------------------------------------------------------------------------
-- 9. RESUME PEDAGOGIQUE FINAL
--
-- Résumé lisible exportable CSV/SSI.
--
--------------------------------------------------------------------------------

SELECT
    'IBMI-SSL-001'                            AS CHECK_ID,

    CASE
        WHEN EXISTS (
            SELECT 1
            FROM QSYS2.CERTIFICATE_INFO
        )
        THEN 'CERTIFICATES_PRESENT'
        ELSE 'NO_CERTIFICATES'
    END                                       AS CERTIFICATE_STATE,

    CASE
        WHEN EXISTS (
            SELECT 1
            FROM QSYS2.NETSTAT_SERVER_INFO
            WHERE PORT IN (22,443,990)
        )
        THEN 'SECURE_SERVICES_DETECTED'
        ELSE 'NO_SECURE_SERVICES'
    END                                       AS TLS_SERVICE_STATE,

    CASE
        WHEN EXISTS (
            SELECT 1
            FROM QSYS2.NETSTAT_SERVER_INFO
            WHERE PORT IN (21,23,80)
        )
        THEN 'LEGACY_PROTOCOLS_PRESENT'
        ELSE 'NO_LEGACY_PROTOCOLS_DETECTED'
    END                                       AS LEGACY_PROTOCOLS,

    CURRENT_TIMESTAMP                         AS AUDIT_TS

FROM SYSIBM.SYSDUMMY1;


--------------------------------------------------------------------------------
-- FIN DU CHECK
--
-- PROCHAINES ETAPES POSSIBLES
--
--   IBMI-SSL-002
--   -> audit DCM / applications liées
--
--   IBMI-NET-002
--   -> services réseau exposés
--
--   IBMI-IFS-002
--   -> clés SSH / .ssh / permissions IFS
--
--   IBMI-OPS-001
--   -> comptes batch et services techniques
--
--------------------------------------------------------------------------------