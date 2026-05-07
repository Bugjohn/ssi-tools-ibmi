--------------------------------------------------------------------------------
-- CHECK ID
-- IBMI-SSL-003
--
-- TITRE
-- Surveillance expiration certificats SSL/TLS IBM i
--
-- DOMAINE
-- SSL / OPS / PRA
--
-- TYPE
-- AUDIT ONLY
--
-- NIVEAU
-- SAFE
--
-- OBJECTIF
--
-- Identifier les certificats :
--   - expirés ;
--   - expirant sous 7 jours ;
--   - expirant sous 30 jours ;
--   - expirant sous 90 jours ;
--   - absents.
--
-- RISQUE SSI
--
-- Un certificat expiré peut provoquer :
--   - arrêt HTTPS ;
--   - échec FTPS ;
--   - échec API REST ;
--   - incident batch ;
--   - rupture PRA/PCA ;
--   - contournement temporaire dangereux type “repasse en HTTP”.
--
-- IMPACT NIVEAU 40
--
-- Le niveau 40 ne force pas l’expiration des certificats.
--
-- Mais il rend les accès plus stricts :
--   - store DCM mal accessible ;
--   - certificat non lisible ;
--   - batch exécuté par un profil sans droits ;
--   - application TLS KO.
--
-- PRE-CHECK
--
-- Vérifier :
--   - accès ACS Run SQL Scripts ;
--   - droit lecture sur QSYS2.CERTIFICATE_INFO ;
--   - présence des PTF nécessaires selon version IBM i.
--
-- DRYRUN
--
-- SAFE : lecture seule.
--
-- EXECUTE
--
-- Exécuter dans ACS.
--
-- LOGGING
--
-- Aucun logging : audit uniquement.
--
-- ROLLBACK
--
-- Aucun rollback nécessaire.
--
-- EXPORT CSV
--
-- ACS -> clic droit sur résultat -> Export Results.
--
-- HUMOUR IBM i TERRAIN
--
-- Le certificat expire toujours :
--   - un vendredi soir ;
--   - pendant les congés ;
--   - ou le jour où “on n’a rien touché”.
--
--------------------------------------------------------------------------------


--------------------------------------------------------------------------------
-- MINI-COURS TERRAIN
--
-- Un certificat SSL/TLS sert à :
--   - chiffrer les échanges ;
--   - authentifier un serveur ;
--   - établir une chaîne de confiance ;
--   - sécuriser HTTPS, FTPS, APIs, clients HTTP, etc.
--
-- Sur IBM i, les certificats sont souvent gérés via DCM.
--
-- Mais attention :
--
--   certificat présent
--       ≠
--   certificat valide
--       ≠
--   certificat utilisé
--       ≠
--   application réellement sécurisée
--
--------------------------------------------------------------------------------


--------------------------------------------------------------------------------
-- 1. INVENTAIRE GLOBAL DES CERTIFICATS AVEC STATUT
--------------------------------------------------------------------------------

SELECT
    'IBMI-SSL-003' AS CHECK_ID,
    'SAFE' AS SAFETY_LEVEL,

    CASE
        WHEN VALID_TO < CURRENT_TIMESTAMP
            THEN 'CRITICAL'
        WHEN VALID_TO < CURRENT_TIMESTAMP + 7 DAYS
            THEN 'HIGH'
        WHEN VALID_TO < CURRENT_TIMESTAMP + 30 DAYS
            THEN 'MEDIUM'
        WHEN VALID_TO < CURRENT_TIMESTAMP + 90 DAYS
            THEN 'LOW'
        ELSE 'INFO'
    END AS SEVERITY,

    CERTIFICATE_STORE,
    CERTIFICATE_LABEL,
    SUBJECT,
    ISSUER,
    VALID_FROM,
    VALID_TO,

    DAYS(DATE(VALID_TO)) - DAYS(CURRENT_DATE) AS DAYS_BEFORE_EXPIRATION,

    CASE
        WHEN VALID_TO < CURRENT_TIMESTAMP
            THEN 'EXPIRED'
        WHEN VALID_TO < CURRENT_TIMESTAMP + 7 DAYS
            THEN 'EXPIRES_IN_LESS_THAN_7_DAYS'
        WHEN VALID_TO < CURRENT_TIMESTAMP + 30 DAYS
            THEN 'EXPIRES_IN_LESS_THAN_30_DAYS'
        WHEN VALID_TO < CURRENT_TIMESTAMP + 90 DAYS
            THEN 'EXPIRES_IN_LESS_THAN_90_DAYS'
        ELSE 'VALID_MORE_THAN_90_DAYS'
    END AS CERTIFICATE_STATUS

FROM QSYS2.CERTIFICATE_INFO
ORDER BY VALID_TO;


--------------------------------------------------------------------------------
-- 2. CERTIFICATS EXPIRES
--------------------------------------------------------------------------------

SELECT
    'IBMI-SSL-003' AS CHECK_ID,
    'SAFE' AS SAFETY_LEVEL,
    'CRITICAL' AS SEVERITY,

    CERTIFICATE_STORE,
    CERTIFICATE_LABEL,
    SUBJECT,
    ISSUER,
    VALID_TO,

    'CERTIFICATE_EXPIRED' AS FINDING,

    'Certificat expiré : service TLS potentiellement indisponible ou non fiable'
        AS RISK,

    'Renouveler le certificat, vérifier DCM, puis tester les applications associées'
        AS ACTION

FROM QSYS2.CERTIFICATE_INFO
WHERE VALID_TO < CURRENT_TIMESTAMP
ORDER BY VALID_TO;


--------------------------------------------------------------------------------
-- 3. CERTIFICATS EXPIRANT SOUS 7 JOURS
--------------------------------------------------------------------------------

SELECT
    'IBMI-SSL-003' AS CHECK_ID,
    'SAFE' AS SAFETY_LEVEL,
    'HIGH' AS SEVERITY,

    CERTIFICATE_STORE,
    CERTIFICATE_LABEL,
    SUBJECT,
    VALID_TO,

    DAYS(DATE(VALID_TO)) - DAYS(CURRENT_DATE) AS DAYS_LEFT,

    'CERTIFICATE_EXPIRES_IN_LESS_THAN_7_DAYS' AS FINDING,

    'Risque imminent de coupure HTTPS / FTPS / API / batch'
        AS RISK,

    'Planifier renouvellement immédiat + test applicatif'
        AS ACTION

FROM QSYS2.CERTIFICATE_INFO
WHERE VALID_TO >= CURRENT_TIMESTAMP
  AND VALID_TO < CURRENT_TIMESTAMP + 7 DAYS
ORDER BY VALID_TO;


--------------------------------------------------------------------------------
-- 4. CERTIFICATS EXPIRANT SOUS 30 JOURS
--------------------------------------------------------------------------------

SELECT
    'IBMI-SSL-003' AS CHECK_ID,
    'SAFE' AS SAFETY_LEVEL,
    'MEDIUM' AS SEVERITY,

    CERTIFICATE_STORE,
    CERTIFICATE_LABEL,
    SUBJECT,
    VALID_TO,

    DAYS(DATE(VALID_TO)) - DAYS(CURRENT_DATE) AS DAYS_LEFT,

    'CERTIFICATE_EXPIRES_IN_LESS_THAN_30_DAYS' AS FINDING,

    'Renouvellement à planifier rapidement'
        AS RISK,

    'Créer ticket OPS/SSI et vérifier propriétaire applicatif'
        AS ACTION

FROM QSYS2.CERTIFICATE_INFO
WHERE VALID_TO >= CURRENT_TIMESTAMP + 7 DAYS
  AND VALID_TO < CURRENT_TIMESTAMP + 30 DAYS
ORDER BY VALID_TO;


--------------------------------------------------------------------------------
-- 5. CERTIFICATS EXPIRANT SOUS 90 JOURS
--------------------------------------------------------------------------------

SELECT
    'IBMI-SSL-003' AS CHECK_ID,
    'SAFE' AS SAFETY_LEVEL,
    'LOW' AS SEVERITY,

    CERTIFICATE_STORE,
    CERTIFICATE_LABEL,
    SUBJECT,
    VALID_TO,

    DAYS(DATE(VALID_TO)) - DAYS(CURRENT_DATE) AS DAYS_LEFT,

    'CERTIFICATE_EXPIRES_IN_LESS_THAN_90_DAYS' AS FINDING,

    'Anticipation PRA/PCA et maintenance préventive'
        AS RISK,

    'Planifier renouvellement avant fenêtre critique'
        AS ACTION

FROM QSYS2.CERTIFICATE_INFO
WHERE VALID_TO >= CURRENT_TIMESTAMP + 30 DAYS
  AND VALID_TO < CURRENT_TIMESTAMP + 90 DAYS
ORDER BY VALID_TO;


--------------------------------------------------------------------------------
-- 6. DETECTION ABSENCE TOTALE DE CERTIFICAT
--
-- Très important :
-- aucun résultat dans un inventaire ne veut pas dire “tout va bien”.
--
-- Ça peut vouloir dire :
--   - DCM jamais configuré ;
--   - aucun TLS ;
--   - flux historiques en clair ;
--   - “on est dans le LAN” version 2003.
--
--------------------------------------------------------------------------------

SELECT
    'IBMI-SSL-003' AS CHECK_ID,
    'SAFE' AS SAFETY_LEVEL,
    'CRITICAL' AS SEVERITY,

    'NO_CERTIFICATE_FOUND' AS FINDING,

    'Aucun certificat détecté dans QSYS2.CERTIFICATE_INFO'
        AS DETAILS,

    'Environnement potentiellement sans TLS exploitable'
        AS RISK,

    'Vérifier DCM, HTTPS, FTPS, API, certificats serveur et CA'
        AS ACTION

FROM SYSIBM.SYSDUMMY1
WHERE NOT EXISTS (
    SELECT 1
    FROM QSYS2.CERTIFICATE_INFO
);


--------------------------------------------------------------------------------
-- 7. RESUME EXECUTIF EXPORTABLE
--------------------------------------------------------------------------------

SELECT
    'IBMI-SSL-003' AS CHECK_ID,

    COUNT(*) AS TOTAL_CERTIFICATES,

    SUM(
        CASE
            WHEN VALID_TO < CURRENT_TIMESTAMP
                THEN 1
            ELSE 0
        END
    ) AS EXPIRED_CERTIFICATES,

    SUM(
        CASE
            WHEN VALID_TO >= CURRENT_TIMESTAMP
             AND VALID_TO < CURRENT_TIMESTAMP + 7 DAYS
                THEN 1
            ELSE 0
        END
    ) AS EXPIRES_7_DAYS,

    SUM(
        CASE
            WHEN VALID_TO >= CURRENT_TIMESTAMP
             AND VALID_TO < CURRENT_TIMESTAMP + 30 DAYS
                THEN 1
            ELSE 0
        END
    ) AS EXPIRES_30_DAYS,

    SUM(
        CASE
            WHEN VALID_TO >= CURRENT_TIMESTAMP
             AND VALID_TO < CURRENT_TIMESTAMP + 90 DAYS
                THEN 1
            ELSE 0
        END
    ) AS EXPIRES_90_DAYS,

    CURRENT_TIMESTAMP AS AUDIT_TS

FROM QSYS2.CERTIFICATE_INFO;


--------------------------------------------------------------------------------
-- FIN DU CHECK
--
-- FUTURS CHECKS LIES
--
--   IBMI-NET-002 : services réseau exposés
--   IBMI-IFS-002 : clés SSH et permissions .ssh
--   IBMI-OPS-001 : comptes batch et profils techniques
--
--------------------------------------------------------------------------------