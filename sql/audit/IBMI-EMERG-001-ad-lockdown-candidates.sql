-- ============================================================================
-- SSI_TOOLS – IBM i Security Toolkit
-- ============================================================================
-- CHECK_ID      : IBMI-EMERG-001
-- NOM           : Candidats lockdown en cas de compromission AD
-- DOMAINE       : EMERG / AD / AUTH
-- CLASSIFICATION: SAFE
-- TYPE          : AUDIT / EMERGENCY PREPARATION
-- EXECUTION     : ACS - Run SQL Scripts
--
-- OBJECTIF
-- --------
-- Identifier les profils IBM i actifs dépendants d’AD/Kerberos et possédant
-- des droits sensibles.
--
-- Pourquoi ?
-- Parce qu’en cas de compromission AD, les profils IBM i liés à AD deviennent
-- une zone de risque immédiate.
--
-- Ce script ne désactive rien.
-- Il prépare une liste de comptes à analyser rapidement par SSI / OPS.
--
--
-- RISQUE SSI
-- ----------
-- Un compte IBM i avec :
--
--   LOCAL_PASSWORD_MANAGEMENT = 'NO'
--
-- signifie généralement que la gestion du mot de passe local n’est pas portée
-- par IBM i mais par une mécanique externe : AD, Kerberos, EIM, SSO.
--
-- Ce n’est pas mauvais en soi.
-- C’est même souvent normal dans une architecture moderne.
--
-- Mais si AD est compromis :
--
--   compte AD compromis
--   -> authentification IBM i possible
--   -> droits IBM i hérités du profil
--   -> accès applications, données, programmes, batchs
--
-- Et si ce profil possède *ALLOBJ, *SECADM ou une classe sensible…
-- là, on n’est plus dans “un petit incident AD”.
-- On est dans “IBM i vient d’être invité à la soirée ransomware” 😅
--
--
-- IMPACT NIVEAU 40
-- ----------------
-- Le passage niveau 40 ne corrige pas une mauvaise gouvernance AD/IBM i.
--
-- Il faut donc identifier :
--   - les profils AD actifs ;
--   - les profils AD à privilèges ;
--   - les profils AD applicatifs ;
--   - les profils AD avec home directory ;
--   - les profils AD pouvant lancer commandes ou scripts.
--
-- Objectif :
-- disposer d’une shortlist claire pour :
--   - gestion de crise ;
--   - lockdown ciblé ;
--   - revue des habilitations ;
--   - documentation PRA/PCA ;
--   - durcissement niveau 40.
--
--
-- PRE-CHECK
-- ---------
-- Lecture seule.
-- Utilise QSYS2.USER_INFO.
--
-- DRYRUN
-- ------
-- Non applicable : audit uniquement.
--
-- EXECUTE
-- -------
-- Exécuter dans ACS / Run SQL Scripts.
--
-- LOGGING
-- -------
-- Aucun logging applicatif.
-- Export CSV recommandé pour runbook de crise.
--
-- ROLLBACK
-- --------
-- Non applicable.
--
-- EXPORT CSV
-- ----------
-- ACS -> clic droit -> Export Results -> CSV.
-- ============================================================================


-- ============================================================================
-- 1. PRE-CHECK – Profils dépendants AD/Kerberos actifs
-- ============================================================================

SELECT
    AUTHORIZATION_NAME,
    STATUS,
    USER_CLASS_NAME,
    LOCAL_PASSWORD_MANAGEMENT,
    HOME_DIRECTORY,
    GROUP_PROFILE_NAME,
    SUPPLEMENTAL_GROUP_LIST,
    SPECIAL_AUTHORITIES,
    PREVIOUS_SIGNON
FROM QSYS2.USER_INFO
WHERE LOCAL_PASSWORD_MANAGEMENT = 'NO'
  AND STATUS = '*ENABLED'
  AND SUBSTR(AUTHORIZATION_NAME, 1, 1) <> 'Q'
ORDER BY AUTHORIZATION_NAME;


-- ============================================================================
-- 2. AUDIT – Candidats lockdown AD sensibles
-- ============================================================================
-- Cette requête priorise les profils AD/Kerberos actifs selon leur dangerosité.
--
-- CRITICAL :
--   - *ALLOBJ
--   - *SECADM
--   - classe *SECOFR
--
-- HIGH :
--   - *PGMR
--   - *SYSOPR
--   - capacités non limitées
--
-- MEDIUM :
--   - profil AD actif avec home directory /home
--
-- IMPORTANT :
-- Ce script NE désactive PAS les comptes.
-- Il sert à préparer une décision SOC/OPS/SSI.
-- ============================================================================

SELECT
    AUTHORIZATION_NAME              AS USER_NAME,
    STATUS                          AS USER_STATUS,
    USER_CLASS_NAME                 AS USER_CLASS,
    LOCAL_PASSWORD_MANAGEMENT       AS LOCAL_PASSWORD_MANAGEMENT,

    GROUP_PROFILE_NAME              AS PRIMARY_GROUP,
    SUPPLEMENTAL_GROUP_LIST         AS SUPPLEMENTAL_GROUPS,
    SPECIAL_AUTHORITIES             AS SPECIAL_AUTHORITIES,

    LIMIT_CAPABILITIES              AS LIMIT_CAPABILITIES,
    HOME_DIRECTORY                  AS HOME_DIRECTORY,
    PREVIOUS_SIGNON                 AS PREVIOUS_SIGNON,

    CASE
        WHEN SPECIAL_AUTHORITIES LIKE '%*ALLOBJ%'
          OR SPECIAL_AUTHORITIES LIKE '%*SECADM%'
          OR USER_CLASS_NAME = '*SECOFR'
            THEN 'CRITICAL'

        WHEN USER_CLASS_NAME IN ('*PGMR', '*SYSOPR')
          OR LIMIT_CAPABILITIES = '*NO'
            THEN 'HIGH'

        WHEN HOME_DIRECTORY LIKE '/home/%'
            THEN 'MEDIUM'

        ELSE 'LOW'
    END                             AS SEVERITY,

    CASE
        WHEN SPECIAL_AUTHORITIES LIKE '%*ALLOBJ%' THEN
            'Profil AD avec *ALLOBJ : candidat lockdown prioritaire en cas de compromission AD.'
        WHEN SPECIAL_AUTHORITIES LIKE '%*SECADM%' THEN
            'Profil AD avec *SECADM : risque élevé sur administration sécurité.'
        WHEN USER_CLASS_NAME = '*SECOFR' THEN
            'Profil AD de classe *SECOFR : exposition critique.'
        WHEN USER_CLASS_NAME IN ('*PGMR', '*SYSOPR') THEN
            'Profil AD avec classe technique sensible : qualifier rapidement.'
        WHEN LIMIT_CAPABILITIES = '*NO' THEN
            'Profil AD pouvant lancer des commandes : risque opérationnel augmenté.'
        WHEN HOME_DIRECTORY LIKE '/home/%' THEN
            'Profil AD avec home directory : vérifier usages PASE, SSH, scripts, clés.'
        ELSE
            'Profil AD actif : à qualifier selon contexte métier.'
    END                             AS SSI_COMMENT

FROM QSYS2.USER_INFO

WHERE LOCAL_PASSWORD_MANAGEMENT = 'NO'
  AND STATUS = '*ENABLED'
  AND SUBSTR(AUTHORIZATION_NAME, 1, 1) <> 'Q'

ORDER BY
    CASE
        WHEN SPECIAL_AUTHORITIES LIKE '%*ALLOBJ%'
          OR SPECIAL_AUTHORITIES LIKE '%*SECADM%'
          OR USER_CLASS_NAME = '*SECOFR'
            THEN 1
        WHEN USER_CLASS_NAME IN ('*PGMR', '*SYSOPR')
          OR LIMIT_CAPABILITIES = '*NO'
            THEN 2
        WHEN HOME_DIRECTORY LIKE '/home/%'
            THEN 3
        ELSE 4
    END,
    AUTHORIZATION_NAME;