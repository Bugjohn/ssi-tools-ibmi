----------------------------------------------------------------------
-- 002-create-security-action-log.sql
--
-- PROJET :
-- SSI_TOOLS - IBM i Security Toolkit
--
-- OBJECTIF :
-- Créer la table centralisée de journalisation SSI.
--
-- UTILISATION :
-- Cette table est utilisée par :
-- - les scripts de remédiation,
-- - les procédures d’urgence,
-- - les opérations de sécurité,
-- - les futurs exports SIEM / reporting.
--
-- TYPE :
-- INSTALL
--
-- IMPACT :
-- Création d’une table SQL dans la bibliothèque SSI_TOOLS.
--
-- NIVEAU DE RISQUE :
-- SAFE
--
-- PARAMETRAGE :
-- Remplacer SSI_TOOLS par votre bibliothèque cible si besoin.
--
-- Exemples :
-- LAB  : MaBibUtilisateur
-- PROD : SSI_TOOLS
----------------------------------------------------------------------

----------------------------------------------------------------------
-- Vérification présence table
----------------------------------------------------------------------

SELECT TABLE_SCHEMA,
       TABLE_NAME
FROM QSYS2.SYSTABLES
WHERE TABLE_SCHEMA = 'SSI_TOOLS'
  AND TABLE_NAME   = 'SECURITY_ACTION_LOG';

----------------------------------------------------------------------
-- Création table de log SSI
----------------------------------------------------------------------

CREATE TABLE SSI_TOOLS.SECURITY_ACTION_LOG (

    ------------------------------------------------------------------
    -- Identifiant technique auto généré
    ------------------------------------------------------------------
    LOG_ID
        BIGINT
        GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    ------------------------------------------------------------------
    -- Identifiant du check
    -- Exemple :
    -- IBMI-AD-001
    ------------------------------------------------------------------
    CHECK_ID
        VARCHAR(32)
        NOT NULL,

    ------------------------------------------------------------------
    -- Type d’action :
    -- AUDIT
    -- REMEDIATION
    -- EMERGENCY
    ------------------------------------------------------------------
    ACTION_TYPE
        VARCHAR(20)
        NOT NULL,

    ------------------------------------------------------------------
    -- Utilisateur concerné
    ------------------------------------------------------------------
    USERNAME
        VARCHAR(128),

    ------------------------------------------------------------------
    -- Objet cible :
    -- bibliothèque,
    -- programme,
    -- fichier,
    -- profil,
    -- AUTL...
    ------------------------------------------------------------------
    TARGET_OBJECT
        VARCHAR(256),

    ------------------------------------------------------------------
    -- Description détaillée
    ------------------------------------------------------------------
    ACTION_DETAIL
        VARCHAR(1000),

    ------------------------------------------------------------------
    -- Informations complémentaires
    -- Exemple :
    -- inactive_days=90
    -- include_ad=YES
    ------------------------------------------------------------------
    CONTEXT_INFO
        VARCHAR(1000),

    ------------------------------------------------------------------
    -- Utilisateur IBM i ayant exécuté le script
    ------------------------------------------------------------------
    EXECUTED_BY
        VARCHAR(128)
        DEFAULT SESSION_USER,

    ------------------------------------------------------------------
    -- Mode d’exécution :
    -- DRYRUN
    -- EXECUTE
    ------------------------------------------------------------------
    EXECUTION_MODE
        VARCHAR(20)
        DEFAULT 'DRYRUN',

    ------------------------------------------------------------------
    -- Résultat :
    -- SUCCESS
    -- ERROR
    ------------------------------------------------------------------
    ACTION_STATUS
        VARCHAR(20)
        DEFAULT 'SUCCESS',

    ------------------------------------------------------------------
    -- Horodatage action
    ------------------------------------------------------------------
    ACTION_TS
        TIMESTAMP
        DEFAULT CURRENT_TIMESTAMP

);

----------------------------------------------------------------------
-- Documentation table
----------------------------------------------------------------------

LABEL ON TABLE SSI_TOOLS.SECURITY_ACTION_LOG
IS 'Central SSI security action log';

----------------------------------------------------------------------
-- Documentation colonnes
----------------------------------------------------------------------

LABEL ON COLUMN SSI_TOOLS.SECURITY_ACTION_LOG (

    CHECK_ID
        TEXT IS 'SSI check identifier',

    ACTION_TYPE
        TEXT IS 'Audit, remediation or emergency action',

    USERNAME
        TEXT IS 'Impacted IBM i user',

    TARGET_OBJECT
        TEXT IS 'Target object impacted',

    ACTION_DETAIL
        TEXT IS 'Detailed executed action',

    CONTEXT_INFO
        TEXT IS 'Execution context and parameters',

    EXECUTED_BY
        TEXT IS 'IBM i user who executed script',

    EXECUTION_MODE
        TEXT IS 'DRYRUN or EXECUTE',

    ACTION_STATUS
        TEXT IS 'SUCCESS or ERROR',

    ACTION_TS
        TEXT IS 'Execution timestamp'

);

----------------------------------------------------------------------
-- Vérification finale
----------------------------------------------------------------------

SELECT TABLE_SCHEMA,
       TABLE_NAME
FROM QSYS2.SYSTABLES
WHERE TABLE_SCHEMA = 'SSI_TOOLS'
  AND TABLE_NAME   = 'SECURITY_ACTION_LOG';