-- ============================================================================
-- SSI_TOOLS – IBM i Security Toolkit
-- ============================================================================
-- CHECK_ID      : IBMI-NET-001
-- NOM           : Exposition FTP et profils utilisateurs associés
-- DOMAINE       : NET
-- CLASSIFICATION: SAFE
-- TYPE          : AUDIT / NETWORK EXPOSURE
-- EXECUTION     : ACS - Run SQL Scripts
--
-- OBJECTIF
-- --------
-- Identifier les profils IBM i pouvant représenter un risque dans le cadre
-- d’échanges FTP / FTPS / transferts automatisés.
--
-- Pourquoi ce contrôle est important ?
--
-- Parce que sur énormément d’environnements IBM i historiques :
--
--   - le FTP a été utilisé partout ;
--   - les mots de passe batch ont été partagés ;
--   - les comptes techniques ont été oubliés ;
--   - les flux applicatifs n’ont jamais été documentés ;
--   - et certains échanges tournent encore depuis 2007 “parce que ça marche”.
--
-- Résultat :
-- le FTP devient souvent :
--   - une dette sécurité ;
--   - une dette documentaire ;
--   - et parfois une porte d’entrée idéale.
--
--
-- RISQUE SSI
-- ----------
-- Les risques classiques liés aux comptes FTP IBM i :
--
--   - mots de passe jamais expirés ;
--   - comptes batch trop puissants ;
--   - profils AD utilisés pour transferts ;
--   - accès IFS trop ouverts ;
--   - réutilisation de comptes techniques ;
--   - comptes avec *ALLOBJ ;
--   - absence de traçabilité ;
--   - scripts FTP stockant les credentials.
--
-- Et historiquement…
-- beaucoup d’interfaces critiques tournent encore avec :
--
--   USER = FTPBATCH
--   PASSWORD = connu par toute l’équipe 
--
--
-- RAPPEL IMPORTANT
-- ----------------
-- FTP n’est pas forcément “mauvais”.
--
-- MAIS :
-- aujourd’hui les bonnes pratiques privilégient :
--
--   - FTPS ;
--   - SFTP ;
--   - APIs HTTPS ;
--   - comptes dédiés ;
--   - mots de passe robustes ;
--   - clés SSH ;
--   - cloisonnement des accès.
--
--
-- IMPACT NIVEAU 40
-- ----------------
-- Le passage niveau 40 pousse généralement à :
--
--   - revoir les comptes techniques ;
--   - réduire les droits excessifs ;
--   - documenter les flux ;
--   - sécuriser l’IFS ;
--   - maîtriser les accès réseau ;
--   - contrôler les comptes batch.
--
-- Les vieux comptes FTP “qui servent à tout” deviennent rapidement
-- problématiques en audit SSI.
--
--
-- BONNES PRATIQUES
-- ----------------
-- Modèle recommandé :
--
--   - un compte technique par flux ;
--   - pas de compte nominatif ;
--   - pas de *ALLOBJ ;
--   - accès IFS limités ;
--   - expiration maîtrisée ;
--   - logs d’échange ;
--   - supervision ;
--   - migration progressive vers SFTP/HTTPS.
--
--
-- PRE-CHECK
-- ---------
-- Lecture seule.
-- Utilise QSYS2.USER_INFO.
--
--
-- DRYRUN
-- ------
-- Non applicable.
--
--
-- EXECUTE
-- -------
-- Exécuter dans ACS / Run SQL Scripts.
--
--
-- LOGGING
-- -------
-- Aucun logging applicatif.
-- Export CSV recommandé.
--
--
-- ROLLBACK
-- --------
-- Non applicable.
--
--
-- EXPORT CSV
-- ----------
-- ACS :
-- clic droit -> Export Results -> CSV.
-- ============================================================================


-- ============================================================================
-- 1. PRE-CHECK – Comptes actifs avec home directory
-- ============================================================================
-- Les comptes utilisés pour FTP/SFTP disposent souvent d’un HOME_DIRECTORY.
-- ============================================================================

SELECT
    AUTHORIZATION_NAME,
    STATUS,
    HOME_DIRECTORY,
    LOCAL_PASSWORD_MANAGEMENT,
    PASSWORD_EXPIRATION_INTERVAL,
    SPECIAL_AUTHORITIES
FROM QSYS2.USER_INFO
WHERE STATUS = '*ENABLED'
  AND HOME_DIRECTORY IS NOT NULL
  AND HOME_DIRECTORY <> ''
ORDER BY AUTHORIZATION_NAME;


-- ============================================================================
-- 2. AUDIT – Comptes potentiellement exposés pour transferts FTP/SFTP
-- ============================================================================
-- Heuristiques utilisées :
--
--   - HOME_DIRECTORY présent ;
--   - mot de passe non expirant ;
--   - compte AD/Kerberos ;
--   - droits élevés ;
--   - capacités non limitées ;
--   - profils techniques/batch fréquents.
--
-- IMPORTANT :
-- Ce script identifie des candidats à qualifier.
-- Il ne prouve PAS qu’un compte est utilisé en FTP.
-- ============================================================================

SELECT
    AUTHORIZATION_NAME                  AS USER_NAME,
    STATUS                              AS USER_STATUS,
    USER_CLASS_NAME                     AS USER_CLASS,

    HOME_DIRECTORY                      AS HOME_DIRECTORY,

    LOCAL_PASSWORD_MANAGEMENT           AS LOCAL_PASSWORD_MANAGEMENT,

    PASSWORD_EXPIRATION_INTERVAL        AS PASSWORD_EXPIRATION_INTERVAL,

    LIMIT_CAPABILITIES                  AS LIMIT_CAPABILITIES,

    GROUP_PROFILE_NAME                  AS PRIMARY_GROUP,

    SPECIAL_AUTHORITIES                 AS SPECIAL_AUTHORITIES,

    PREVIOUS_SIGNON                     AS PREVIOUS_SIGNON,

    CASE
        WHEN SPECIAL_AUTHORITIES LIKE '%*ALLOBJ%'
            THEN 'CRITICAL'

        WHEN LIMIT_CAPABILITIES = '*NO'
            THEN 'HIGH'

        WHEN LOCAL_PASSWORD_MANAGEMENT = 'NO'
            THEN 'HIGH'

        WHEN PASSWORD_EXPIRATION_INTERVAL = 0
            THEN 'HIGH'

        WHEN HOME_DIRECTORY LIKE '/home/%'
            THEN 'MEDIUM'

        ELSE 'LOW'
    END                                 AS SEVERITY,

    CASE
        WHEN SPECIAL_AUTHORITIES LIKE '%*ALLOBJ%' THEN
            'Compte potentiellement utilisé pour transfert avec *ALLOBJ : risque majeur.'
        WHEN LIMIT_CAPABILITIES = '*NO' THEN
            'Compte pouvant exécuter commandes/scripts : vérifier usages batch/FTP.'
        WHEN LOCAL_PASSWORD_MANAGEMENT = 'NO' THEN
            'Compte AD/Kerberos utilisé potentiellement pour flux réseau.'
        WHEN PASSWORD_EXPIRATION_INTERVAL = 0 THEN
            'Mot de passe non expirant : pratique historique fréquente sur comptes FTP.'
        WHEN HOME_DIRECTORY LIKE '/home/%' THEN
            'Compte avec environnement IFS actif : vérifier usages SFTP/SSH/API.'
        ELSE
            'Compte à qualifier selon usages applicatifs.'
    END                                 AS SSI_COMMENT

FROM QSYS2.USER_INFO

WHERE STATUS = '*ENABLED'
  AND SUBSTR(AUTHORIZATION_NAME, 1, 1) <> 'Q'

  AND (
        HOME_DIRECTORY LIKE '/home/%'
        OR PASSWORD_EXPIRATION_INTERVAL = 0
        OR LOCAL_PASSWORD_MANAGEMENT = 'NO'
        OR LIMIT_CAPABILITIES = '*NO'
        OR SPECIAL_AUTHORITIES LIKE '%*ALLOBJ%'
      )

ORDER BY
    CASE
        WHEN SPECIAL_AUTHORITIES LIKE '%*ALLOBJ%' THEN 1
        WHEN LIMIT_CAPABILITIES = '*NO' THEN 2
        WHEN LOCAL_PASSWORD_MANAGEMENT = 'NO' THEN 3
        WHEN PASSWORD_EXPIRATION_INTERVAL = 0 THEN 4
        ELSE 5
    END,
    AUTHORIZATION_NAME;