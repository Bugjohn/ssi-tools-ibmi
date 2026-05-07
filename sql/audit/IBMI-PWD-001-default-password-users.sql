----------------------------------------------------------------------
-- IBMI-PWD-001-default-password-users.sql
--
-- CHECK :
-- Profils IBM i utilisant un mot de passe par défaut
--
-- OBJECTIF :
-- Identifier les profils actifs dont le mot de passe est encore
-- considéré comme un mot de passe par défaut IBM i.
--
-- SIGNIFICATION :
-- Sur IBM i, un profil peut être marqué comme utilisant
-- un mot de passe par défaut.
--
-- Historiquement :
-- cela signifie souvent :
-- - mot de passe identique au nom utilisateur,
-- - mot de passe faible,
-- - mot de passe initial jamais changé.
--
-- RISQUE SSI :
-- Très élevé.
--
-- En cas d’exposition :
-- - compromission rapide,
-- - attaques par dictionnaire,
-- - propagation latérale,
-- - compromission VPN/5250/SSH/API.
--
-- TYPE :
-- AUDIT
--
-- NIVEAU DE RISQUE DU SCRIPT :
-- SAFE
--
-- IMPACT :
-- Aucun impact système.
-- Lecture seule uniquement.
--
-- UTILISATION :
-- ACS -> Run SQL Scripts
--
-- EXPORT :
-- Résultat exportable en CSV depuis ACS.
--
-- COMPATIBILITE :
-- Certaines versions IBM i utilisent :
-- - DEFAULT_PASSWORD
-- ou :
-- - USER_DEFAULT_PASSWORD
--
-- Vérifier les colonnes disponibles si besoin.
--
-- BIBLIOTHEQUE CIBLE :
-- Aucune table projet requise.
--
-- EXEMPLES :
-- LAB  : MonUserIbm
-- PROD : SSI_TOOLS
----------------------------------------------------------------------

----------------------------------------------------------------------
-- PRE-CHECK
--
-- Vérification présence de USER_INFO.
----------------------------------------------------------------------

SELECT TABLE_SCHEMA,
       TABLE_NAME
FROM QSYS2.SYSTABLES
WHERE TABLE_SCHEMA = 'QSYS2'
  AND TABLE_NAME = 'USER_INFO';

----------------------------------------------------------------------
-- PRE-CHECK COMPLEMENTAIRE
--
-- Vérifier les colonnes réellement disponibles
-- selon la version IBM i.
--
-- IMPORTANT :
-- Certaines releases utilisent :
-- DEFAULT_PASSWORD
--
-- D’autres :
-- USER_DEFAULT_PASSWORD
----------------------------------------------------------------------

SELECT COLUMN_NAME
FROM QSYS2.SYSCOLUMNS
WHERE TABLE_SCHEMA = 'QSYS2'
  AND TABLE_NAME   = 'USER_INFO'
  AND COLUMN_NAME LIKE '%DEFAULT%PASSWORD%'
ORDER BY COLUMN_NAME;

----------------------------------------------------------------------
-- AUDIT PRINCIPAL
--
-- Ce SELECT identifie les profils actifs utilisant encore
-- un mot de passe par défaut.
--
-- IMPORTANT :
-- Adapter la colonne si nécessaire selon votre version IBM i.
----------------------------------------------------------------------

SELECT
    AUTHORIZATION_NAME        AS USER_NAME,
    STATUS                    AS USER_STATUS,
    USER_CLASS_NAME           AS USER_CLASS,
    LOCAL_PASSWORD_MANAGEMENT AS LOCAL_PASSWORD_MANAGEMENT,
    GROUP_PROFILE_NAME        AS PRIMARY_GROUP,
    SUPPLEMENTAL_GROUP_LIST   AS SUPPLEMENTAL_GROUPS,
    HOME_DIRECTORY            AS HOME_DIRECTORY,
    PREVIOUS_SIGNON           AS PREVIOUS_SIGNON,
    SPECIAL_AUTHORITIES       AS SPECIAL_AUTHORITIES,
    DEFAULT_PASSWORD          AS DEFAULT_PASSWORD
FROM QSYS2.USER_INFO
WHERE STATUS = '*ENABLED'
  AND DEFAULT_PASSWORD = 'YES'
ORDER BY AUTHORIZATION_NAME;

----------------------------------------------------------------------
-- LECTURE DU RESULTAT
--
-- Les profils retournés utilisent un mot de passe considéré
-- comme mot de passe par défaut IBM i.
--
-- Cela représente généralement :
-- - un mot de passe faible,
-- - un mot de passe historique,
-- - un mot de passe jamais changé,
-- - un risque critique d’accès non autorisé.
--
-- POINTS DE VIGILANCE :
--
-- Vérifier particulièrement :
-- - comptes techniques,
-- - comptes batch,
-- - comptes AD/Kerberos,
-- - comptes avec *ALLOBJ,
-- - comptes avec *SECADM,
-- - comptes VPN,
-- - comptes SSH/PASE,
-- - profils applicatifs oubliés.
--
-- CROISEMENTS RECOMMANDES :
--
-- - IBMI-AD-001
-- - IBMI-AUTH-001
-- - IBMI-AUTH-002
-- - IBMI-GRP-001
--
-- REMEDIATION POSSIBLE :
--
-- Aucune correction automatique dans ce script.
--
-- Les corrections doivent être réalisées via :
-- - changement mot de passe,
-- - expiration forcée,
-- - activation MFA côté AD/VPN,
-- - désactivation comptes inutilisés,
-- - séparation comptes techniques/utilisateurs.
----------------------------------------------------------------------

----------------------------------------------------------------------
-- RECOMMANDATION SSI
--
-- Aucun profil actif ne devrait conserver
-- un mot de passe par défaut.
--
-- Les comptes techniques doivent :
-- - être documentés,
-- - être protégés,
-- - être régulièrement audités.
----------------------------------------------------------------------