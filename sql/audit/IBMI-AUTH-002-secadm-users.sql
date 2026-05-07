----------------------------------------------------------------------
-- IBMI-AUTH-002-secadm-users.sql
--
-- CHECK :
-- Profils IBM i avec autorité spéciale *SECADM
--
-- OBJECTIF :
-- Identifier les profils actifs disposant de l’autorité spéciale
-- *SECADM.
--
-- SIGNIFICATION :
-- *SECADM permet d’administrer la sécurité IBM i.
--
-- Un profil disposant de *SECADM peut notamment intervenir sur :
-- - la gestion des profils utilisateurs,
-- - certaines autorités,
-- - certains paramètres de sécurité,
-- - des opérations sensibles liées à la gouvernance des accès.
--
-- RISQUE SSI :
-- Élevé.
--
-- En cas de compromission :
-- - création ou modification de profils,
-- - contournement de certaines règles d’habilitation,
-- - préparation d’une élévation de privilèges,
-- - modification non maîtrisée des accès.
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
-- BIBLIOTHEQUE CIBLE :
-- Aucune table projet requise pour ce check.
--
-- EXEMPLES :
-- LAB  : MonUserIbm
-- PROD : SSI_TOOLS
----------------------------------------------------------------------

----------------------------------------------------------------------
-- PRE-CHECK
--
-- Vérification disponibilité de la vue USER_INFO.
----------------------------------------------------------------------

SELECT TABLE_SCHEMA,
       TABLE_NAME
FROM QSYS2.SYSTABLES
WHERE TABLE_SCHEMA = 'QSYS2'
  AND TABLE_NAME = 'USER_INFO';

----------------------------------------------------------------------
-- AUDIT PRINCIPAL
--
-- SPECIAL_AUTHORITIES contient la liste des autorités spéciales
-- affectées au profil IBM i.
--
-- Le LIKE '%*SECADM%' permet d’identifier les profils
-- disposant de cette autorité spéciale.
--
-- Seuls les profils actifs sont affichés.
----------------------------------------------------------------------

SELECT
    AUTHORIZATION_NAME        AS USER_NAME,
    STATUS                    AS USER_STATUS,
    USER_CLASS_NAME           AS USER_CLASS,
    SPECIAL_AUTHORITIES       AS SPECIAL_AUTHORITIES,
    LOCAL_PASSWORD_MANAGEMENT AS LOCAL_PASSWORD_MANAGEMENT,
    GROUP_PROFILE_NAME        AS PRIMARY_GROUP,
    SUPPLEMENTAL_GROUP_LIST   AS SUPPLEMENTAL_GROUPS,
    HOME_DIRECTORY            AS HOME_DIRECTORY,
    PREVIOUS_SIGNON           AS PREVIOUS_SIGNON
FROM QSYS2.USER_INFO
WHERE STATUS = '*ENABLED'
  AND SPECIAL_AUTHORITIES LIKE '%*SECADM%'
ORDER BY AUTHORIZATION_NAME;

----------------------------------------------------------------------
-- LECTURE DU RESULTAT
--
-- Les profils retournés disposent de l’autorité spéciale *SECADM.
--
-- Cela ne signifie pas automatiquement une anomalie :
-- certains profils d’administration sécurité peuvent en avoir besoin.
--
-- En revanche, chaque profil doit être :
-- - justifié,
-- - documenté,
-- - rattaché à un rôle clair,
-- - validé par la SSI,
-- - revu régulièrement.
--
-- POINTS DE VIGILANCE :
--
-- Vérifier :
-- - profils non nominatifs,
-- - comptes techniques,
-- - comptes AD/Kerberos,
-- - comptes avec HOME_DIRECTORY sous /home,
-- - comptes cumulant *SECADM et *ALLOBJ,
-- - comptes sans groupe principal,
-- - comptes inactifs.
--
-- CROISEMENTS RECOMMANDES :
--
-- - IBMI-AD-001  : comptes dépendants AD/Kerberos
-- - IBMI-AUTH-001 : comptes avec *ALLOBJ
-- - IBMI-USR-001 : comptes inactifs
-- - IBMI-GRP-001 : comptes sans groupe principal
--
-- REMEDIATION POSSIBLE :
--
-- Aucune correction automatique dans ce script.
--
-- Les actions possibles doivent passer par des procédures contrôlées :
-- - retrait de *SECADM si non justifié,
-- - séparation des rôles,
-- - création de profils d’administration dédiés,
-- - journalisation renforcée,
-- - validation SSI,
-- - MFA côté accès distant / AD si applicable.
----------------------------------------------------------------------

----------------------------------------------------------------------
-- RECOMMANDATION SSI
--
-- Les profils *SECADM doivent être limités aux vrais besoins
-- d’administration sécurité.
--
-- Ils ne doivent pas être utilisés comme comptes applicatifs,
-- comptes batch ou comptes utilisateur standard.
----------------------------------------------------------------------