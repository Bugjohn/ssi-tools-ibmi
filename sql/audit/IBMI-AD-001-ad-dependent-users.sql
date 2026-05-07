----------------------------------------------------------------------
-- IBMI-AD-001-ad-dependent-users.sql
--
-- CHECK :
-- Comptes dépendants Active Directory / Kerberos
--
-- OBJECTIF :
-- Identifier les profils IBM i actifs dont le mot de passe
-- n’est pas géré localement par IBM i.
--
-- INDICATEUR TECHNIQUE :
-- LOCAL_PASSWORD_MANAGEMENT = 'NO'
--
-- SIGNIFICATION :
-- Le profil dépend d’un mécanisme externe de gestion/authentification,
-- typiquement Active Directory / Kerberos / EIM selon l’architecture.
--
-- RISQUE SSI :
-- En cas de compromission Active Directory, VPN ou Kerberos,
-- ces comptes peuvent représenter un point d’entrée vers IBM i.
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
-- Vérification rapide de la disponibilité de la vue QSYS2.USER_INFO.
--
-- Cette vue système IBM i contient les informations principales
-- des profils utilisateurs.
----------------------------------------------------------------------

SELECT TABLE_SCHEMA,
       TABLE_NAME
FROM QSYS2.SYSTABLES
WHERE TABLE_SCHEMA = 'QSYS2'
  AND TABLE_NAME = 'USER_INFO';

----------------------------------------------------------------------
-- AUDIT PRINCIPAL
--
-- Ce SELECT liste les profils :
-- - actifs,
-- - non système IBM i standard,
-- - dont la gestion locale du mot de passe est désactivée.
--
-- SUBSTR(AUTHORIZATION_NAME, 1, 1) <> 'Q'
-- permet d’exclure les profils système IBM i commençant par Q.
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
    SPECIAL_AUTHORITIES       AS SPECIAL_AUTHORITIES
FROM QSYS2.USER_INFO
WHERE STATUS = '*ENABLED'
  AND LOCAL_PASSWORD_MANAGEMENT = 'NO'
  AND SUBSTR(AUTHORIZATION_NAME, 1, 1) <> 'Q'
ORDER BY AUTHORIZATION_NAME;

----------------------------------------------------------------------
-- LECTURE DU RESULTAT
--
-- Si des lignes remontent :
-- cela ne signifie pas forcément une anomalie.
--
-- Cela signifie :
-- - qu’il existe des comptes actifs dépendants d’une authentification
--   ou gestion de mot de passe non locale IBM i,
-- - qu’ils doivent être analysés dans le contexte AD / Kerberos / EIM,
-- - qu’ils doivent être croisés avec les privilèges IBM i.
--
-- POINTS A VERIFIER :
-- - le compte est-il un compte utilisateur réel ?
-- - est-il utilisé par un batch ?
-- - est-il utilisé par une interface ?
-- - possède-t-il *ALLOBJ, *SECADM ou une classe élevée ?
-- - est-il présent dans EIM ?
-- - a-t-il un HOME_DIRECTORY sous /home ?
--
-- REMEDIATION POSSIBLE :
-- Aucune correction automatique dans ce script.
--
-- Les actions possibles seront traitées dans des scripts séparés :
-- - bascule LCLPWDMGT(*YES),
-- - reset mot de passe,
-- - désactivation,
-- - ajout en whitelist,
-- - durcissement AD/MFA.
----------------------------------------------------------------------