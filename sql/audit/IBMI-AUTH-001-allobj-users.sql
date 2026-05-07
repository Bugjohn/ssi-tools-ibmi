----------------------------------------------------------------------
-- IBMI-AUTH-001-allobj-users.sql
--
-- CHECK :
-- Profils IBM i avec autorité spéciale *ALLOBJ
--
-- OBJECTIF :
-- Identifier les profils actifs disposant de l’autorité spéciale
-- *ALLOBJ.
--
-- SIGNIFICATION :
-- *ALLOBJ permet de contourner la majorité des contrôles
-- d’autorité objet IBM i.
--
-- Un profil disposant de *ALLOBJ peut :
-- - accéder à quasiment tous les objets,
-- - contourner certaines restrictions,
-- - lire/modifier des données sensibles,
-- - exécuter des actions d’administration avancées.
--
-- RISQUE SSI :
-- Très critique.
--
-- En cas de compromission :
-- - compromission totale potentielle du système,
-- - élévation de privilèges,
-- - accès transversal aux applications et données.
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
-- Le LIKE '%*ALLOBJ%' permet d’identifier les profils
-- possédant cette autorité spéciale.
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
  AND SPECIAL_AUTHORITIES LIKE '%*ALLOBJ%'
ORDER BY AUTHORIZATION_NAME;

----------------------------------------------------------------------
-- LECTURE DU RESULTAT
--
-- Les profils retournés disposent de l’autorité spéciale *ALLOBJ.
--
-- Cela ne signifie pas automatiquement une anomalie :
-- certains profils d’administration système nécessitent ce niveau.
--
-- En revanche :
-- chaque profil doit être justifié,
-- documenté,
-- validé SSI,
-- régulièrement audité.
--
-- POINTS DE VIGILANCE :
--
-- Vérifier :
-- - profils utilisateurs métier,
-- - comptes techniques,
-- - comptes batch,
-- - comptes applicatifs,
-- - comptes AD/Kerberos,
-- - comptes de service,
-- - comptes oubliés/historiques.
--
-- POINTS CRITIQUES :
--
-- Croiser ce résultat avec :
-- - IBMI-AD-001
-- - comptes VPN,
-- - accès SSH,
-- - HOME_DIRECTORY sous /home,
-- - comptes non expirants,
-- - comptes sans groupe,
-- - adopted authority des programmes.
--
-- RISQUES MAJEURS :
--
-- - propagation latérale depuis AD,
-- - ransomware,
-- - exfiltration massive,
-- - destruction objets,
-- - contournement niveau 40,
-- - accès IFS/QNTC/API.
--
-- REMEDIATION POSSIBLE :
--
-- Aucune correction automatique dans ce script.
--
-- Les actions doivent être traitées via procédures contrôlées :
-- - suppression *ALLOBJ,
-- - remplacement par AUTL/groupes,
-- - segmentation des rôles,
-- - comptes techniques dédiés,
-- - MFA AD,
-- - revue des privilèges.
----------------------------------------------------------------------

----------------------------------------------------------------------
-- RECOMMANDATION SSI
--
-- Les profils *ALLOBJ doivent être :
--
-- - extrêmement limités,
-- - nominatifs si possible,
-- - supervisés,
-- - journalisés,
-- - intégrés aux audits SSI réguliers.
--
-- En environnement moderne :
-- éviter l’utilisation applicative de *ALLOBJ.
----------------------------------------------------------------------