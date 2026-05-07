----------------------------------------------------------------------
-- IBMI-GRP-001-users-without-primary-group.sql
--
-- CHECK :
-- Profils IBM i sans groupe principal
--
-- OBJECTIF :
-- Identifier les profils actifs ne possédant pas de groupe principal.
--
-- SIGNIFICATION :
-- Un profil sans groupe principal est souvent :
-- - géré individuellement,
-- - affecté par des droits directs,
-- - difficile à maintenir,
-- - difficile à auditer,
-- - incompatible avec une approche moderne niveau 40.
--
-- RISQUE SSI :
-- MEDIUM à HIGH selon le contexte.
--
-- Environnement concerné :
-- - droits directs massifs,
-- - gouvernance faible,
-- - héritage historique IBM i,
-- - difficulté de segmentation des accès.
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
-- Résultat exportable CSV depuis ACS.
--
-- EXEMPLES :
-- LAB  : MonUserIbm
-- PROD : SSI_TOOLS
----------------------------------------------------------------------

----------------------------------------------------------------------
-- PRE-CHECK
----------------------------------------------------------------------

SELECT TABLE_SCHEMA,
       TABLE_NAME
FROM QSYS2.SYSTABLES
WHERE TABLE_SCHEMA = 'QSYS2'
  AND TABLE_NAME = 'USER_INFO';

----------------------------------------------------------------------
-- AUDIT PRINCIPAL
--
-- GROUP_PROFILE_NAME :
-- groupe principal IBM i.
--
-- SUPPLEMENTAL_GROUP_LIST :
-- groupes secondaires éventuels.
--
-- Ce check cible :
-- - profils actifs,
-- - sans groupe principal.
----------------------------------------------------------------------

SELECT
    AUTHORIZATION_NAME        AS USER_NAME,
    STATUS                    AS USER_STATUS,
    USER_CLASS_NAME           AS USER_CLASS,
    GROUP_PROFILE_NAME        AS PRIMARY_GROUP,
    SUPPLEMENTAL_GROUP_LIST   AS SUPPLEMENTAL_GROUPS,
    LOCAL_PASSWORD_MANAGEMENT AS LOCAL_PASSWORD_MANAGEMENT,
    HOME_DIRECTORY            AS HOME_DIRECTORY,
    PREVIOUS_SIGNON           AS PREVIOUS_SIGNON,
    SPECIAL_AUTHORITIES       AS SPECIAL_AUTHORITIES
FROM QSYS2.USER_INFO
WHERE STATUS = '*ENABLED'
  AND (
       GROUP_PROFILE_NAME = '*NONE'
       OR GROUP_PROFILE_NAME = ''
      )
ORDER BY AUTHORIZATION_NAME;

----------------------------------------------------------------------
-- LECTURE DU RESULTAT
--
-- Les profils retournés ne possèdent pas de groupe principal.
--
-- Cela ne signifie pas automatiquement une anomalie :
-- certains comptes techniques peuvent être volontairement isolés.
--
-- MAIS :
-- dans beaucoup d’environnements IBM i historiques,
-- cela révèle souvent :
--
-- - des droits attribués directement,
-- - une absence de gouvernance,
-- - une architecture ancienne,
-- - une difficulté future de durcissement.
--
-- POINTS DE VIGILANCE :
--
-- Vérifier particulièrement :
-- - profils utilisateurs métier,
-- - comptes administrateurs,
-- - comptes *ALLOBJ,
-- - comptes *SECADM,
-- - comptes AD/Kerberos,
-- - comptes batch,
-- - profils applicatifs,
-- - comptes historiques oubliés.
--
-- IMPACT NIVEAU 40 :
--
-- Les environnements fortement basés sur :
-- - droits directs,
-- - absence de groupes,
-- - absence d’AUTL,
-- peuvent rencontrer :
--
-- - erreurs d’autorité,
-- - comportements imprévisibles,
-- - difficultés de maintenance,
-- - explosion des habilitations.
--
-- RECOMMANDATION SSI :
--
-- Modèle cible recommandé :
--
-- Utilisateurs
--     -> Groupes
--         -> AUTL
--             -> Objets
--
-- Eviter :
-- - droits directs massifs,
-- - ALLOBJ applicatif,
-- - profils isolés non documentés.
--
-- REMEDIATION POSSIBLE :
--
-- Aucune correction automatique dans ce script.
--
-- Les corrections doivent être planifiées :
-- - création groupes,
-- - segmentation rôles,
-- - migration AUTL,
-- - suppression droits directs,
-- - revue sécurité.
----------------------------------------------------------------------

----------------------------------------------------------------------
-- NOTE IBM i TERRAIN 😅
--
-- Dans de nombreux environnements historiques :
--
-- "tout fonctionne"
-- MAIS :
-- personne ne sait vraiment pourquoi.
--
-- Ce check aide justement à reconstruire une gouvernance claire.
----------------------------------------------------------------------