----------------------------------------------------------------------
-- IBMI-LIB-001-public-change-libraries.sql
--
-- CHECK :
-- Bibliothèques IBM i exposées à *PUBLIC avec droits élevés
--
-- OBJECTIF :
-- Identifier les bibliothèques dont l’autorité *PUBLIC
-- est configurée avec :
--
-- - *CHANGE
-- - *ALL
--
-- SIGNIFICATION :
-- *PUBLIC représente tous les utilisateurs du système
-- n’ayant pas d’autorité spécifique définie.
--
-- Une bibliothèque ouverte à *PUBLIC avec droits élevés
-- peut permettre :
--
-- - lecture non autorisée,
-- - modification de données,
-- - suppression objets,
-- - propagation ransomware,
-- - exécution applicative non maîtrisée.
--
-- RISQUE SSI :
-- HIGH à CRITICAL selon les objets contenus.
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
-- VUE IBM i UTILISEE :
-- QSYS2.OBJECT_PRIVILEGES
--
-- EXEMPLES :
-- LAB  : MonUserIbm
-- PROD : SSI_TOOLS
----------------------------------------------------------------------

----------------------------------------------------------------------
-- PRE-CHECK
--
-- Vérification disponibilité de OBJECT_PRIVILEGES.
----------------------------------------------------------------------

SELECT TABLE_SCHEMA,
       TABLE_NAME
FROM QSYS2.SYSTABLES
WHERE TABLE_SCHEMA = 'QSYS2'
  AND TABLE_NAME = 'OBJECT_PRIVILEGES';

----------------------------------------------------------------------
-- AUDIT PRINCIPAL
--
-- OBJECT_TYPE = '*LIB'
-- -> cible uniquement les bibliothèques IBM i.
--
-- AUTHORIZATION_NAME = '*PUBLIC'
-- -> cible les droits ouverts à tous.
--
-- OBJECT_AUTHORITY IN ('*CHANGE', '*ALL')
-- -> niveaux dangereux.
----------------------------------------------------------------------

SELECT
    SYSTEM_OBJECT_NAME     AS LIBRARY_NAME,
    OBJECT_TYPE            AS OBJECT_TYPE,
    AUTHORIZATION_NAME     AS AUTHORIZATION_NAME,
    OBJECT_AUTHORITY       AS PUBLIC_AUTHORITY,
    OWNER                  AS OBJECT_OWNER,
    PRIMARY_GROUP          AS PRIMARY_GROUP,
    AUTHORIZATION_LIST     AS AUTHORIZATION_LIST,
    TEXT_DESCRIPTION       AS DESCRIPTION
FROM QSYS2.OBJECT_PRIVILEGES
WHERE OBJECT_TYPE = '*LIB'
  AND AUTHORIZATION_NAME = '*PUBLIC'
  AND OBJECT_AUTHORITY IN ('*CHANGE', '*ALL')
ORDER BY SYSTEM_OBJECT_NAME;

----------------------------------------------------------------------
-- LECTURE DU RESULTAT
--
-- Les bibliothèques retournées sont ouvertes à *PUBLIC
-- avec des droits élevés.
--
-- Cela ne signifie pas automatiquement une faille :
-- certains environnements historiques IBM i fonctionnent
-- encore avec ce modèle.
--
-- MAIS :
-- cela représente souvent :
--
-- - une dette historique,
-- - une gouvernance faible,
-- - une exposition importante,
-- - un frein au niveau 40,
-- - un risque ransomware élevé.
--
-- POINTS DE VIGILANCE :
--
-- Vérifier particulièrement :
-- - bibliothèques applicatives,
-- - bibliothèques contenant données métier,
-- - bibliothèques interfaces,
-- - bibliothèques batch,
-- - bibliothèques contenant programmes RPG/CL,
-- - bibliothèques accessibles via ODBC/JDBC/API.
--
-- RISQUES MAJEURS :
--
-- - modification objets par utilisateurs non prévus,
-- - suppression données,
-- - propagation malware,
-- - contournement segmentation sécurité,
-- - difficulté audit conformité,
-- - compromission applicative.
--
-- IMPACT NIVEAU 40 :
--
-- Les environnements fortement ouverts à *PUBLIC
-- rencontrent souvent :
--
-- - erreurs d’autorité,
-- - comportements applicatifs cassés,
-- - difficultés de migration,
-- - dépendances implicites invisibles.
--
-- MODELE CIBLE RECOMMANDE :
--
-- PUBLIC = *EXCLUDE
--
-- Puis :
--
-- Utilisateurs
--     -> Groupes
--         -> AUTL
--             -> Objets
--
-- REMEDIATION POSSIBLE :
--
-- Aucune correction automatique dans ce script.
--
-- Les corrections doivent être planifiées :
--
-- - réduction progressive de *PUBLIC,
-- - création AUTL,
-- - segmentation groupes,
-- - audit dépendances applicatives,
-- - tests pré-production,
-- - accompagnement niveau 40.
----------------------------------------------------------------------

----------------------------------------------------------------------
-- NOTE IBM i TERRAIN 😅
--
-- Très souvent :
--
-- "Si on met PUBLIC=*EXCLUDE,
--  plus rien ne fonctionne."
--
-- Ce check aide justement à :
--
-- - identifier les dépendances historiques,
-- - reconstruire une gouvernance propre,
-- - préparer un vrai durcissement IBM i.
----------------------------------------------------------------------