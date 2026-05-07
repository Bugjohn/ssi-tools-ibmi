----------------------------------------------------------------------
-- 001-create-library.sql
--
-- PROJET :
-- SSI_TOOLS - IBM i Security Toolkit
--
-- OBJECTIF :
-- Créer la bibliothèque IBM i utilisée par le projet SSI_TOOLS.
--
-- Cette bibliothèque centralise :
-- - les tables SSI,
-- - les logs de sécurité,
-- - les vues SOC,
-- - les procédures d’urgence,
-- - les résultats d’audit,
-- - les objets SQL du projet.
--
-- TYPE :
-- INSTALL
--
-- NIVEAU DE RISQUE :
-- SAFE
--
-- IMPACT :
-- Création d’une bibliothèque IBM i via CREATE SCHEMA.
--
-- UTILISATION :
-- ACS -> Run SQL Scripts
--
-- MODE SUPPORTES :
-- - LAB  : bibliothèque personnelle utilisateur
-- - PROD : bibliothèque commune SSI_TOOLS
--
-- PARAMETRAGE :
-- Remplacer SSI_TOOLS par votre bibliothèque cible si besoin.
--
-- Exemples :
-- LAB  : MaBibUtilisateur
-- PROD : SSI_TOOLS
--
-- IMPORTANT :
-- CREATE SCHEMA crée automatiquement :
-- - un schéma SQL,
-- - une bibliothèque IBM i associée.
--
-- AUTEUR :
-- Projet SSI IBM i / SQL-first / ACS-first
----------------------------------------------------------------------

----------------------------------------------------------------------
-- ETAPE 1
-- Vérifier si la bibliothèque existe déjà
--
-- QSYS2.SYSSCHEMAS contient les schémas SQL visibles.
----------------------------------------------------------------------

SELECT SCHEMA_NAME,
       SYSTEM_SCHEMA_NAME
FROM QSYS2.SYSSCHEMAS
WHERE SCHEMA_NAME = 'SSI_TOOLS';

----------------------------------------------------------------------
-- ETAPE 2
-- Création de la bibliothèque
--
-- ATTENTION :
-- Si la bibliothèque existe déjà,
-- CREATE SCHEMA générera une erreur SQL.
--
-- Dans ce cas :
-- -> vérifier le résultat de l’étape 1
-- -> ne PAS relancer inutilement le script
----------------------------------------------------------------------

CREATE SCHEMA SSI_TOOLS;

----------------------------------------------------------------------
-- ETAPE 3
-- Ajouter une description documentaire
--
-- Le LABEL permet d’identifier rapidement
-- le rôle de la bibliothèque dans IBM i.
----------------------------------------------------------------------

LABEL ON SCHEMA SSI_TOOLS
IS 'SSI Tools - IBM i Security Toolkit';

----------------------------------------------------------------------
-- ETAPE 4
-- Vérification finale
----------------------------------------------------------------------

SELECT SCHEMA_NAME,
       SYSTEM_SCHEMA_NAME
FROM QSYS2.SYSSCHEMAS
WHERE SCHEMA_NAME = 'SSI_TOOLS';

----------------------------------------------------------------------
-- FIN DU SCRIPT
--
-- RESULTAT ATTENDU :
-- - bibliothèque créée,
-- - visible dans IBM i,
-- - utilisable dans ACS,
-- - prête à accueillir les objets SSI_TOOLS.
--
-- EXEMPLE :
-- SSI_TOOLS.SECURITY_ACTION_LOG
-- SSI_TOOLS.CHECK_RESULTS
-- SSI_TOOLS.INACTIVE_USER_AUDIT
----------------------------------------------------------------------
