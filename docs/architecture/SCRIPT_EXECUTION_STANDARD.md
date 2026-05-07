# SCRIPT EXECUTION STANDARD – SSI_TOOLS

## 1. Objectif

Ce document définit les règles standardisées d’écriture et d’exécution des scripts SQL du projet SSI_TOOLS.

L’objectif est de garantir :

- la sécurité des opérations,
- la lisibilité des scripts,
- la compréhension par les équipes IBM i,
- la traçabilité des actions,
- la réduction des erreurs humaines,
- la compatibilité ACS / SQL-first.

---

# 2. Philosophie générale

Le projet SSI_TOOLS applique toujours la logique suivante :

Voir d’abord.
Comprendre ensuite.
Corriger seulement après validation.
Tracer systématiquement.
Aucun script ne doit effectuer de modification système sans :
explication préalable,
phase DRYRUN,
documentation,
journalisation.

## 3. Types de scripts

Type Description
AUDIT Lecture seule
INVENTORY Cartographie / inventaire
REMEDIATION Correction contrôlée
EMERGENCY Action de crise
INSTALL Installation structure projet
ROLLBACK Retour arrière

## 4. Niveaux de risque

SAFE
Lecture seule.
Aucun impact système.
Exemples :
SELECT,
vues,
inventaires,
exports.
CONTROLLED
Modification limitée et contrôlée.
Exemples :
changement d’autorité,
ajout groupe,
changement owner.
DANGEROUS
Impact important possible.
Exemples :
désactivation utilisateurs,
changement massif d’autorisations,
modifications objets critiques.
CRITICAL
Action de crise ou risque majeur.
Exemples :
lockdown,
reset massif,
confinement,
suppression accès.

## 5. Structure obligatoire des scripts

Chaque script doit contenir :
Bloc Obligatoire
HEADER DOCUMENTAIRE Oui
OBJECTIF Oui
RISQUE SSI Oui
PRE-REQUIS Oui
DRYRUN Oui si modification
EXECUTE Oui si modification
LOGGING Oui
ROLLBACK Recommandé
EXPORT CSV Recommandé

## 6. HEADER standard

Chaque script doit commencer par un header documenté.
Exemple :

---

## -- IBMI-AD-001

-- CHECK :
-- Comptes dépendants Active Directory / Kerberos
--
-- OBJECTIF :
-- Identifier les comptes IBM i utilisant
-- LOCAL_PASSWORD_MANAGEMENT = 'NO'
--
-- TYPE :
-- AUDIT
--
-- NIVEAU DE RISQUE :
-- SAFE
--
-- IMPACT :
-- Aucun impact système.
--
-- UTILISATION :
-- ACS -> Run SQL Scripts

---

## 7. DRYRUN obligatoire

Toute action système doit être précédée d’un mode DRYRUN.
Le DRYRUN :
affiche les objets impactés,
permet validation humaine,
évite les erreurs de production.
Exemple :

---

-- MODE DRYRUN
-- Aucun changement système effectué.

---

SELECT ...

## 8. MODE EXECUTE

Le mode EXECUTE doit être clairement identifié.
Exemple :

---

## -- MODE EXECUTE

-- ATTENTION :
-- Ce bloc modifie réellement le système IBM i.

---

## 9. Journalisation obligatoire

Toute remédiation ou procédure d’urgence doit écrire dans :
SSI_TOOLS.SECURITY_ACTION_LOG
Informations minimales :
check_id,
utilisateur impacté,
action,
résultat,
timestamp,
exécutant.

## 10. Bibliothèque cible

Mode standard projet :
SSI_TOOLS
Mode LAB autorisé :
MonUserIbm
Tous les scripts doivent pouvoir être adaptés facilement.
Exemple :
-- Remplacer SSI_TOOLS par votre bibliothèque cible si besoin.

## 11. Interdictions

Les scripts suivants sont interdits :
scripts silencieux,
modifications sans DRYRUN,
suppression sans log,
commandes non documentées,
hardcode production non expliqué.

## 12. Compatibilité

Les scripts doivent être compatibles :
IBM i ACS,
Run SQL Scripts,
SQL IBM i moderne,
export CSV ACS.

## 13. Objectif long terme

Le projet SSI_TOOLS vise à fournir :
un framework SSI IBM i moderne,
une base documentaire pédagogique,
une boîte à outils SOC/OPS,
un socle de durcissement IBM i,
un support au passage niveau 40,
une base exploitable pour SIEM et portail web futur.
