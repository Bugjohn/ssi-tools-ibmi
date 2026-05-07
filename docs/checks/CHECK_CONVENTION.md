# Convention des CHECKS – SSI Tools IBM i

## 1. Objectif

Ce document définit la convention utilisée pour nommer, classer, évaluer et documenter les contrôles de sécurité IBM i du projet `SSI_TOOLS`.

Un CHECK correspond à un contrôle SSI exécutable ou documenté permettant d’identifier un risque, une mauvaise configuration ou une exposition de sécurité sur IBM i.

---

## 2. Format des identifiants

Format standard :

IBMI-<DOMAINE>-<NUMERO>

Exemples :
IBMI-USR-001
IBMI-AUTH-001
IBMI-AD-001
IBMI-LIB-001
IBMI-AUTL-001
IBMI-PGM-001
IBMI-SSL-001

## 3. Domaines

Domaine Description
USR Comptes utilisateurs
GRP Groupes utilisateurs
AUTH Autorités spéciales et privilèges
AD Active Directory, Kerberos, EIM
PWD Mots de passe et politique d’authentification
LIB Bibliothèques
OBJ Objets IBM i
AUTL Listes d’autorisation
PGM Programmes, owners et adopted authority
IFS IFS, dossiers utilisateurs, permissions fichiers
SSL Certificats, DCM, TLS
NET Flux réseau, FTP, SFTP, API
OPS Comptes batch, exploitation, traitements planifiés
EMERG Contrôles liés aux procédures d’urgence

## 4. Niveaux de sévérité

Severity Description
CRITICAL Risque de compromission immédiate ou élévation de privilèges majeure
HIGH Exposition importante nécessitant une action prioritaire
MEDIUM Mauvaise pratique significative ou faiblesse structurelle
LOW Point d’hygiène ou de durcissement
INFO Information utile à l’analyse, sans risque direct

## 5. Types de checks

Type Description
AUDIT Lecture seule, sans impact système
REMEDIATION Action corrective contrôlée
EMERGENCY Action de crise ou de confinement
INVENTORY Inventaire technique ou cartographie
REPORTING Consolidation ou restitution

## 6. Structure documentaire d’un check

Chaque check doit suivre ce modèle :

## IBMI-XXX-000 – Titre du contrôle

### Domaine

XXX

### Type

AUDIT / REMEDIATION / EMERGENCY / INVENTORY

### Severity

CRITICAL / HIGH / MEDIUM / LOW / INFO

### Objectif

Décrire ce que le contrôle cherche à identifier.

### Risque

Décrire le risque SSI associé.

### Critère de détection

Décrire précisément la logique métier ou technique.

### SQL

Requête SQL utilisée.

### Résultat attendu

Décrire ce qui est considéré comme conforme ou non conforme.

### Remédiation recommandée

Décrire les actions possibles.

### Précautions

Lister les points de vigilance avant toute action.

### Références internes

Lien vers runbook, script ou procédure associée.

## 7. Règle importante

Un check AUDIT ne doit jamais modifier le système.
Toute modification doit être isolée dans un script ou une procédure de type :
REMEDIATION
EMERGENCY

## 8. Convention de nommage des fichiers

Format recommandé :
IBMI-<DOMAINE>-<NUMERO>-<nom-court>.sql
IBMI-<DOMAINE>-<NUMERO>-<nom-court>.md
Exemples :
IBMI-AD-001-ad-dependent-users.sql
IBMI-AD-001-ad-dependent-users.md
IBMI-AUTH-001-allobj-users.sql
IBMI-USR-001-inactive-users.sql

## 9. Statuts possibles

Statut Description
DRAFT En cours de rédaction
READY Prêt à tester
TESTED Testé sur environnement IBM i
VALIDATED Validé pour usage contrôlé
DEPRECATED Ancien check conservé pour historique

## 10. Principe général

Le projet doit toujours respecter cette logique :
Voir d’abord.
Comprendre ensuite.
Corriger seulement après validation.
Tracer systématiquement.

Ensuite, on pourra attaquer le **premier catalogue officiel de checks V1**, en commençant par :

IBMI-USR-001 – Comptes actifs inactifs depuis plus de X jours
IBMI-AD-001 – Comptes dépendants AD/Kerberos actifs
IBMI-AUTH-001 – Profils avec *ALLOBJ
IBMI-AUTH-002 – Profils avec *SECADM
IBMI-PWD-001 – Profils avec mot de passe par défaut
IBMI-PWD-002 – Profils avec mot de passe sans expiration
IBMI-GRP-001 – Profils sans groupe principal
IBMI-LIB-001 – Bibliothèques avec *PUBLIC = *CHANGE ou *ALL
IBMI-OBJ-001 – Objets exposés à *PUBLIC
IBMI-AUTL-001 – Bibliothèques sans Authorization List
