# SSI_TOOLS – IBM i Security Toolkit

Framework SSI IBM i moderne orienté :

- SQL-first
- ACS-first
- PRA/PCA
- forensic IBM i
- gouvernance SSI
- préparation niveau 40
- inventory & dépendances
- AD / Kerberos / TLS / SSH
- audit + remédiation contrôlée

---

# 🎯 Objectif du projet

SSI_TOOLS n’est PAS :

- une collection de scripts SQL jetables ;
- un toolkit “hacky” ;
- un pack de commandes IBM i sans contexte ;
- un projet réservé aux experts IBM i historiques.

SSI_TOOLS DOIT devenir :

- un framework SSI IBM i moderne ;
- un support PRA/PCA cyber ;
- un support SOC/OPS ;
- un support forensic IBM i ;
- un socle gouvernance ;
- un support pédagogique ;
- un accélérateur de montée en compétence IBM i.

---

# 🧠 Philosophie du projet

Le projet est volontairement :

- très commenté ;
- pédagogique ;
- orienté terrain ;
- compatible ACS ;
- centré SQL ;
- pensé pour le monde réel.

Objectif :
réconcilier :

- IBM i historique,
- cybersécurité moderne,
- PRA/PCA,
- audit,
- gouvernance,
- SOC,
- AD/Kerberos,
- TLS/SSH/API,
- forensic.

---

# 👥 Public visé

SSI_TOOLS est pensé pour :

- admins IBM i ;
- admins Windows/Linux découvrant IBM i ;
- SOC ;
- RSSI ;
- DSI ;
- auditeurs ;
- OPS ;
- juniors IBM i ;
- équipes PRA/PCA ;
- consultants sécurité.

---

# ⚠️ Philosophie sécurité

Le projet suit une approche stricte :

## SAFE

Lecture seule.
Aucune modification.

## CONTROLLED

Modification contrôlée avec validation humaine.

## DANGEROUS

Actions potentiellement impactantes.
DRYRUN obligatoire.

## CRITICAL

Actions de crise / urgence.
Whitelist + logs + validation impératifs.

---

# 🚨 IMPORTANT

Le projet contient :

- des scripts d’audit ;
- des procédures d’urgence ;
- des exemples de remédiation ;
- des actions de durcissement ;
- des commandes systèmes IBM i.

👉 Toujours :

- tester en LAB ;
- exporter les résultats ;
- documenter les actions ;
- valider les impacts PRA/PCA ;
- maintenir une whitelist ;
- comprendre les dépendances batch/API/FTP avant action.

---

# 🏗️ Architecture actuelle

```text
docs/
├── architecture/
├── checks/
├── compatibility/
├── runbooks/
└── README_PROJECT_STRUCTURE.md

sql/
├── install/
├── audit/
├── remediation/
├── emergency/
├── inventory/
└── rollback/
```

---

# 📚 Principes techniques

## SQL-first

Le projet privilégie :

- SQL IBM i ;
- vues QSYS2 ;
- ACS Run SQL Scripts.

Pourquoi ?
Parce que :

- exportable ;
- auditable ;
- moderne ;
- facilement partageable ;
- exploitable par SOC/RSSI ;
- compatible forensic.

---

## ACS-first

Le toolkit est pensé pour :
IBM i Access Client Solutions (ACS)

Objectifs :

- éviter la dépendance 5250 ;
- faciliter export CSV ;
- faciliter PRA ;
- faciliter audit ;
- faciliter documentation.

---

# 🔐 Domaines couverts

## Utilisateurs / Authentification

- comptes à privilèges ;
- dépendances AD/Kerberos ;
- mots de passe ;
- comptes techniques ;
- groupes ;
- profils batch.

## Réseau

- FTP ;
- FTPS ;
- SFTP ;
- SSH ;
- Telnet ;
- services exposés.

## SSL / TLS / DCM

- certificats ;
- expiration ;
- DCM ;
- applications TLS ;
- PRA SSL.

## IFS / QNTC

- permissions IFS ;
- QNTC ;
- home directories ;
- clés SSH ;
- risques PASE.

## Programmes / Objets

- adopted authority ;
- owners ;
- droits \*PUBLIC ;
- AUTL ;
- exposition objets.

## PRA / PCA

- dépendances batch ;
- dépendances certificats ;
- flux historiques ;
- comptes critiques ;
- forensic post-incident.

---

# 🔥 Réalité terrain IBM i

Un IBM i peut :

- démarrer ;
- avoir DB2 OK ;
- avoir les LPAR OK ;

…et pourtant le PRA métier être totalement KO.

Exemples :

- FTPS cassé ;
- certificats expirés ;
- DCM inaccessible ;
- batch oublié ;
- dépendance QNTC ;
- vieux script FTP ;
- compte technique supprimé ;
- mapping Kerberos incorrect ;
- API HTTPS KO.

SSI_TOOLS existe aussi pour ça.

---

# 🧱 Niveau 40 – Vision du projet

Le niveau 40 n’est pas :
“un paramètre système magique”.

Le niveau 40 :

- révèle les mauvaises pratiques ;
- casse les droits implicites ;
- impose une vraie gouvernance.

Le modèle cible :

- groupes ;
- AUTL ;
- owners maîtrisés ;
- programmes propres ;
- droits explicites ;
- comptes techniques gouvernés.

---

# 📦 Bibliothèque standard

## Production

SSI_TOOLS

## LAB

Bibliothèque utilisateur possible.

Exemple :

MONUSERIBM

---

# 🧪 Exécution

Tous les scripts sont conçus pour :

- ACS → Run SQL Scripts ;
- export CSV ;
- audit documentaire ;
- usage SOC/OPS.

---

# 📝 Convention des checks

Format :

```text
IBMI-<DOMAINE>-<NUMERO>
```

Exemples :

```text
IBMI-AUTH-001
IBMI-SSL-003
IBMI-NET-006
IBMI-INV-005
```

---

# 📂 Domaines actuels

| Domaine | Description                  |
| ------- | ---------------------------- |
| USR     | Utilisateurs                 |
| AUTH    | Autorités                    |
| AD      | Dépendances Active Directory |
| PWD     | Mots de passe                |
| LIB     | Bibliothèques                |
| OBJ     | Objets                       |
| AUTL    | Authorization Lists          |
| PGM     | Programmes                   |
| IFS     | IFS / PASE                   |
| SSL     | TLS / DCM                    |
| NET     | Réseau                       |
| OPS     | Exploitation                 |
| EMERG   | Procédures d’urgence         |
| GRP     | Groupes                      |
| INV     | Inventory / dépendances      |

---

# 🚦 Niveaux de sécurité

| Niveau     | Description                  |
| ---------- | ---------------------------- |
| SAFE       | Lecture seule                |
| CONTROLLED | Action contrôlée             |
| DANGEROUS  | Impact potentiellement élevé |
| CRITICAL   | Procédure de crise           |

---

# 📖 Documentation

Le projet contient :

- documentation technique ;
- runbooks PRA/PCA ;
- guides niveau 40 ;
- procédures SOC ;
- procédures OPS ;
- conventions de checks ;
- guides forensic IBM i.

---

# 🔍 Objectif forensic

Le projet aide aussi à :

- comprendre les flux historiques ;
- identifier les comptes techniques oubliés ;
- tracer les actions ;
- documenter les incidents ;
- accélérer les investigations IBM i modernes.

---

# 🌍 IBM i moderne

IBM i moderne ce n’est plus uniquement :

- RPG ;
- 5250 ;
- DB2.

Aujourd’hui IBM i = aussi :

- SSH ;
- APIs ;
- TLS ;
- DCM ;
- Kerberos ;
- AD ;
- PASE ;
- shell ;
- SFTP ;
- FTPS ;
- forensic ;
- cybersécurité ;
- PRA/PCA.

---

# ⚠️ DISCLAIMER

Ce projet fournit :

- des outils ;
- des exemples ;
- des procédures ;
- des scripts d’audit ;
- des scripts de remédiation contrôlée.

L’auteur ne peut être tenu responsable :

- d’une mauvaise utilisation ;
- d’une exécution sans validation ;
- d’un usage en production sans test préalable.

Toujours :

- tester ;
- sauvegarder ;
- documenter ;
- valider ;
- exporter ;
- tracer.

---

# 📌 Roadmap envisagée

## Court terme

- inventory PRA/PCA ;
- inventory batch ;
- inventory DCM ;
- inventory certificats ;
- inventory APIs ;
- inventory QNTC ;
- inventory SSH ;
- forensic IBM i.

## Moyen terme

- rollback framework ;
- reporting consolidé ;
- exports automatisés ;
- checklist PRA cyber ;
- gouvernance flux.

## Long terme

- SIEM integration ;
- API ACS ;
- reporting avancé ;
- support MFA ;
- workflows SOC ;
- tableau de bord documentaire.

---

# 🤝 Contribution

Objectifs des contributions :

- pédagogie ;
- stabilité ;
- sécurité ;
- documentation ;
- réalisme terrain IBM i.

Pas de :

- scripts dangereux sans DRYRUN ;
- automatisation aveugle ;
- refactor massif ;
- “one-liner magique”.

---

# 📜 Licence

Projet sous licence MIT.

---

# 🧊 Dernier mot

Sur IBM i, les problèmes critiques ne viennent pas toujours :

- d’un exploit zero-day ;
- d’un ransomware sophistiqué ;
- d’un APT.

Très souvent, ils viennent de :

- vieux batchs oubliés ;
- comptes techniques historiques ;
- FTP “temporaire” depuis 2009 ;
- certificats expirés ;
- profils ALLOBJ applicatifs ;
- dépendances fantômes ;
- PRA jamais réellement testé.

Bienvenue dans le monde réel IBM i. 😅
