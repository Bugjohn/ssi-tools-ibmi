# SSI_TOOLS – IBM i Security Toolkit

> Framework SSI IBM i moderne orienté SQL-first, ACS-first, audit, gouvernance, PRA/PCA et préparation niveau 40.

---

# ⚠️ IMPORTANT

SSI_TOOLS n’est PAS :

- une collection de scripts SQL “jetables” ;
- un toolkit offensif ;
- un remplacement d’un administrateur IBM i ;
- un “script magique” de remédiation massive.

SSI_TOOLS EST :

- un framework SSI IBM i ;
- un socle de gouvernance ;
- un kit SOC / OPS ;
- un support PRA/PCA ;
- un support de montée en compétence ;
- un accélérateur de préparation niveau 40 ;
- un pont entre IBM i historique et cybersécurité moderne.

---

# 🎯 Philosophie du projet

Le projet suit plusieurs principes NON NEGOCIABLES :

## SQL-first

Tout doit pouvoir être :

- audité ;
- exporté ;
- relu ;
- compris ;
  depuis ACS / Run SQL Scripts.

## ACS-first

L’objectif est de réduire la dépendance :

- au 5250 ;
- aux menus historiques ;
- aux outils peu documentés.

## SAFE FIRST

Par défaut :

- lecture seule ;
- audit ;
- export CSV ;
- validation humaine ;
- compréhension avant action.

Aucune action dangereuse sans :

- DRYRUN ;
- logging ;
- rollback ;
- explication d’impact ;
- niveau de criticité.

## Pédagogie obligatoire

Chaque script doit être :

- compréhensible par un junior ;
- utile à un admin Windows/Linux découvrant IBM i ;
- crédible pour un admin IBM i terrain.

Le projet sert aussi à faire monter des équipes en compétence IBM i moderne.

---

# 👥 Public cible

SSI_TOOLS s’adresse à :

- Administrateurs IBM i
- RSSI
- SOC
- OPS
- Sysadmins Windows
- Admins Linux
- Auditeurs SSI
- Équipes PRA/PCA
- Équipes cybersécurité
- Juniors découvrant IBM i

---

# 🧱 Architecture du projet

```text
docs/
├── architecture/
├── checks/
├── compatibility/
├── runbooks/

sql/
├── install/
├── audit/
├── remediation/
├── emergency/
├── inventory/
└── rollback/
```

## 📚 Description des dossiers

# docs/architecture/

Documentation technique globale :
philosophie ;
architecture ;
exécution ;
gouvernance ;
niveaux SAFE/CRITICAL ;
workflow SOC/OPS.

# docs/checks/

Documentation des contrôles :
convention de nommage ;
niveaux de criticité ;
explication des domaines ;
mapping sécurité.

# docs/compatibility/

Compatibilité IBM i :
versions 7.3 / 7.4 / 7.5 ;
dépendances PTF ;
limitations QSYS2 ;
vues disponibles.

# docs/runbooks/

Runbooks opérationnels :
PRA/PCA ;
FTPS/SFTP ;
compromission AD ;
emergency lockdown ;
rollback ;
validation post-incident.

# sql/install/

Installation initiale :
bibliothèque SSI_TOOLS ;
tables de log ;
vues ;
structures SQL.

# sql/audit/

Contrôles lecture seule :
audit utilisateurs ;
audit SSL ;
audit objets ;
audit IFS ;
audit réseau ;
audit niveau 40.
SAFE par défaut.

# sql/remediation/

Scripts de remédiation contrôlée :
corrections ;
durcissement ;
changements de configuration.

Toujours avec :
DRYRUN ;
logging ;
rollback.

# sql/emergency/

Scripts d’urgence :
lockdown ;
désactivation ;
reset ;
containment.

Utilisation STRICTEMENT encadrée.

# sql/inventory/

Inventaires techniques :
flux ;
certificats ;
programmes ;
objets ;
services ;
comptes batch.

# sql/rollback/

Retour arrière :
restauration ;
réactivation ;
rollback contrôlé ;
reprise post-incident.

## 🏷️ Convention des checks

Format :
IBMI-<DOMAINE>-<NUMERO>

Exemples :
IBMI-SSL-001
IBMI-NET-002
IBMI-IFS-003
IBMI-PGM-001

## 🧭 Domaines disponibles

Domaine Description
USR Utilisateurs
AUTH Autorisations spéciales
AD Active Directory / Kerberos
PWD Mots de passe
LIB Bibliothèques
OBJ Objets
AUTL Authorization Lists
PGM Programmes
IFS Integrated File System
SSL Certificats / TLS
NET Réseau
OPS Exploitation
EMERG Urgence
GRP Groupes

## 🚦 Niveaux de sécurité des scripts

Niveau Description
SAFE Lecture seule
CONTROLLED Action contrôlée
DANGEROUS Action potentiellement impactante
CRITICAL Action de crise / containment

## 🔐 IBM i moderne et sécurité

SSI_TOOLS considère IBM i comme :
une plateforme moderne ;
critique ;
exposée ;
interconnectée ;
soumise aux mêmes exigences SSI que Linux/Windows.

## 🌐 Sujets majeurs couverts

Le projet couvre progressivement :
Niveau 40
DCM
SSL/TLS
FTPS/SFTP
SSH
APIs REST
Kerberos
EIM
Active Directory
comptes batch
adopted authority
\*AUTL
IFS
QNTC
PRA/PCA
emergency lockdown
gouvernance SSI

## 🔥 Niveau 40 – philosophie

Le niveau 40 :
ne “casse” pas IBM i ;
révèle les incohérences historiques ;
impose une gestion propre des droits ;
supprime beaucoup de comportements implicites.

SSI_TOOLS aide à :
préparer le passage ;
identifier les points bloquants ;
documenter les risques ;
industrialiser les corrections.

## 🌍 SSL/TLS et IBM i

Le projet considère les flux sécurisés comme obligatoires dans un SI moderne.
Les contrôles SSL/TLS couvrent :
DCM ;
certificats ;
HTTPS ;
FTPS ;
SSH/SFTP ;
expiration ;
PRA/PCA ;
batchs ;
APIs.

## 🧠 Philosophie pédagogique

Le projet documente systématiquement :
le “quoi” ;
le “comment” ;
le “pourquoi”.

L’objectif est aussi de :
démystifier IBM i ;
aider les profils Windows/Linux ;
transmettre les bonnes pratiques terrain.

## 😅 Réalité terrain IBM i

Quelques phrases classiques rencontrées en production :
"Le FTP est interne donc ça va."
"On a un certificat quelque part."
"Le niveau 40 casse tout."
"Le batch marche chez moi."
"On ne sait plus à quoi sert ce profil."
"Le PRA est OK (on n'a pas testé les APIs)."
SSI_TOOLS est justement conçu pour remettre :
de la visibilité ;
de la gouvernance ;
de la traçabilité ;
de la compréhension.

## 🛣️ Roadmap prévisionnelle

Sécurité
MFA
intégration SIEM
reporting avancé
scoring SSI

Réseau
FTPS/SFTP
audit TLS avancé
inventaire flux

Gouvernance
tableaux de bord
reporting CSV/HTML
export audit

PRA/PCA
runbooks cyber
validation post-bascule
tests automatisés

IBM i moderne
APIs ACS
automatisation contrôlée
inventory enrichi

## 🏁 Conclusion

SSI_TOOLS vise à devenir :
un framework SSI IBM i ;
un support de gouvernance ;
un kit SOC/OPS ;
un support de montée en compétence ;
un accélérateur de modernisation IBM i.

Le projet évoluera progressivement avec :
les retours terrain ;
les tests en production ;
les validations niveau 40 ;
les besoins PRA/PCA ;
les évolutions SSI modernes.
