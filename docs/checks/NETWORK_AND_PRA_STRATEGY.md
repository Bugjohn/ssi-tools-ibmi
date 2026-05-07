# Stratégie Réseau / PRA / SSL – SSI_TOOLS

## Objectif

Le framework SSI_TOOLS ne se limite pas :

- aux profils utilisateurs ;
- aux mots de passe ;
- aux autorités IBM i.

Le framework doit également :

- comprendre les flux ;
- comprendre les dépendances réseau ;
- comprendre les impacts PRA/PCA ;
- comprendre les dépendances SSL/TLS.

---

# Pourquoi c’est important

Sur IBM i :

beaucoup de PRA sont validés uniquement sur :

- disponibilité partition ;
- disponibilité DB2 ;
- démarrage batch.

Mais aujourd’hui :

un IBM i dépend aussi :

- APIs ;
- HTTPS ;
- SSH/SFTP ;
- FTPS ;
- DCM ;
- Kerberos ;
- QNTC ;
- SMB ;
- certificats ;
- trust stores.

---

# Concept clé

## PRA technique ≠ PRA métier

Exemple :

| Élément               | État |
| --------------------- | ---- |
| LPAR IBM i            | OK   |
| DB2                   | OK   |
| Jobs batch            | OK   |
| APIs HTTPS            | KO   |
| Certificat DCM expiré | KO   |
| Flux FTPS             | KO   |
| QNTC                  | KO   |

Résultat :

- PRA technique = OK
- PRA métier = ÉCHEC

---

# Philosophie du framework

Chaque check réseau doit :

- vulgariser IBM i ;
- expliquer le risque SSI ;
- expliquer l’impact PRA ;
- préparer niveau 40 ;
- préparer migration TLS ;
- documenter les dépendances cachées.

---

# Objectifs long terme

Le framework doit permettre :

- cartographie flux IBM i ;
- réduction surface d’attaque ;
- migration FTP -> FTPS/SFTP ;
- préparation audits SSI ;
- préparation ISO 27001 ;
- préparation NIS2 ;
- préparation forensic ;
- support SOC ;
- support OPS ;
- support PRA/PCA cyber.

---

# Sujet majeur : FTP historique

Dans énormément d’environnements IBM i :

FTP :

- existe encore ;
- est critique ;
- est mal documenté ;
- dépend de batchs oubliés ;
- dépend de comptes techniques ;
- dépend parfois d’anciens prestataires.

Le framework doit aider à :

- identifier ces flux ;
- les documenter ;
- préparer migration sécurisée.

---

# Sujet majeur : SSL/TLS

IBM i moderne :

- doit utiliser TLS ;
- doit surveiller DCM ;
- doit surveiller expiration certificats ;
- doit surveiller comptes batch ;
- doit surveiller accès aux stores.

---

# Sujet majeur : SSH/SFTP

SSH devient :

- central ;
- critique ;
- souvent mal documenté.

Le framework doit aider à :

- inventorier ;
- sécuriser ;
- documenter ;
- tester PRA/PCA.
