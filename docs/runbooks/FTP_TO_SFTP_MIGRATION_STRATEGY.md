# Migration FTP -> FTPS/SFTP – Stratégie IBM i

## Objectif

Préparer migration progressive :

- FTP historique ;
- vers FTPS ou SFTP ;
- sans casser la production.

---

# Pourquoi c’est un sujet majeur

Dans énormément d’environnements IBM i :

FTP :

- existe depuis 15/20 ans ;
- est critique ;
- n’est plus documenté ;
- dépend de batchs historiques.

Très souvent :
personne ne sait :

- quels flux existent ;
- quels partenaires utilisent FTP ;
- quels batchs dépendent du flux.

---

# Risques SSI

FTP :

- mots de passe en clair ;
- données potentiellement interceptables ;
- flux rarement supervisés ;
- comptes techniques anciens.

---

# Différence FTPS / SFTP

## FTPS

FTP + SSL/TLS

Dépend :

- DCM ;
- certificats ;
- TLS ;
- stores IBM i.

---

## SFTP

SSH File Transfer Protocol

Dépend :

- SSH ;
- clés SSH ;
- comptes techniques ;
- HOME_DIRECTORY.

---

# Réalité terrain IBM i

Très fréquent :

## "On veut couper FTP"

Puis :

- batch EDI KO ;
- partenaire KO ;
- export finance KO ;
- API KO 😅

---

# Étapes recommandées

## 1. Inventaire

Identifier :

- jobs FTP ;
- scripts ;
- comptes techniques ;
- partenaires ;
- batchs ;
- répertoires IFS.

---

## 2. Documentation

Documenter :

- source ;
- destination ;
- protocole ;
- compte utilisé ;
- PRA associé.

---

## 3. Classification

Identifier :

- flux critiques ;
- flux legacy ;
- flux supprimables.

---

## 4. Migration pilote

Commencer :

- flux non critiques ;
- environnement pré-prod ;
- SFTP si possible.

---

## 5. PRA/PCA

Tester :

- restauration clés SSH ;
- restauration certificats ;
- restauration scripts ;
- restauration batchs.

---

# Sujet niveau 40

Après niveau 40 :

- accès implicites supprimés ;
- certificats peuvent casser ;
- scripts shell peuvent casser ;
- comptes batch peuvent perdre accès.

---

# Recommandation moderne

Cible idéale :

- SSH/SFTP ;
- comptes techniques dédiés ;
- clés SSH ;
- rotation secrets ;
- supervision ;
- journalisation ;
- PRA testé.
