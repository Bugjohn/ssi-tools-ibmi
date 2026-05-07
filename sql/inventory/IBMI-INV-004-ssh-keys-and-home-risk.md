# IBMI-INV-004 – SSH Keys and HOME_DIRECTORY Risk

## Domaine

OPS / IFS / SSH

## Niveau

SAFE

---

# Objectif

Comprendre les risques liés :

- aux clés SSH ;
- aux HOME_DIRECTORY ;
- aux scripts shell ;
- aux comptes batch ;
- aux comptes techniques.

---

# Pourquoi c’est important

Sur IBM i moderne :

SSH/SFTP devient souvent :

- critique ;
- central ;
- invisible pour les équipes historiques IBM i.

Très souvent :

- les clés SSH sont oubliées ;
- les comptes batch sont partagés ;
- les scripts shell ne sont pas documentés.

---

# Risques SSI

## 1. Clés SSH orphelines

Cas classique :

- ancien prestataire ;
- ancien admin ;
- ancien batch.

Mais :

- clé toujours valide ;
- accès toujours possible 😅

---

# 2. HOME_DIRECTORY mal sécurisés

Les HOME_DIRECTORY peuvent contenir :

- clés SSH ;
- tickets Kerberos ;
- scripts shell ;
- exports sensibles ;
- logs ;
- mots de passe oubliés.

---

# 3. Scripts shell critiques

Souvent stockés :

- dans /home ;
- dans IFS ;
- hors sauvegarde classique IBM i.

En PRA :

- IBM i UP ;
- DB2 UP ;
- MAIS scripts shell absents.

=> PRA technique OK
=> PRA métier KO

---

# Contrôles recommandés

## Vérifier :

- permissions IFS ;
- propriétaires ;
- comptes désactivés ;
- répertoires orphelins ;
- clés SSH anciennes ;
- comptes batch ;
- scripts QSH/STRQSH.

---

# Sujet PRA/PCA

Les scripts shell doivent :

- être sauvegardés ;
- être documentés ;
- être restaurables ;
- être testés.

---

# Sujet niveau 40

Après passage niveau 40 :

- accès implicites supprimés ;
- scripts shell peuvent casser ;
- accès IFS peuvent changer ;
- comptes batch peuvent perdre accès.

---

# Recommandations

## Court terme

- inventorier ;
- documenter ;
- réduire FTP ;
- identifier clés SSH.

## Moyen terme

- migration SFTP ;
- rotation clés ;
- cloisonnement comptes techniques.

## Long terme

- gouvernance flux IBM i ;
- PRA cyber IBM i ;
- forensic IBM i moderne.
