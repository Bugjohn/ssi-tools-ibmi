# SSI IBM i — Remplacer progressivement *ALLOBJ par groupe + AUTL

## Objectif

Un utilisateur possède actuellement :

*ALLOBJ

Il doit continuer à utiliser plusieurs objets IBM i : programmes, fichiers, bibliothèques, commandes, répertoires IFS, etc.

L’objectif est de :

identifier les objets nécessaires ;
vérifier les droits actuels ;
créer un groupe de transition ;
rattacher l’utilisateur au groupe ;
créer une liste d’autorisation AUTL ;
donner les droits nécessaires via cette AUTL ;
tester ;
retirer *ALLOBJ à l’utilisateur quand tout est validé.

## Pré-check utilisateur

Remplace MONUSER par le profil réel.

DSPUSRPRF USRPRF(MONUSER) TYPE(*BASIC)

Puis :

DSPUSRPRF USRPRF(MONUSER) TYPE(*SPCAUT)

À vérifier :

SPCAUT = *ALLOBJ
USRCLS = *USER, *PGMR, etc.
GRPPRF = éventuel groupe principal
SUPGRPPRF = groupes supplémentaires

## Lister les objets nécessaires

Créer une liste de travail :

Bibliothèque : APPLI01
Objets :
- APPLI01/PGM_FACTURE    *PGM
- APPLI01/F_CLIENT       *FILE
- APPLI01/F_COMMANDE     *FILE
- APPLI01/CMD_EXPORT     *CMD
- /home/appli/export     IFS

Exemple de tableau de suivi :

Objet	Type	Usage	Droit nécessaire
APPLI01/PGM_FACTURE	*PGM	Exécution	*USE
APPLI01/F_CLIENT	*FILE	Lecture	*USE
APPLI01/F_COMMANDE	*FILE	Lecture/écriture	*CHANGE
APPLI01/CMD_EXPORT	*CMD	Exécution commande	*USE
/home/appli/export	IFS	dépôt fichiers	rwx selon besoin

## Vérifier les droits actuels sur les objets

Objet IBM i classique
DSPOBJAUT OBJ(APPLI01/PGM_FACTURE) OBJTYPE(*PGM)
DSPOBJAUT OBJ(APPLI01/F_CLIENT) OBJTYPE(*FILE)
DSPOBJAUT OBJ(APPLI01/CMD_EXPORT) OBJTYPE(*CMD)

À regarder :

PUBLIC
Owner
Group
AUTL éventuelle
MONUSER
Groupes existants

## Créer un groupe de transition avec *ALLOBJ

⚠️ À utiliser avec prudence. Ce groupe sert à ne pas casser le métier pendant la bascule.

CRTUSRPRF USRPRF(GRPSSIALL) +
          PASSWORD(*NONE) +
          USRCLS(*USER) +
          SPCAUT(*ALLOBJ) +
          TEXT('Groupe transitoire SSI - droits ALLOBJ contrôlés')

Puis générer un GID si nécessaire :

CHGUSRPRF USRPRF(GRPSSIALL) GID(*GEN)

## Ajouter l’utilisateur au groupe

Si l’utilisateur n’a pas encore de groupe principal :

CHGUSRPRF USRPRF(MONUSER) GRPPRF(GRPSSIALL)

S’il a déjà un groupe principal, utiliser un groupe supplémentaire :

CHGUSRPRF USRPRF(MONUSER) SUPGRPPRF(GRPSSIALL)

Vérification :

DSPUSRPRF USRPRF(MONUSER) TYPE(*GRPMBR)

## Créer une AUTL dédiée

Exemple :

CRTAUTL AUTL(AUTL_APP01) +
        TEXT('AUTL droits applicatifs APPLI01')

Vérification :

DSPAUTL AUTL(AUTL_APP01)

## Ajouter le groupe ou l’utilisateur dans l’AUTL

Option recommandée : donner les droits au groupe métier, pas directement à l’utilisateur.

ADDAUTLE AUTL(AUTL_APP01) USER(GRPSSIALL) AUT(*CHANGE)

Ou pour un droit plus limité :

ADDAUTLE AUTL(AUTL_APP01) USER(GRPSSIALL) AUT(*USE)

Vérification :

DSPAUTL AUTL(AUTL_APP01)

## Rattacher les objets à l’AUTL

Programme
CHGOBJAUT OBJ(APPLI01/PGM_FACTURE) OBJTYPE(*PGM) AUTL(AUTL_APP01)
Fichier
CHGOBJAUT OBJ(APPLI01/F_CLIENT) OBJTYPE(*FILE) AUTL(AUTL_APP01)
Commande
CHGOBJAUT OBJ(APPLI01/CMD_EXPORT) OBJTYPE(*CMD) AUTL(AUTL_APP01)

Vérification :

DSPOBJAUT OBJ(APPLI01/PGM_FACTURE) OBJTYPE(*PGM)

Tu dois voir :

Authorization list . . . . . . . . : AUTL_APP01

## Cas IFS

Pour les répertoires/fichiers IFS :

WRKLNK OBJ('/home/appli/export')

Puis option :

9 = Work with authority

Ou en commande :

CHGAUT OBJ('/home/appli/export') USER(GRPSSIALL) DTAAUT(*RWX) OBJAUT(*ALL)

Pour vérifier :

DSPAUT OBJ('/home/appli/export')

## Test utilisateur

Demander à l’utilisateur de se reconnecter.

Important : les groupes et droits peuvent nécessiter une nouvelle session.

Tests à faire :

1. Ouverture de session
2. Accès menu applicatif
3. Lancement programme
4. Lecture fichier
5. Écriture / modification si nécessaire
6. Export fichier
7. Accès IFS
8. Traitement batch éventuel
11. Retrait de *ALLOBJ sur l’utilisateur

Quand les tests sont OK :

CHGUSRPRF USRPRF(MONUSER) SPCAUT(*NONE)

Ou si l’utilisateur possède plusieurs droits spéciaux, ne retirer que *ALLOBJ en conservant les autres nécessaires.

Vérifier :

DSPUSRPRF USRPRF(MONUSER) TYPE(*SPCAUT)

## Test après retrait de *ALLOBJ

Refaire les tests métier.

Si tout fonctionne :

OK : les droits applicatifs sont bien portés par AUTL / groupe.

Si erreur :

CPFxxxx authority failure
Objet concerné
Type d’objet
Programme appelant
Bibliothèque

Puis corriger uniquement le droit manquant.

## Rollback rapide

Si blocage critique :

CHGUSRPRF USRPRF(MONUSER) SPCAUT(*ALLOBJ)

Puis documenter :

Date
Utilisateur
Objet bloquant
Message CPF
Action corrective prévue

## Point SSI important

À terme, il faut éviter ça :

Utilisateur normal → groupe avec *ALLOBJ permanent

Cible propre :

Utilisateur
  ↓
Groupe métier sans *ALLOBJ
  ↓
AUTL applicative
  ↓
Droits précis sur objets

Donc après stabilisation, créer plutôt un groupe métier sans *ALLOBJ :

CRTUSRPRF USRPRF(GRPAPP01) +
          PASSWORD(*NONE) +
          USRCLS(*USER) +
          SPCAUT(*NONE) +
          TEXT('Groupe métier application APPLI01')

Puis :

ADDAUTLE AUTL(AUTL_APP01) USER(GRPAPP01) AUT(*CHANGE)

Et rattacher l’utilisateur à GRPAPP01.

Synthèse
Étape 1 : Identifier les objets utilisés
Étape 2 : Vérifier DSPOBJAUT / DSPAUT
Étape 3 : Créer groupe de transition si nécessaire
Étape 4 : Créer AUTL
Étape 5 : Donner droits via AUTL
Étape 6 : Tester
Étape 7 : Retirer *ALLOBJ
Étape 8 : Corriger les droits manquants
Étape 9 : Supprimer le groupe *ALLOBJ si devenu inutile