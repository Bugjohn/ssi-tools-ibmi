-- ============================================================================
-- SSI_TOOLS – IBM i Security Toolkit
-- ============================================================================
-- CHECK_ID      : IBMI-AUTL-001
-- NOM           : Objets sans Authorization List (*AUTL)
-- DOMAINE       : AUTL
-- CLASSIFICATION: SAFE
-- TYPE          : AUDIT / GOVERNANCE
-- EXECUTION     : ACS - Run SQL Scripts
--
-- OBJECTIF
-- --------
-- Identifier les objets IBM i ne reposant sur aucune Authorization List
-- (*AUTL).
--
-- Pourquoi ce contrôle est important ?
--
-- Parce qu’un environnement IBM i “historique” accumule souvent :
--   - des droits directs ;
--   - des exceptions locales ;
--   - des profils ajoutés “temporairement” il y a 12 ans ;
--   - des programmes hérités ;
--   - des accès jamais nettoyés.
--
-- Résultat :
-- la sécurité devient illisible.
--
-- Et sur IBM i, quand les droits deviennent illisibles :
--   - les audits deviennent compliqués ;
--   - les corrections deviennent risquées ;
--   - le passage niveau 40 devient douloureux ;
--   - et personne n’ose toucher “parce que ça marche en prod” 😅
--
--
-- RAPPEL – QU’EST-CE QU’UNE *AUTL ?
-- ---------------------------------
-- Une Authorization List (*AUTL) permet de centraliser les droits.
--
-- Au lieu de donner des droits objet par objet :
--
--   USER_A -> fichier 1
--   USER_A -> fichier 2
--   USER_B -> programme 1
--   USER_C -> fichier 3
--
-- ... on rattache les objets à une liste d’autorisation :
--
--   OBJET -> AUTL(APP_FINANCE)
--
-- Puis :
--
--   GRP_FINANCE_USER  -> *USE
--   GRP_FINANCE_ADMIN -> *ALL
--
-- Avantages :
--   - gouvernance simplifiée ;
--   - audit plus lisible ;
--   - maintenance centralisée ;
--   - réduction des erreurs humaines ;
--   - cohérence sécurité ;
--   - préparation niveau 40.
--
--
-- RISQUE SSI
-- ----------
-- Un objet sans *AUTL n’est pas forcément vulnérable.
--
-- MAIS :
-- plus il y a d’objets sans gouvernance centralisée,
-- plus le SI IBM i devient difficile à sécuriser.
--
-- Risques classiques :
--   - droits incohérents ;
--   - utilisateurs oubliés ;
--   - accès historiques ;
--   - privilèges excessifs ;
--   - dérive progressive des autorités ;
--   - incapacité à expliquer “qui a accès à quoi”.
--
-- Dans beaucoup d’audits IBM i, le vrai problème n’est pas :
--   “les droits sont ouverts”.
--
-- Le vrai problème est :
--   “plus personne ne comprend les droits”.
--
--
-- IMPACT NIVEAU 40
-- ----------------
-- Le niveau 40 impose une gouvernance plus propre.
--
-- Le modèle cible moderne IBM i est généralement :
--
--   Utilisateurs -> Groupes
--   Groupes      -> *AUTL
--   *AUTL        -> Objets
--
-- Avec :
--   - *PUBLIC maîtrisé ;
--   - owners techniques ;
--   - adopted authority limitée ;
--   - droits explicites ;
--   - documentation claire.
--
-- Les objets sans *AUTL doivent donc être identifiés progressivement
-- avant migration ou durcissement.
--
--
-- PRE-CHECK
-- ---------
-- Ce script utilise QSYS2.OBJECT_PRIVILEGES.
-- Lecture seule uniquement.
--
--
-- DRYRUN
-- ------
-- Non applicable : audit uniquement.
--
--
-- EXECUTE
-- -------
-- Exécuter dans ACS / Run SQL Scripts.
--
--
-- LOGGING
-- -------
-- Aucun logging applicatif.
-- Export CSV recommandé pour qualification SSI.
--
--
-- ROLLBACK
-- --------
-- Non applicable.
--
--
-- EXPORT CSV
-- ----------
-- ACS :
-- clic droit -> Export Results -> CSV.
-- ============================================================================


-- ============================================================================
-- 1. PRE-CHECK – Vérification de la vue OBJECT_PRIVILEGES
-- ============================================================================
-- Permet de confirmer les colonnes disponibles selon la version IBM i.
-- ============================================================================

SELECT
    COLUMN_NAME
FROM QSYS2.SYSCOLUMNS
WHERE TABLE_SCHEMA = 'QSYS2'
  AND TABLE_NAME   = 'OBJECT_PRIVILEGES'
ORDER BY ORDINAL_POSITION;


-- ============================================================================
-- 2. AUDIT – Objets applicatifs sans Authorization List
-- ============================================================================
-- Cette requête cible les objets applicatifs sans AUTHORIZATION_LIST.
--
-- Types surveillés en priorité :
--   *FILE    : données métiers
--   *PGM     : programmes RPG/COBOL/CL
--   *SRVPGM  : service programs
--   *CMD     : commandes
--   *DTAARA  : data areas
--
-- Exclusions :
-- bibliothèques système IBM.
--
-- IMPORTANT :
-- L’absence de *AUTL n’est PAS automatiquement une anomalie.
-- L’objectif est :
--   - d’identifier ;
--   - qualifier ;
--   - documenter ;
--   - préparer une gouvernance propre.
-- ============================================================================

SELECT
    SYSTEM_OBJECT_SCHEMA AS OBJECT_LIBRARY,
    SYSTEM_OBJECT_NAME AS OBJECT_NAME,
    OBJECT_TYPE,
    OWNER,
    PRIMARY_GROUP,
    AUTHORIZATION_LIST,
    AUTHORIZATION_NAME,
    OBJECT_AUTHORITY,
    TEXT_DESCRIPTION,

    CASE
        WHEN OBJECT_TYPE IN ('*PGM', '*SRVPGM') THEN 'HIGH'
        WHEN OBJECT_TYPE IN ('*FILE', '*DTAARA') THEN 'MEDIUM'
        ELSE 'LOW'
    END AS SEVERITY,

    CASE
        WHEN OBJECT_TYPE IN ('*PGM', '*SRVPGM')
            THEN 'Programme sans gouvernance *AUTL : vérifier owner, adopted authority et droits.'
        WHEN OBJECT_TYPE IN ('*FILE', '*DTAARA')
            THEN 'Objet de données sans *AUTL : vérifier cohérence des accès.'
        ELSE
            'Objet sans *AUTL : qualification recommandée.'
    END AS SSI_COMMENT

FROM QSYS2.OBJECT_PRIVILEGES

WHERE COALESCE(NULLIF(TRIM(AUTHORIZATION_LIST), ''), '*NONE') IN ('*NONE', '-')
  AND OBJECT_TYPE IN (
      '*FILE',
      '*PGM',
      '*SRVPGM',
      '*CMD',
      '*DTAARA'
  )
  AND SYSTEM_OBJECT_SCHEMA NOT LIKE 'Q%'

ORDER BY
    OBJECT_LIBRARY,
    OBJECT_TYPE,
    OBJECT_NAME;