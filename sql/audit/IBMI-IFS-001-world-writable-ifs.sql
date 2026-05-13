-- ============================================================================
-- SSI_TOOLS – IBM i Security Toolkit
-- ============================================================================
-- CHECK_ID      : IBMI-IFS-001
-- NOM           : Objets IFS accessibles en écriture à tout le monde
-- DOMAINE       : IFS
-- CLASSIFICATION: SAFE
-- TYPE          : AUDIT / FILESYSTEM SECURITY
-- EXECUTION     : ACS - Run SQL Scripts
--
-- OBJECTIF
-- --------
-- Identifier les répertoires et fichiers IFS potentiellement ouverts en
-- écriture pour *PUBLIC ou pour tous les utilisateurs.
--
-- Pourquoi ce contrôle est important ?
--
-- Parce qu’aujourd’hui l’IFS n’est plus “juste un coin UNIX d’IBM i”.
--
-- L’IFS héberge souvent :
--   - des exports métiers ;
--   - des flux inter-applicatifs ;
--   - des scripts ;
--   - des clés SSH ;
--   - des certificats ;
--   - des fichiers batch ;
--   - des APIs ;
--   - des dépôts temporaires ;
--   - parfois même des applications web complètes.
--
-- Et historiquement…
-- beaucoup d’environnements IBM i ont utilisé :
--
--   chmod 777
--
-- ... comme méthode officielle de résolution d’incident 😅
--
--
-- RISQUE SSI
-- ----------
-- Un répertoire IFS ouvert en écriture à tout le monde peut permettre :
--
--   - modification de fichiers applicatifs ;
--   - dépôt de scripts malveillants ;
--   - remplacement de fichiers batch ;
--   - altération d’exports ;
--   - compromission de flux ;
--   - propagation ransomware ;
--   - pivot Linux/Samba/QNTC ;
--   - persistance discrète.
--
-- Risque aggravé si :
--   - partage Samba ;
--   - accès NetServer ;
--   - montages NFS ;
--   - APIs ;
--   - scripts shell ;
--   - jobs batch ;
--   - comptes de service AD/Kerberos.
--
--
-- RAPPEL IBM i TERRAIN
-- --------------------
-- Sur IBM i, l’IFS mélange souvent :
--
--   - logique IBM i ;
--   - logique UNIX/POSIX ;
--   - logique Windows/Samba ;
--   - logique applicative.
--
-- Résultat :
-- les droits deviennent parfois très difficiles à suivre.
--
-- Et dans beaucoup de prod :
--
--   “On a ouvert temporairement le répertoire pour débloquer l’interface.”
--
-- ... puis le “temporaire” fête son 14e anniversaire 😅
--
--
-- IMPACT NIVEAU 40
-- ----------------
-- Le niveau 40 renforce la gouvernance des accès.
--
-- Même si le niveau 40 ne change pas directement les ACL POSIX,
-- il force généralement les équipes à :
--
--   - revoir les accès IFS ;
--   - documenter les flux ;
--   - réduire les droits implicites ;
--   - maîtriser les comptes techniques ;
--   - contrôler les accès Samba/QNTC/API.
--
-- L’IFS devient donc un vrai sujet SSI.
--
--
-- BONNES PRATIQUES
-- ----------------
-- Modèle cible recommandé :
--
--   - répertoires applicatifs dédiés ;
--   - owners techniques ;
--   - groupes applicatifs ;
--   - droits minimaux ;
--   - pas de chmod 777 ;
--   - séparation batch / API / utilisateurs ;
--   - supervision des répertoires sensibles ;
--   - contrôle des clés SSH et certificats.
--
--
-- PRE-CHECK
-- ---------
-- Ce script utilise QSYS2.IFS_OBJECT_STATISTICS.
--
-- IMPORTANT :
-- Certaines colonnes peuvent varier selon :
--   - IBM i 7.4 / 7.5 ;
--   - niveau TR/PTF ;
--   - options installées.
--
-- Des ajustements pourront être nécessaires après tests terrain.
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
-- Export CSV recommandé.
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
-- 1. PRE-CHECK – Vérification des colonnes disponibles
-- ============================================================================
-- Les services SQL IFS évoluent selon les versions IBM i.
-- On commence donc par explorer la structure réelle.
-- ============================================================================

SELECT *
FROM TABLE(
    QSYS2.IFS_OBJECT_STATISTICS(
        START_PATH_NAME => '/',
        SUBTREE_DIRECTORIES => 'NO'
    )
) AS IFSOBJ
FETCH FIRST 10 ROWS ONLY;


-- ============================================================================
-- 2. AUDIT – Répertoires et fichiers IFS potentiellement dangereux
-- ============================================================================
-- Cette requête recherche les objets avec des permissions très ouvertes.
--
-- ATTENTION :
-- Le format exact des permissions peut varier selon la version IBM i.
--
-- Les environnements utilisant :
--   rwxrwxrwx
-- ou équivalent
-- doivent être analysés rapidement.
--
-- IMPORTANT :
-- Tous les résultats ne sont pas forcément critiques.
-- Certains répertoires techniques peuvent nécessiter des droits étendus.
--
-- L’objectif est :
--   - identifier ;
--   - qualifier ;
--   - documenter ;
--   - réduire progressivement les expositions.
-- ============================================================================

/* ============================================================
   AUDIT SSI - IFS POTENTIELLEMENT DANGEREUX
   ------------------------------------------------------------
   OBJECTIF :
   - Identifier fichiers/répertoires IFS sensibles
   - Détecter absence d'AUTL
   - Détecter objets non journalisés
   - Identifier fichiers SSH / temporaires / cachés
   - Préparer forensic / PRA / niveau 40

   TYPE :
   SAFE / LECTURE SEULE
   ============================================================ */

SELECT

    PATH_NAME                         AS IFS_PATH,
    OBJECT_TYPE,
    OBJECT_OWNER,
    PRIMARY_GROUP,

    DATA_SIZE,

    AUTHORIZATION_LIST,

    OBJECT_AUDIT,
    JOURNALED,

    OBJECT_SIGNED,
    SYSTEM_TRUSTED_SOURCE,

    OBJECT_HIDDEN,
    TEMPORARY_OBJECT,

    CREATE_TIMESTAMP,
    DATA_CHANGE_TIMESTAMP,
    LAST_USED_TIMESTAMP,

    CASE

        WHEN PATH_NAME LIKE '/home/%/.ssh/%'
            THEN 'CRITICAL'

        WHEN PATH_NAME LIKE '/tmp/%'
          OR PATH_NAME LIKE '/QOpenSys/tmp/%'
            THEN 'HIGH'

        WHEN AUTHORIZATION_LIST IS NULL
          OR AUTHORIZATION_LIST = ''
            THEN 'MEDIUM'

        WHEN JOURNALED = 'NO'
            THEN 'MEDIUM'

        ELSE 'LOW'

    END AS SEVERITY,

    CASE

        WHEN PATH_NAME LIKE '/home/%/.ssh/%'
            THEN 'Présence de clés/fichiers SSH utilisateur : vérifier permissions et usages.'

        WHEN PATH_NAME LIKE '/tmp/%'
          OR PATH_NAME LIKE '/QOpenSys/tmp/%'
            THEN 'Répertoire temporaire : risque dépôt scripts/binaires.'

        WHEN AUTHORIZATION_LIST IS NULL
          OR AUTHORIZATION_LIST = ''
            THEN 'Objet IFS sans gouvernance *AUTL.'

        WHEN JOURNALED = 'NO'
            THEN 'Objet IFS non journalisé : visibilité forensic réduite.'

        ELSE
            'Objet IFS à qualifier selon contexte applicatif.'

    END AS SSI_COMMENT

FROM TABLE(

    QSYS2.IFS_OBJECT_STATISTICS(
        START_PATH_NAME => '/home',
        SUBTREE_DIRECTORIES => 'YES'
    )

) AS IFSOBJ

WHERE

       PATH_NAME LIKE '/home/%/.ssh/%'
    OR PATH_NAME LIKE '/tmp/%'
    OR PATH_NAME LIKE '/QOpenSys/tmp/%'
    OR AUTHORIZATION_LIST IS NULL
    OR AUTHORIZATION_LIST = ''
    OR JOURNALED = 'NO'

ORDER BY
    SEVERITY,
    IFS_PATH;