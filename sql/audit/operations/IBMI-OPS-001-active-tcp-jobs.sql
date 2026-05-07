------------------------------------------------------------------------------
-- CHECK ID     : IBMI-OPS-001
-- CHECK NAME   : Active TCP/IP Jobs
-- DOMAIN       : OPS
-- LEVEL        : SAFE
--
-- DESCRIPTION
-- -----------
-- Inventaire des jobs TCP/IP actifs.
--
-- OBJECTIFS SSI
-- --------------
-- - Identifier activité réseau réelle
-- - Corréler services/jobs/users
-- - Aider PRA/PCA
-- - Détecter services oubliés
--
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- SECTION 1
-- Jobs réseau actifs
------------------------------------------------------------------------------

SELECT
    JOB_NAME,
    AUTHORIZATION_NAME,
    SUBSYSTEM,
    FUNCTION,
    JOB_STATUS,
    MEMORY_POOL
FROM TABLE(QSYS2.ACTIVE_JOB_INFO())
WHERE SUBSYSTEM LIKE 'QSYSWRK%'
   OR FUNCTION LIKE '%TCP%'
   OR FUNCTION LIKE '%FTP%'
   OR FUNCTION LIKE '%SSH%'
ORDER BY FUNCTION;

------------------------------------------------------------------------------
-- SECTION 2
-- Intérêt SSI
------------------------------------------------------------------------------
--
-- Sur IBM i :
--
-- les services TCP/IP tournent sous forme de jobs.
--
-- Très utile pour :
--
-- - voir activité réelle
-- - identifier comptes techniques
-- - préparer forensic
-- - corréler incidents réseau
--
------------------------------------------------------------------------------