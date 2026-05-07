----------------------------------------------------------------------
-- IBMI-PWD-002-password-never-expire.sql
--
-- CHECK :
-- Profils IBM i avec mot de passe sans expiration ou expiration longue
--
-- OBJECTIF :
-- Identifier les profils actifs dont la politique d’expiration
-- du mot de passe est absente ou trop permissive.
--
-- INDICATEURS :
-- PASSWORD_EXPIRATION_INTERVAL = 0
-- PASSWORD_EXPIRATION_INTERVAL > 180
--
-- RISQUE SSI :
-- HIGH
--
-- TYPE :
-- AUDIT
--
-- NIVEAU DE RISQUE DU SCRIPT :
-- SAFE
--
-- IMPACT :
-- Aucun impact système. Lecture seule uniquement.
--
-- UTILISATION :
-- ACS -> Run SQL Scripts
--
-- EXEMPLES :
-- LAB  : MonUserIbm
-- PROD : SSI_TOOLS
----------------------------------------------------------------------

SELECT TABLE_SCHEMA,
       TABLE_NAME
FROM QSYS2.SYSTABLES
WHERE TABLE_SCHEMA = 'QSYS2'
  AND TABLE_NAME = 'USER_INFO';

----------------------------------------------------------------------
-- AUDIT PRINCIPAL
----------------------------------------------------------------------

SELECT
    AUTHORIZATION_NAME          AS USER_NAME,
    STATUS                      AS USER_STATUS,
    USER_CLASS_NAME             AS USER_CLASS,
    LOCAL_PASSWORD_MANAGEMENT   AS LOCAL_PASSWORD_MANAGEMENT,
    PASSWORD_EXPIRATION_INTERVAL AS PASSWORD_EXPIRATION_INTERVAL,
    DAYS_UNTIL_PASSWORD_EXPIRES AS DAYS_UNTIL_PASSWORD_EXPIRES,
    GROUP_PROFILE_NAME          AS PRIMARY_GROUP,
    HOME_DIRECTORY              AS HOME_DIRECTORY,
    PREVIOUS_SIGNON             AS PREVIOUS_SIGNON,
    SPECIAL_AUTHORITIES         AS SPECIAL_AUTHORITIES
FROM QSYS2.USER_INFO
WHERE STATUS = '*ENABLED'
  AND LOCAL_PASSWORD_MANAGEMENT = 'YES'
  AND (
       PASSWORD_EXPIRATION_INTERVAL = 0
       OR PASSWORD_EXPIRATION_INTERVAL > 180
  )
ORDER BY PASSWORD_EXPIRATION_INTERVAL DESC,
         AUTHORIZATION_NAME;

----------------------------------------------------------------------
-- LECTURE DU RESULTAT
--
-- Les profils retournés ont une expiration désactivée ou trop longue.
--
-- A vérifier en priorité :
-- - comptes nominatifs,
-- - comptes administrateurs,
-- - comptes avec *ALLOBJ ou *SECADM,
-- - comptes techniques non documentés,
-- - comptes accessibles via VPN / SSH / 5250.
--
-- REMEDIATION POSSIBLE :
-- - appliquer une durée d’expiration conforme à la politique SSI,
-- - forcer PWDEXP(*YES) si nécessaire,
-- - isoler les comptes techniques,
-- - documenter les exceptions.
----------------------------------------------------------------------