------------------------------------------------------------------------------
-- CHECK ID     : IBMI-INV-005
-- CHECK NAME   : Certificate Dependencies Inventory
-- DOMAIN       : SSL
-- LEVEL        : SAFE
--
-- DESCRIPTION
-- -----------
-- Inventaire des dépendances certificats SSL/TLS.
--
-- OBJECTIFS SSI
-- --------------
-- - Préparer PRA/PCA
-- - Préparer rotation certificats
-- - Identifier dépendances TLS
-- - Réduire incidents expiration
--
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- SECTION 1
-- Certificats connus
------------------------------------------------------------------------------

SELECT
    CERTIFICATE_STORE,
    CERTIFICATE_LABEL,
    EXPIRATION_DATE,
    SUBJECT,
    ISSUER
FROM QSYS2.CERTIFICATE_INFO
ORDER BY EXPIRATION_DATE;

------------------------------------------------------------------------------
-- SECTION 2
-- Certificats proches expiration
------------------------------------------------------------------------------

SELECT
    CERTIFICATE_STORE,
    CERTIFICATE_LABEL,
    EXPIRATION_DATE,
    SUBJECT
FROM QSYS2.CERTIFICATE_INFO
WHERE EXPIRATION_DATE < CURRENT_DATE + 90 DAYS
ORDER BY EXPIRATION_DATE;

------------------------------------------------------------------------------
-- SECTION 3
-- Risques SSI
------------------------------------------------------------------------------
--
-- Très fréquent :
--
-- certificat :
-- - oublié ;
-- - auto-signé ;
-- - expiré ;
-- - dépendance inconnue.
--
-- Résultat :
--
-- - APIs KO
-- - FTPS KO
-- - HTTPS KO
-- - batchs KO
--
-- Vérifier :
--
-- 1. Qui utilise le certificat ?
-- 2. Batchs dépendants ?
-- 3. APIs dépendantes ?
-- 4. PRA/PCA testé ?
-- 5. Rotation documentée ?
--
------------------------------------------------------------------------------