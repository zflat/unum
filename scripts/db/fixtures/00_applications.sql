START TRANSACTION;
SELECT 'Applications' AS ' ';
SET FOREIGN_KEY_CHECKS = 0;
TRUNCATE TABLE `applications`;
SET FOREIGN_KEY_CHECKS = 1;
INSERT INTO `applications`
 (`name`, `app_key`)
VALUES
 ('app1', 'k-app-A')
,('app2', 'k-app-B')
;

COMMIT;
