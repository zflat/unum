-- Toggle the direction for schema changes by changing the sign of the
-- current db_version value. A negative value will downgrade by 1
-- version when running schema changes. A positive value will upgrade
-- as applicable.
DELIMITER //
DROP PROCEDURE IF EXISTS `toggle` //
CREATE PROCEDURE `toggle`() 
BEGIN
  DECLARE current_version INT DEFAULT 0;
  SELECT CAST(`value` AS SIGNED) INTO current_version FROM `meta_options` WHERE `name`='db_version';
  SET current_version=-1*current_version;
  UPDATE `meta_options` SET `value`=current_version WHERE `name`='db_version';
  SELECT CONCAT('db_version: ', current_version) AS ' ';
END //
DELIMITER ;

START TRANSACTION;
  CALL toggle();
COMMIT;
DROP PROCEDURE IF EXISTS `toggle`;
