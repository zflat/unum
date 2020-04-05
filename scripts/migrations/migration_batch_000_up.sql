DROP PROCEDURE IF EXISTS `sp1`;
DELIMITER //
CREATE PROCEDURE `sp1`()
BEGIN
  DECLARE current_version INT;
  DECLARE new_version INT DEFAULT 0;
  SELECT CAST(`value` AS UNSIGNED) INTO current_version
    FROM `meta_options` WHERE `name`='db_version';
  IF current_version < new_version OR current_version IS NULL THEN
    START TRANSACTION;
    -- START MIGRATION DEFINITION

    DROP TABLE IF EXISTS `users`;
    CREATE TABLE `users` (
      `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
      `application_id` INT UNSIGNED NOT NULL,
      `user_name` varchar(256), -- app is reponsible for deciding if using email or handle
      `password_hash` varchar(256) NOT NULL,
      `salt` varchar(256) NOT NULL,
      created_at DATETIME,
      updated_at TIMESTAMP,
      UNIQUE INDEX `i_application` (`application_id`, `id`),
      PRIMARY KEY (`id`)
    ) ENGINE=InnoDB, charset=utf8;
    
    DROP TABLE IF EXISTS `sessions`;
    CREATE TABLE `sessions` (
      `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
      `user_id` INT UNSIGNED NOT NULL,
      `application_id` INT UNSIGNED NOT NULL,
      `token` varchar(64),
      `ip` varchar(256),
      `user_agent` varchar(256),
      created_at DATETIME,
      expires_at DATETIME,
      last_used DATETIME,
      INDEX `i_user` (`user_id`),
      UNIQUE INDEX `i_token_user` (`token`, `user_id`),
      UNIQUE INDEX `i_token_application` (`token`),
      PRIMARY KEY (`id`)
    ) ENGINE=InnoDB, charset=utf8;
    
    DROP TABLE IF EXISTS `challenges`;
    CREATE TABLE `challenges` (
      `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
      `user_id` INT UNSIGNED NOT NULL,
      `session_id` INT UNSIGNED NOT NULL,
      `type` SMALLINT UNSIGNED NOT NULL, -- {confirm,reset,totp,token,etc}
      `val` varchar(256),
      `token` varchar(64),
      created_at DATETIME,
      expires_at DATETIME,
      INDEX `i_user` (`user_id`, `type`),
      UNIQUE INDEX `i_token_user` (`token`, `user_id`),
      UNIQUE INDEX `i_token_session` (`token`, `session_id`),
      PRIMARY KEY (`id`)
    ) ENGINE=InnoDB, charset=utf8;
    
    DROP TABLE IF EXISTS `user_factors`;
    CREATE TABLE `user_factors` (
      `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
      `user_id` INT UNSIGNED NOT NULL,
      `type` SMALLINT UNSIGNED NOT NULL, -- {email,sms,totp,etc}
      `val` text,
      `priority` SMALLINT,
      INDEX `i_user` (`user_id`, `type`),
      PRIMARY KEY (`id`)
    ) ENGINE=InnoDB, charset=utf8;
    
    DROP TABLE IF EXISTS `applications`;
    CREATE TABLE `applications` (
      `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
      `name` varchar(64),
      `app_key` varchar(64),
      UNIQUE INDEX `i_app_key` (`app_key`),
      PRIMARY KEY (`id`)
    ) ENGINE=InnoDB, charset=utf8;
    
    DROP TABLE IF EXISTS `meta_options`;
    CREATE TABLE `meta_options` (
      `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
      `name` varchar(64),
      `value` text,
      UNIQUE INDEX `i_option_name` (`name`),
      PRIMARY KEY (`id`)
    ) ENGINE=InnoDB, charset=utf8;

    -- END MIGRATION DEFINITION
    INSERT INTO `meta_options` (`name`, `value`) VALUES ('db_version', new_version);
    SELECT 'Migration complete' AS ' ';
    COMMIT;
  ELSE
    SELECT 'Migration skipped' AS ' ';
  END IF;
END //
CALL sp1();
DROP PROCEDURE IF EXISTS `sp1`;
