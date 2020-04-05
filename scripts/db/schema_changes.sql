-- --------------------
-- Version definitions
-- --------------------

DELIMITER //

DROP PROCEDURE IF EXISTS `def_1` //
CREATE PROCEDURE `def_1`(IN direction INT)
def: BEGIN
  IF direction < 0 THEN
    DROP TABLE IF EXISTS `sessions`;
    DROP TABLE IF EXISTS `challenges`;
    DROP TABLE IF EXISTS `user_factors`;
    DROP TABLE IF EXISTS `users`;
    DROP TABLE IF EXISTS `applications`;
    LEAVE def;
  END IF;

  CREATE TABLE `applications` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `name` varchar(64),
    `app_key` varchar(64),
    UNIQUE INDEX `i_app_key` (`app_key`),
    PRIMARY KEY (`id`)
  ) ENGINE=InnoDB, charset=utf8;

  CREATE TABLE `users` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `application_id` INT UNSIGNED NOT NULL,
    `user_name` varchar(256), -- end application is reponsible for deciding if using email or user name
    -- `password_hash` varchar(256) NOT NULL,
    -- `salt` varchar(256) NOT NULL,
    updated_at TIMESTAMP NOT NULL ON UPDATE CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL,
    UNIQUE INDEX `i_application` (`application_id`, `id`),
    FOREIGN KEY (application_id) REFERENCES applications(id)
            ON UPDATE CASCADE
            ON DELETE RESTRICT,
    PRIMARY KEY (`id`)
  ) ENGINE=InnoDB, charset=utf8;

  CREATE TABLE `user_factors` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT UNSIGNED NOT NULL,
    `type` SMALLINT UNSIGNED NOT NULL, -- {email,sms,totp,etc}
    `val` text,
    `priority` SMALLINT,
    INDEX `i_user` (`user_id`, `type`),
    FOREIGN KEY (user_id) REFERENCES users(id)
            ON UPDATE CASCADE
            ON DELETE CASCADE,
    PRIMARY KEY (`id`)
  ) ENGINE=InnoDB, charset=utf8;
  
  CREATE TABLE `sessions` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT UNSIGNED NOT NULL,
    `application_id` INT UNSIGNED NOT NULL,
    `token` varchar(64),
    `ip` varchar(256),
    `user_agent` varchar(256),
    created_at TIMESTAMP NOT NULL,
    expires_at DATETIME,
    last_used DATETIME,
    INDEX `i_user` (`user_id`),
    UNIQUE INDEX `i_token_user` (`token`, `user_id`),
    UNIQUE INDEX `i_token_application` (`token`, `application_id`),
    FOREIGN KEY (user_id) REFERENCES users(id)
            ON UPDATE CASCADE
            ON DELETE CASCADE,
    PRIMARY KEY (`id`)
  ) ENGINE=InnoDB, charset=utf8;
  
  CREATE TABLE `challenges` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT UNSIGNED NOT NULL,
    `session_id` INT UNSIGNED NOT NULL,
    `type` SMALLINT UNSIGNED NOT NULL, -- {confirm,reset,totp,token,etc}
    `val` varchar(256),
    `token` varchar(64),
    created_at TIMESTAMP NOT NULL,
    expires_at DATETIME,
    INDEX `i_user` (`user_id`, `type`),
    UNIQUE INDEX `i_token_user` (`token`, `user_id`),
    UNIQUE INDEX `i_token_session` (`token`, `session_id`),
    FOREIGN KEY (user_id) REFERENCES users(id)
            ON UPDATE CASCADE
            ON DELETE CASCADE,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
            ON UPDATE CASCADE
            ON DELETE CASCADE,
    PRIMARY KEY (`id`)
  ) ENGINE=InnoDB, charset=utf8;
  
END //

-- ----------------- --
-- ----Run logic---- --
-- ----------------- --
DROP PROCEDURE IF EXISTS `run_changes` //
CREATE PROCEDURE `run_changes`()
BEGIN
  DECLARE current_version INT DEFAULT 0;
  DECLARE def_version INT DEFAULT 0;
  DECLARE next_version INT DEFAULT 0;
  DECLARE direction INT DEFAULT 1;
  changes_loop: LOOP
    SELECT CAST(`value` AS SIGNED) INTO current_version FROM `meta_options` WHERE `name`='db_version';
    IF current_version < 0 THEN 
      -- run current definition down
      SET direction=-1;
      SET def_version = ABS(current_version);
      SET next_version = def_version-1;
      SELECT CONCAT('downgrading to db_version: ', def_version) AS ' ';
    ELSE
      -- run next definition up
      SET def_version = current_version+1;
      SET next_version = def_version;
      SELECT CONCAT('current db_version: ', current_version) AS ' ';
    END IF;

    CASE def_version
      WHEN 1 THEN CALL def_1(direction);
      -- WHEN 2 THEN CALL def_2(direction);
      ELSE LEAVE changes_loop;
    END CASE;

    INSERT INTO `meta_options` (`name`, `value`) VALUES ('db_version', 1)
    ON DUPLICATE KEY UPDATE `value`=next_version;
 
    IF direction < 0 THEN 
      SELECT CONCAT('current db_version: ', CAST(`value` AS SIGNED)) AS ' ' 
      FROM `meta_options` WHERE `name`='db_version';
      LEAVE changes_loop; 
    END IF;
    ITERATE changes_loop;
  END LOOP changes_loop;
END //

DELIMITER ;

START TRANSACTION;
  CREATE TABLE IF NOT EXISTS `meta_options` (
    `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `name` varchar(64),
    `value` text DEFAULT NULL,
    UNIQUE INDEX `i_option_name` (`name`),
    PRIMARY KEY (`id`)
  ) ENGINE=InnoDB, charset=utf8;
  CALL run_changes();
COMMIT;


-- --------------- --
-- ----Cleanup---- --
-- --------------- --
DROP PROCEDURE IF EXISTS `def_1`;
DROP PROCEDURE IF EXISTS `run_changes`;

-- https://dev.mysql.com/doc/refman/5.7/en/mysql-batch-commands.html
