DROP TABLE IF EXISTS `users`;
DROP TABLE IF EXISTS `sessions`;
DROP TABLE IF EXISTS `challenges`;
DROP TABLE IF EXISTS `user_factors`;
DROP TABLE IF EXISTS `applications`;
DROP TABLE IF EXISTS `meta_options`;
CREATE TABLE `meta_options` (
  `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `name` varchar(64),
  `value` text,
  UNIQUE INDEX `i_option_name` (`name`),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB, charset=utf8;

-- https://dev.mysql.com/doc/refman/5.7/en/mysql-batch-commands.html
