#!/usr/bin/env bash
setup_sh_dir="$( cd "$(dirname "$0")" ; pwd -P )"
echo "DROP USER '$DB_TEST_USER'@'localhost';" | mysql -uroot 2>> /dev/null
echo "CREATE USER '$DB_TEST_USER'@'localhost' IDENTIFIED BY '$DB_TEST_PASS';" | mysql -uroot 2>> /dev/null
cat <<EOF | mysql -uroot
DROP DATABASE IF EXISTS $DB_TEST_NAME;
CREATE DATABASE IF NOT EXISTS $DB_TEST_NAME;
GRANT ALL ON $DB_TEST_NAME.* TO '$DB_TEST_USER'@'localhost';
EOF
mysql -u$DB_TEST_USER -p$DB_TEST_PASS $DB_TEST_NAME < "$setup_sh_dir/../db/schema_changes.sql" 1>> /dev/null
