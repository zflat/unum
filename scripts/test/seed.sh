#!/usr/bin/env bash
seed_sh_dir="$( cd "$(dirname "$0")" ; pwd -P )"
for fixture in "$seed_sh_dir"/../db/fixtures/*.sql; do
    [ -e "$fixture" ] || continue
    mysql -u $DB_TEST_USER -p$DB_TEST_PASS $DB_TEST_NAME < $fixture 1>> /dev/null
done
