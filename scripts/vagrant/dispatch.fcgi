#!/bin/bash
this_dir=`dirname $0`
export DB_NAME=valDbName
export DB_USER=valDbUser
export DB_HOST=valDbPw
export DB_PW=valDbHost
exec "${this_dir}/app.fcgi"
