set(DB_SETUP_ENV
  "DB_TEST_USER=$ENV{APP_USER_TEST}"
  "DB_TEST_NAME=$ENV{APP_USER_TEST}"
  "DB_TEST_PASS=$ENV{APP_PASS}"
  )
set(DB_ENV
  "DB_NAME=$ENV{APP_USER_TEST}"
  "DB_USER=$ENV{APP_USER_TEST}"
  "DB_PW=$ENV{APP_PASS}"
  "DB_HOST=127.0.0.1"
  )
add_test (NAME setupDB
  COMMAND ${CMAKE_SOURCE_DIR}/scripts/test/setup.sh
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  )
add_test (NAME seedDB
  COMMAND ${CMAKE_SOURCE_DIR}/scripts/test/seed.sh
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  )
set_tests_properties(setupDB PROPERTIES ENVIRONMENT "${DB_SETUP_ENV}")
set_tests_properties(setupDB PROPERTIES FIXTURES_SETUP DB)

set_tests_properties(seedDB PROPERTIES ENVIRONMENT "${DB_SETUP_ENV}")
set_tests_properties(seedDB PROPERTIES FIXTURES_REQUIRED DB)
set_tests_properties(seedDB PROPERTIES FIXTURES_SETUP DB_SEED)

#######################
# Unit test executables
set(TESTS
  # "router"
  "user_model"
  )
foreach(UNITTEST ${TESTS})
    add_executable(${UNITTEST}_test EXCLUDE_FROM_ALL unit/${UNITTEST}.cpp ${SRC_FILES})
    target_link_libraries(${UNITTEST}_test soci_core soci_mysql mysqlclient soci_sqlite3 sqlite3 fcgi++ fcgi curl z)
    add_test(unit_${UNITTEST} ${UNITTEST}_test )
    set_tests_properties(unit_${UNITTEST} PROPERTIES ENVIRONMENT "${DB_ENV}")
    set_tests_properties(unit_${UNITTEST} PROPERTIES FIXTURES_REQUIRED DB_SEED)

    list(APPEND TEST_UNIT_TARGET ${UNITTEST}_test) # unit tests list
    list(APPEND TEST_TARGET ${UNITTEST}_test) # all tests list
endforeach()

add_executable(srp_test EXCLUDE_FROM_ALL unit/srp.cpp ${SRC_FILES_VENDOR})
add_test(unit_srp srp_test)
list(APPEND TEST_UNIT_TARGET srp_test) # unit tests list
list(APPEND TEST_TARGET srp_test) # all tests list

#######################
# Core test executables

add_executable(io_test EXCLUDE_FROM_ALL core/io.cpp ${VENDOR_SRC_FILES} ${CMAKE_SOURCE_DIR}/src/core/io.cpp)
target_link_libraries(io_test soci_core soci_mysql mysqlclient soci_sqlite3 sqlite3 fcgi++ fcgi curl z)
add_test(core_io io_test)
set_tests_properties(core_io PROPERTIES FIXTURES_REQUIRED DB)
set_tests_properties(core_io PROPERTIES ENVIRONMENT "${DB_ENV}")
list(APPEND TEST_CORE_TARGET io_test)
list(APPEND TEST_TARGET io_test)


add_executable(model_test EXCLUDE_FROM_ALL core/model.cpp ${CMAKE_SOURCE_DIR}/src/core/attr_map.cpp ${CMAKE_SOURCE_DIR}/src/core/model.cpp ${CMAKE_SOURCE_DIR}/src/core/io.cpp)
target_link_libraries(model_test soci_core soci_mysql mysqlclient soci_sqlite3 sqlite3 fcgi++ fcgi curl z)
add_test(core_model model_test)
set_tests_properties(core_model PROPERTIES FIXTURES_REQUIRED DB)
set_tests_properties(core_model PROPERTIES ENVIRONMENT "${DB_ENV}")
list(APPEND TEST_CORE_TARGET model_test)
list(APPEND TEST_TARGET model_test)

#######################################
# Integration tests w/ external command
add_test (NAME setupDBIntegration
  COMMAND ${CMAKE_SOURCE_DIR}/scripts/test/seed.sh
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  )
set_tests_properties(setupDBIntegration PROPERTIES ENVIRONMENT "${DB_SETUP_ENV}")
set_tests_properties(setupDBIntegration PROPERTIES FIXTURES_SETUP DB_SETUP_INTEGRATION)
add_test(NAME integration
  COMMAND integration.sh
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/scripts/test
)
set_tests_properties(integration PROPERTIES ENVIRONMENT "${DB_ENV}")
set_tests_properties(integration PROPERTIES FIXTURES_REQUIRED DB_SETUP_INTEGRATION)

# see https://stackoverflow.com/a/10824578


set(PRINT_TEST_RESULT "printf '\\e[38;5;46mTests Passed\\n\\033[0m' || printf '\\e[38;5;196mTests Failed\\n\\033[0m'")


###################
# Core tests target
# (prefixed with core_)
add_custom_target(core_tests
  COMMAND /bin/bash -lic "ctest -V -R ^core && ${PRINT_TEST_RESULT}"
  DEPENDS ${TEST_CORE_TARGET}
  VERBATIM
  )

###################
# Unit tests target
add_custom_target(unit_tests
  COMMAND /bin/bash -lic "ctest -V -R ^unit && ${PRINT_TEST_RESULT}"
  DEPENDS ${TEST_UNIT_TARGET}
  VERBATIM
 )


##########################
# Integration tests target
add_custom_target(integration_tests
 COMMAND /bin/bash -lic "ctest -V -R ^integration && ${PRINT_TEST_RESULT}"
 DEPENDS ${TEST_TARGET} app.fcgi
 VERBATIM
)

##################
# All tests target

# list(APPEND TEST_TARGET io_test user_model_test model_test) #not needed since this list is build above
add_custom_target(_tests DEPENDS ${TEST_TARGET} VERBATIM)
add_custom_target(tests
  COMMAND /bin/bash -lic "ctest -V && ${PRINT_TEST_RESULT}"
  DEPENDS ${TEST_TARGET}
  VERBATIM
  )
