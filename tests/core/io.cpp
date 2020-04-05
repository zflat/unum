#include <iostream>
#include <vector>
#include <unordered_map>
#include <string>
#include <memory>
#include <cassert>

#include "core/io.hpp"

using namespace std;

//  DB_NAME=$APP_USER DB_USER=$APP_USER DB_PW=$APP_USER DB_HOST=127.0.0.1 ./io_test 
int main() {
  vector<unum::IO> vIO(2);
  int count = 0;
  int db_version;
  for(auto &io: vIO) {
    soci::session & db = io.db();
    db << "SELECT CAST(value AS SIGNED) FROM meta_options WHERE name='db_version'", into(db_version);
    // cout << " DB_VERSION " << db_version << endl;
    assert(db_version > 0);

    std::ostringstream val;
    val << "{❤" << (count++) << "}" ;
    string val_in = val.str();
    db << "INSERT INTO meta_options (name, value) VALUES ('io_val_utf8', :value) ON DUPLICATE KEY UPDATE value=:value", use(val_in, "value");

    string val_out;
    db << "SELECT value FROM meta_options WHERE name='io_val_utf8'", into(val_out);
    // cout << " VAL OUT " << val_out << endl;
    assert(val_in.compare(val_out) == 0);

    db << "DELETE FROM meta_options WHERE name='io_val_utf8'";
  }
  return EXIT_SUCCESS;
}
