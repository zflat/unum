#include <iostream>
#include <cassert>

#include "core/io.hpp"
#include "user.hpp"

using namespace std;
using namespace unum;

int main() {
  int status;

  shared_ptr<IO> io;
  io.reset(new IO());

  // Verify attributes are fully defined
  User u(io);
  assert( u.set<User::id>(ATTR_STATUS::not_present) == AttrMap::SETTER::unchanged );
  assert( u.set<User::user_name>(ATTR_STATUS::not_present) == AttrMap::SETTER::unchanged );
  assert( u.set<User::created_at>(ATTR_STATUS::not_present) == AttrMap::SETTER::unchanged );
  assert( u.set<User::updated_at>(ATTR_STATUS::not_present) == AttrMap::SETTER::unchanged );
  assert( u.set<User::application_id>(ATTR_STATUS::val_null) == AttrMap::SETTER::inserted );
  assert( !u.save() );
  assert( !u.del() );

  assert( u.primary_key().size() > 0 );
  assert (unum::User::TableName().compare(u.table_name()) == 0);

  assert( u.set<User::user_name>((string)"usertester") == AttrMap::SETTER::inserted );
  assert( u.set<User::application_id>((long long)1) == AttrMap::SETTER::updated );



  // TODO logging added to application (https://github.com/gabime/spdlog/wiki/1.-QuickStart)



  assert(u.save());
  // assert(u.del());

  return 0;
}
