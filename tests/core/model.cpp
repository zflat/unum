#include <cassert>
#include <unordered_map>
#include <ctime>
#include <unistd.h>

#include "core/io.hpp"
#include "core/model.hpp"
#include "core/attr_base.hpp"

using namespace std;
using namespace unum;

namespace unum {

  class ModelTester : public Model<ModelTester> {
  public:
    using Model::Model;
    // ModelTester() : Model<ModelTester>() {}; // Needed for singleton instance?

    // (1) define attributes
    struct created_at     : public attr_base::created_at {};
    struct updated_at     : public attr_base::updated_at {};
    struct desc           : public attr_base::string {};
    struct id             : public attr_base::id {};
    struct name : public attr_base::string {
      const bool is_nullable = false; // Override value from attr_base::string
    };
    struct application_id : public attr_config {
      const ATTR_TYPE type          = ATTR_TYPE::int_t;
      const bool is_nullable        = true;
      const bool is_auto            = false;
      const std::string default_val = "99"; // using a default value
    };

    bool validate();
  protected:
    const static string _table_name;
    const static attr_config::map _attribute_names;
    friend class Model<ModelTester>;
  };

  // (2) bind attribute name to declared type
  REGISTER_ATTR(ModelTester, id,             long long);
  REGISTER_ATTR(ModelTester, application_id, int);
  REGISTER_ATTR(ModelTester, name,           std::string);
  REGISTER_ATTR(ModelTester, desc,           std::string);
  REGISTER_ATTR(ModelTester, created_at,     std::tm);
  REGISTER_ATTR(ModelTester, updated_at,     std::tm);

  // (3) add attributes to the model definition
  const attr_config::map ModelTester::_attribute_names {
    {"id", attr_config::make<id>()}, // long version without macro
    {CONFIG_ATTR(application_id)},
    {CONFIG_ATTR(name)},
    {CONFIG_ATTR(desc)},
    {CONFIG_ATTR(created_at)},
    {CONFIG_ATTR(updated_at)},
  };

  const std::string ModelTester::_table_name = "model_testers";

  // Override the default primary key column name (optional)
  template <>
  const vector<string> Model<ModelTester>::_primary_key = {"id"};


  bool ModelTester::validate() {
    return true;
  }
}

int main () {
  bool status;

  shared_ptr<IO> io;
  io.reset(new IO());

  soci::session & db = io->db();

  // Setup
  db.create_table(ModelTester::TableName())
    (
      "id INT UNSIGNED NOT NULL AUTO_INCREMENT,"
      "application_id INT NOT NULL,"
      "name varchar(100) NOT NULL,"
      "`desc` varchar(100),"
      "updated_at TIMESTAMP NOT NULL ON UPDATE CURRENT_TIMESTAMP," // https://stackoverflow.com/a/42308662
      "created_at TIMESTAMP NOT NULL,"
     )
    .primary_key("k_id", "id")
    ;

  assert(Model<ModelTester>::AttributeNames().at("application_id")->default_val.compare("99") == 0);

  ModelTester t(io);
  vector<string> pkCol = t.primary_key();
  assert(pkCol[0].length() > 0);

  assert(t.set_attr<long long>("application_id", 123) == AttrMap::SETTER::failure);
  assert((t.set<ModelTester::application_id, int>(123) == AttrMap::SETTER::inserted));
  assert((t.set<ModelTester::application_id, int>(124) == AttrMap::SETTER::updated));

  assert(!t.save());
  assert((t.set<ModelTester::name, string>("test name") == AttrMap::SETTER::inserted));

  assert(t.save());
  assert((t.get<ModelTester::id, long long>(status) == 1));
  assert((t.get<ModelTester::application_id, int>(status)) == 124);
  assert((t.get<ModelTester::desc, string>(status).size()==0));
  assert(!status);
  assert((t.get<ModelTester::desc>() == ATTR_STATUS::val_null));

  assert(((int)t.set<ModelTester::name>(ATTR_STATUS::val_null) != -1));
  assert(!t.save());
  assert((t.set<ModelTester::name, string>("test name") == AttrMap::SETTER::updated));

  std::tm created_at = t.get<ModelTester::created_at, std::tm>(status);
  assert(t.get<ModelTester::updated_at>() != ATTR_STATUS::val_null);
  assert(t.get("updated_at") != ATTR_STATUS::val_null);
  assert(t.get("created_at") != ATTR_STATUS::val_null);

  sleep(1); // for testing updated_at
  assert(t.save());
  assert(t.get("updated_at") != ATTR_STATUS::val_null);
  assert(t.get<ModelTester::updated_at>() != ATTR_STATUS::val_null);
  std::tm updated_at = t.get_attr<std::tm>("updated_at", status);
  std::tm created_02 = t.get<ModelTester::created_at, std::tm>(status);
  assert(created_at.tm_sec != updated_at.tm_sec);
  assert(created_02.tm_sec != updated_at.tm_sec); // created_at is unchanged
  assert(created_at.tm_sec == created_02.tm_sec); // created_at is unchanged

  ModelTester t1(io);
  std::tm now;
  assert(t1.set<ModelTester::updated_at>(now) == AttrMap::SETTER::inserted);
  assert(!t1.save());
  assert((t1.set<ModelTester::name, string>("test t1 name") == AttrMap::SETTER::inserted));
  assert(t1.save());
  assert((t1.get<ModelTester::id, long long>(status) == 2));

  assert(t1.get_attr<long long>("id", status) != t.get_attr<long long>("id", status));
  assert((t1.get<ModelTester::application_id, int>(status) == 99)); // default value

  t1.set<ModelTester::application_id, int>(124);
  assert(t1.save());
  assert((t1.get<ModelTester::application_id, int>(status) == 124)); // new value

  assert(t1.del());
  assert((t1.get<ModelTester::id, long long>(0, status) == 0));

  assert(((int)t1.set<ModelTester::desc>(ATTR_STATUS::val_null) >= 0));
  assert((t1.get<ModelTester::desc>() == ATTR_STATUS::val_null));

  // Create new record with required field
  assert((t1.set<ModelTester::name, string>("test t1 name") == AttrMap::SETTER::inserted));
  assert(t1.save());
  assert(t1.is_persisted());
  assert(t1.reload());

  // Loading a record by primary key
  ModelTester tFind(io);
  tFind.set<ModelTester::id, long long>(t1.get<ModelTester::id, long long>(status)+1000);
  assert(!tFind.reload());
  assert(!tFind.is_persisted());
  tFind.set<ModelTester::id, long long>(t1.get<ModelTester::id, long long>(status));
  assert(tFind.reload());
  assert(tFind.is_persisted());

  AttrMap m = ModelTester::AttributeNames();

  // query for a single record
  db << "SELECT * from model_testers ORDER BY id DESC LIMIT 2;", into(m);
  ModelTester tester(io, m, false);
  assert(tester.is_persisted());

  // cursor-based query for multiple records
  // see https://stackoverflow.com/a/42275224
  statement st = (db.prepare << "SELECT * from model_testers ORDER BY id DESC LIMIT 2;", into(m));
  st.execute();
  while(st.fetch()) {
    ModelTester tester(io, m);
    assert(tester.is_persisted());
    assert((tester.get<ModelTester::id, long long>(status) > 0));
    assert(m.to_json().length() > 2);
  }

  // multi-row query
  rowset<ModelAttrs<ModelTester>> rs = (db.prepare << "SELECT * from model_testers ORDER BY id DESC LIMIT 2;");
  for(auto it=rs.begin(); it != rs.end(); ++it) {
    ModelTester tester(io, *it);
    assert( tester.is_persisted() );
    assert( (tester.get<ModelTester::id, long long>(status) > 0) );
    assert(it->to_json().length() > 2);
    cout << it->to_json() << std::endl;
  }

  return EXIT_SUCCESS;
}
