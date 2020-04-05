#ifndef unum_user_h
#define unum_user_h

#include <unordered_map>
#include "core/model.hpp"
#include "core/attr_base.hpp"

namespace unum {
  class User : public Model<User> {
  public:
    using Model::Model;

    // Define attribute types
    struct id             : public attr_base::id {};
    struct application_id : public attr_base::fk {
      const bool is_nullable = false;
    };
    struct user_name      : public attr_base::string {};
    struct created_at     : public attr_base::created_at {};
    struct updated_at     : public attr_base::updated_at {};

    bool validate();
  protected:
    const static std::string _table_name;
    const static attr_config::map _attribute_names;
    friend class Model<User>;
  };
}

#endif
