#include <iostream>
#include <string>
#include <vector>

#include "user.hpp"

namespace unum {

  // Bind attribute name to type
  REGISTER_ATTR(User, id,             long long);
  REGISTER_ATTR(User, application_id, long long);
  REGISTER_ATTR(User, user_name,      std::string);
  REGISTER_ATTR(User, created_at,     std::tm);
  REGISTER_ATTR(User, updated_at,     std::tm);

  // Initialize static attribute configurations list
  const attr_config::map User::_attribute_names {
    {CONFIG_ATTR(id            )},
    {CONFIG_ATTR(application_id)},
    {CONFIG_ATTR(user_name     )},
    {CONFIG_ATTR(created_at    )},
    {CONFIG_ATTR(updated_at    )},
  };

  const std::string User::_table_name = "users";

  bool User::validate() {
    return true;
  }

}
