#include <iostream>
#include <string>
#include <ctime>
#include <vector>
#include <unordered_map>

#include "core/attr_map.hpp"

using namespace std;

namespace unum {

  const attr_config::map AttrMap::attribute_names() const {
    return _attribute_names;
  }

  void AttrMap::clear() {
    _vals.clear();
    _vals_null.clear();
  }

  AttrMap::SETTER AttrMap::erase(const string & attr_name) {
    auto config = attribute_names();
    // make sure the attribute is present
    if(!config.count(attr_name)) {
      return SETTER::failure;
    }

    bool changed = false;
    if(_vals.count(attr_name) == 1 || _vals_null.count(attr_name) == 1) {
      changed = true;
    }
    _vals.erase(attr_name);
    _vals_null.erase(attr_name);
    return changed ? AttrMap::SETTER::updated : AttrMap::SETTER::unchanged;
  }

  AttrMap::SETTER AttrMap::set_null(const string & attr_name, bool flag) {
    AttrMap::SETTER result = AttrMap::SETTER::unchanged;
    auto config = attribute_names();
    // make sure the attribute is present
    if(!config.count(attr_name)) {
      return SETTER::failure;
    }

    bool current = is_null(attr_name);
    if(flag && !current) {
      // cannot be both null and present
      if (_vals.count(attr_name)) {
        _vals.erase(attr_name);
        result = AttrMap::SETTER::updated;
      } else {
        result = AttrMap::SETTER::inserted;
      }
    }
    _vals_null[attr_name] = flag;
    return result;
  }

  bool AttrMap::is_null(const string & attr_name) const {
    return (_vals_null.count(attr_name) == 1)
      && (_vals_null.at(attr_name));
  }

  bool AttrMap::is_present(const string & attr_name) const {
    return _vals.count(attr_name) == 1;
  }

  bool AttrMap::copy_value(const string & name, const AttrMap & source, AttrMap & dest) {
    attr_config::map source_configs = source.attribute_names();
    attr_config::map dest_configs = dest.attribute_names();
    bool found = false;

    if(dest_configs.count(name) != 1 || 
       source_configs.at(name)->type != dest_configs.at(name)->type) {
      return false;
    }

    switch(source_configs.at(name)->type) {
    case unum::ATTR_TYPE::int_t:
      dest.set<int>(name, source.get<int>(name, found));
      break;
    case unum::ATTR_TYPE::long_t:
      dest.set<long long>(name, source.get<long long>(name, found));
      break;
    case unum::ATTR_TYPE::string_t:
      dest.set<string>(name, source.get<string>(name, found));
      break;
    case unum::ATTR_TYPE::double_t:
      dest.set<double>(name, source.get<double>(name, found));
      break;
    case unum::ATTR_TYPE::datetime_t:
      dest.set<std::tm>(name, source.get<std::tm>(name, found));
      break;
    case unum::ATTR_TYPE::char_t:
      dest.set<char>(name, source.get<char>(name, found));
      break;
    default:
      break;
    }
    return found;
  }

  string AttrMap::gets(const string & attr_name, bool & found) const {
    if(!(found = (_vals.count(attr_name)==1))) {
      return "";
    }
    char date_buff [40];
    std::tm dt;
    std::ostringstream retval;
    switch(_attribute_names.at(attr_name)->type) {
    case ATTR_TYPE::int_t:
      retval << _vals.at(attr_name)->get<int>();
      break;
    case ATTR_TYPE::long_t:
      retval << _vals.at(attr_name)->get<long long>();
      break;
    case ATTR_TYPE::string_t:
      retval << _vals.at(attr_name)->get<string>();
      break;
    case ATTR_TYPE::datetime_t:
      // ISO 8601
      dt = _vals.at(attr_name)->get<std::tm>();
      strftime(date_buff, 40, "%Y-%m-%dT%H:%M:%S%z", &dt);
      retval << date_buff;
      break;
    default:
      break;
    }
    return retval.str();
  }

  string AttrMap::to_json() const {
    std::ostringstream retval;
    retval << "{";
    bool first = true;
    bool has_attr = false;
    bool is_null = false;
    bool enclose_quotes = false;
    attr_config::ptr config;
    string name, val;
    // access attribute values in order of position
    std::map<int, std::pair<std::string, std::string>> props;
    std::pair<std::string, std::string> prop;
    for(auto & n: _attribute_names) {
      std::ostringstream val_str;
      std::tie(name, config) = n;
      is_null = this->is_null(name);
      string val = gets(name, has_attr);
      if(!has_attr && !is_null) {
        continue;
      }
      switch(config->type) {
      case unum::ATTR_TYPE::string_t:
      case unum::ATTR_TYPE::char_t:
      case unum::ATTR_TYPE::datetime_t:
        enclose_quotes = !is_null;
        break;
      case unum::ATTR_TYPE::int_t:
      case unum::ATTR_TYPE::long_t:
      case unum::ATTR_TYPE::double_t:
        enclose_quotes = false;
      }

      val_str << (enclose_quotes ? "\"" : "")
              << (is_null ? "null" : val)
              << (enclose_quotes ? "\"" : "");
      props[config->position] = std::make_pair(name, val_str.str());
    }

    // traversal in order of config position
    first = true;
    for(auto & e: props) {
      prop = e.second;
      if(first) { first = false;} else {retval<< ",";};
      retval << "\"" << prop.first << "\":" << prop.second;
    }

    retval << "}";
    return retval.str();
  }
  
  REGISTER_ATTR_TYPE(int, ATTR_TYPE::int_t);
  REGISTER_ATTR_TYPE(long long, ATTR_TYPE::long_t);
  REGISTER_ATTR_TYPE(std::string, ATTR_TYPE::string_t);
  REGISTER_ATTR_TYPE(double, ATTR_TYPE::double_t);
  REGISTER_ATTR_TYPE(std::tm, ATTR_TYPE::datetime_t);
  REGISTER_ATTR_TYPE(char, ATTR_TYPE::char_t);

}


