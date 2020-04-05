#ifndef unum_attr_map_h
#define unum_attr_map_h

#define REGISTER_ATTR_TYPE(X, Y) \
  template<> const int AttrTypeParseTraits<X>::id = (int)Y

#include <iostream>
#include <string>
#include <ctime>
#include <vector>
#include <unordered_map>

#include "core/attr_config.hpp"
#include "soci/values.h"
#include "soci/type-holder.h"
#include "soci/rowid.h"

using namespace std;

namespace unum{

  // https://stackoverflow.com/a/36926221
  template<typename T>
  struct AttrTypeParseTraits {
    static const int id;
    typedef T type;
  };

  class AttrMap {
  public:
    enum class SETTER { // set results
      failure,
      inserted,
      updated,
      unchanged,
    };
    AttrMap() = delete;
    AttrMap(const attr_config::map & attributes) : _attribute_names(attributes) {};
    //AttrMap(map<string, tuple<attr_config, value_holder>)) // config with initial values
    AttrMap(const AttrMap & other) : _attribute_names(other.attribute_names()) {
      for(auto & n : other.attribute_names()) {
        if(other.is_present(n.first)) {
          AttrMap::copy_value(n.first, other, *this);
          set_null(n.first, false);
        } else if (other.is_null(n.first)) {
          set_null(n.first, true);
        }
      }
    }
    virtual ~AttrMap() {
      _vals.clear();
    };

    template<typename V>
    static unique_ptr<soci::details::holder> value_u(V val) {
      return static_cast<unique_ptr<soci::details::holder>>(new soci::details::type_holder<V>(new V(val)));
    }

    template<typename V>
    static shared_ptr<soci::details::holder> value(V val) {
      return shared_ptr<soci::details::holder>(std::move(AttrMap::value_u<V>(val)));
    }

    //virtual const unordered_map<string, attr_config> attribute_names() const;
    virtual const attr_config::map attribute_names() const;

    template<typename V>
    SETTER set(const string & attr_name, V val) ;

    template<typename V>
    V get(const string & attr_name, bool & found) const ;

    template<typename V>
    V get(const string & attr_name, V fallback, bool & found) const;

    virtual void clear(); // all attributes treated as not present

    virtual SETTER erase(const string & attr_name); // attribute value treated as not present

    virtual SETTER set_null(const string & attr_name, bool is_null);

    virtual bool is_null(const string & attr_name) const; // attribute value treated as null

    virtual bool is_present(const string & attr_name) const;

    static bool copy_value(const string & attr_name, const AttrMap & from, AttrMap & to);

    // Get a string representation of the value being held
    virtual string gets(const string & attr_name, bool & found) const;

    virtual string to_json() const;



    template<typename V>
    bool static addVal(const string & name, V fallback, soci::values & v, const unum::AttrMap & p) {
      bool found = false;
      V val = p.get<V>(name, fallback, found);
      bool is_null = p.is_null(name);
      if(!found && !is_null) {
        return false; // value not present
      };
      v.set<V>(name, val, (is_null ? soci::i_null : soci::i_ok));
      return true;
    }
    template<typename V>
    bool static extractVal(const string & name, const soci::values & v, unum::AttrMap & p) {
      V val {};
      try {
        if(v.get_indicator(name) == soci::i_null) {
          // handle setting null value
          p.set_null(name, true);
          return true;
        }
      } catch (const soci::soci_error &e) {
        bool found = false;
        p.get<V>(name, found);
        if(!found) { // was never set
          return false;
        }
        throw e;
      }
      try {
        val = v.get<V>(name);
      } catch (const std::bad_cast &bc) {
        cerr << "[" << __FUNCTION__ << "][" << __FILE__ << " L" << __LINE__ << "] "
             << bc.what() << " Could not get '"
             << name << "' due to bad cast into ATTR_TYPE " ;
          // << (int)p.attribute_names().at(name).type << endl;
        throw bc;
      }
      p.set<V>(name, val);
      return true;
    }



  protected:
    // Map string to tuple <ATTR_TYPE, (bool)nullable, (bool)auto, (string)default>
    const attr_config::map _attribute_names;
    unordered_map<string, unique_ptr<soci::details::holder>> _vals;
    unordered_map<string, bool> _vals_null;
  };

  template<typename C>
  class AttrMapCfg : AttrMap {
  };


  template<typename V>
  AttrMap::SETTER AttrMap::set(const string & attr_name, V val) {
    attr_config::map config = attribute_names();
    // make sure the attribute is present
    if(!config.count(attr_name)) {
      return SETTER::failure;
    }
    bool overridden = (_vals.count(attr_name) > 0)
      || (_vals_null.count(attr_name));
    bool correct_type = false;
    switch(config.at(attr_name)->type) {
    case ATTR_TYPE::int_t:
      correct_type = (AttrTypeParseTraits<V>::id == (int)ATTR_TYPE::int_t);
      break;
    case ATTR_TYPE::long_t:
      correct_type = (AttrTypeParseTraits<V>::id == (int)ATTR_TYPE::long_t);
      break;
    case ATTR_TYPE::double_t:
      correct_type = (AttrTypeParseTraits<V>::id == (int)ATTR_TYPE::double_t);
      break;
    case ATTR_TYPE::string_t:
      correct_type = (AttrTypeParseTraits<V>::id == (int)ATTR_TYPE::string_t);
      break;
    case ATTR_TYPE::datetime_t:
      correct_type = (AttrTypeParseTraits<V>::id == (int)ATTR_TYPE::datetime_t);
      break;
    case ATTR_TYPE::char_t:
      correct_type = (AttrTypeParseTraits<V>::id == (int)ATTR_TYPE::char_t);
      break;
    default:
      correct_type = false;
    }
    if(!correct_type) {
      cerr << "Could not assign '" << attr_name << "', wrong type provided" << endl;
      return SETTER::failure;
    }
    _vals[attr_name] = AttrMap::value_u<V>(val);
    set_null(attr_name, false); // cannot be both null and present
    return overridden ? SETTER::updated : SETTER::inserted;
  }

  template<typename V>
  V AttrMap::get(const string & attr_name, V fallback, bool & found) const {
    V retval = get<V>(attr_name, found);
    return found ? retval : fallback;
  }

  template<typename V>
  V AttrMap::get(const string & attr_name, bool & found) const {
    V retval {};
    if((found = _vals.count(attr_name))) {
      try {
        retval = _vals.at(attr_name)->get<V>();
      } catch (const std::out_of_range &e)  {}
    }
    return retval;
  }

}

namespace soci {
  template<>
  struct type_conversion<unum::AttrMap> {
    typedef values base_type;
    static void from_base_attributes(values const & v,
                                     indicator /* ind */,
                                     unum::AttrMap & p,
                                     unum::attr_config::map attributes) {
      for(auto it : attributes) {
        switch(it.second->type) {
        case unum::ATTR_TYPE::long_t:
          unum::AttrMap::extractVal<long long>(it.first, v, p);
          break;
        case unum::ATTR_TYPE::int_t:
          unum::AttrMap::extractVal<int>(it.first, v, p);
          break;
        case unum::ATTR_TYPE::double_t:
          unum::AttrMap::extractVal<double>(it.first, v, p);
          break;
        case unum::ATTR_TYPE::string_t:
          unum::AttrMap::extractVal<string>(it.first, v, p);
          break;
        case unum::ATTR_TYPE::datetime_t:
          unum::AttrMap::extractVal<std::tm>(it.first, v, p);
          break;
        case unum::ATTR_TYPE::char_t:
          unum::AttrMap::extractVal<char>(it.first, v, p);
          break;
        }
      }
    }

    static void from_base(values const & v, indicator /* ind */, unum::AttrMap & p) {
      p.clear(); // starting clean
      from_base_attributes(v, i_ok, p, p.attribute_names());
    }


    static void to_base_attributes(const unum::AttrMap & p,
                                   values & v,
                                   unum::attr_config::map attributes) {
      for(auto it : attributes) {
        switch(it.second->type) {
        case unum::ATTR_TYPE::int_t:
          unum::AttrMap::addVal<int>(it.first, 0, v, p);
          break;
        case unum::ATTR_TYPE::long_t:
          unum::AttrMap::addVal<long long>(it.first, 0, v, p);
          break;
        case unum::ATTR_TYPE::string_t:
          unum::AttrMap::addVal<string>(it.first, "", v, p);
          break;
        case unum::ATTR_TYPE::datetime_t:
          std::tm fallback;
          unum::AttrMap::addVal<std::tm>(it.first, fallback, v, p);
          break;
        case unum::ATTR_TYPE::char_t:
          unum::AttrMap::addVal<char>(it.first, '\0', v, p);
          break;
        default:
          break;
        };
      }
    }

    static void to_base(const unum::AttrMap & p, values & v, indicator & ind) {
      to_base_attributes(p, v, p.attribute_names());
      ind = i_ok;
    }
  };

}

#endif
