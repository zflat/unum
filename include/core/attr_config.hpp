#ifndef unum_attr_config_h
#define unum_attr_config_h

#include <cstdarg>
#include <string>
#include <memory>
#include <unordered_map>

namespace unum {
  enum class ATTR_TYPE {
    int_t,
    long_t,
    double_t,
    string_t,
    datetime_t,
    char_t,
  };

  enum class ATTR_STATUS {
    not_valid,
    present,
    not_present,
    val_default,
    val_null,
  };

  struct attr_config {
    attr_config() {};
    attr_config(ATTR_TYPE arg_type,
                bool arg_is_nullable,
                bool arg_is_auto,
                std::string arg_default_val,
                int arg_position) :
      type(arg_type),
      is_nullable(arg_is_nullable),
      is_auto(arg_is_auto),
      default_val(arg_default_val),
      position(arg_position) {};

    template<typename C>
    static std::shared_ptr<attr_config> make();

    typedef std::shared_ptr<const attr_config> ptr;
    typedef std::unordered_map<std::string, const ptr> map;

    ATTR_TYPE type;
    bool is_nullable;
    bool is_auto;
    std::string default_val;
    int position; // used when eunumerating attributes in order
  };


  template<typename T, typename U>
  struct AttrNameParseTraits {
    static const int position;
    static const std::string name;
    static const attr_config::ptr config;
    typedef U type;
  };

  // Binds the attr config class to type and defines name property for
  // dynamic lookup
#define REGISTER_ATTR_MAC(X, Y, U)                                         \
  template <> const std::string AttrNameParseTraits<X::Y, U>::name = #Y;   \
  template <> const attr_config::ptr AttrNameParseTraits<X::Y, U>::config = attr_config::make<X::Y>(); \
  template <> const int AttrNameParseTraits<X::Y, U>::position = __LINE__;
#define REGISTER_ATTR(X, Y, U) REGISTER_ATTR_MAC(X,Y,U);REGISTER_ATTR_MAC(X,Y,ATTR_STATUS);

  // Convenience macro to keep the attribute names list less verbose
#define CONFIG_ATTR(N) #N, attr_config::make<N>()

    template<typename C>
    std::shared_ptr<attr_config> attr_config::make() {
      // typename 'C' must provide members for initialization
      C derived;
      return std::make_shared<attr_config>(attr_config(
                                        derived.type,
                                        derived.is_nullable,
                                        derived.is_auto,
                                        derived.default_val,
                                        AttrNameParseTraits<C, ATTR_STATUS>::position
                                      ));
    }


}


#endif
