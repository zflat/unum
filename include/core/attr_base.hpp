#ifndef unum_attr_base_h
#define unum_attr_base_h

/*
 * Base attr configuration classes for common attributes
 */
namespace unum {
  namespace attr_base{

    /*
     * General attributes based on type
     */

    struct string : public attr_config {
      const ATTR_TYPE type          = ATTR_TYPE::string_t;
      const bool is_nullable        = true;
      const bool is_auto            = false;
      const std::string default_val = "";
    };

    /*
     * Attributes with specific behavior 
     */

    struct id : public attr_config {
      const ATTR_TYPE type          = ATTR_TYPE::long_t;
      const bool is_nullable        = true;
      const bool is_auto            = true;
      const std::string default_val = "";
    };

    struct fk : public attr_config {
      const ATTR_TYPE type          = ATTR_TYPE::long_t;
      const bool is_nullable        = false;
      const bool is_auto            = false;
      const std::string default_val = "";
    };

    struct updated_at : public attr_config {
      const ATTR_TYPE type          = ATTR_TYPE::datetime_t;
      const bool is_nullable        = false;
      const bool is_auto            = true;
      const std::string default_val = "";
    };

    struct created_at : public attr_config {
      const ATTR_TYPE type          = ATTR_TYPE::datetime_t;
      /*
       * When auto: true AND nullable: true
       *   - on inserts: NULL is used
       *   - on updates: No value (column is ommitted)
       */
      const bool is_nullable        = true;
      const bool is_auto            = true;
      const std::string default_val = "";
    };
  }
}

#endif
