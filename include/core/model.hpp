#ifndef unum_model_h
#define unum_model_h

#include <iostream>
#include <string>
#include <ctime>
#include <vector>
#include <tuple>
#include <unordered_map>

#include "core/io.hpp"
#include "core/attr_map.hpp"

using namespace std;

// curiously recurring template pattern
// https://stackoverflow.com/a/7191334
// https://oopscenities.net/2011/04/30/c-the-curiously-recurring-template-pattern/


// Interesting helpers:
// https://stackoverflow.com/a/31616949

namespace unum {

  template <typename M>
  class Model {
  public:
    Model<M>():
      _data(attr_config::map()), // singleton instance has empty data
      _is_persisted(false)
    {};
    Model(weak_ptr<IO> io) :
      _data(Model<M>::AttributeNames()),
      _is_persisted(false),
      _io(io)
    {};
    // Copy values into _data
    Model(weak_ptr<IO> io, const AttrMap & attrs, bool new_record = false) :
      _data(attrs),
      _is_persisted(!new_record),
      _io(io)
    {};
    virtual ~Model() = default;

    // Returns the table name
    virtual const string table_name() const;
    static const string TableName();

    // Returns the name of the primary key field
    virtual const vector<string> primary_key() const;
    static const vector<string> PrimaryKey();

    // Returns a list of column names and types
    virtual const attr_config::map attribute_names() const;
    static const attr_config::map AttributeNames();

    // Runs all validations. Returns true if no errors are found,
    // false otherwise.
    virtual bool validate() = 0;

    virtual bool save();
    virtual bool del();
    virtual bool reload(bool skip_cache = true, bool just_created = false);

    // use when the attr_name and type are not known until runtime,
    // like dynamic query generation
    template<typename V>
    AttrMap::SETTER set_attr(const string & attr_name, V val) {
      // TODO: should setting an auto field be an error?
      return _data.set<V>(attr_name, val);
    }

    // Can be used to set an attribute to null or not present
    AttrMap::SETTER set_attr(const string & attr_name, ATTR_STATUS status) {
      switch(status) {
      case ATTR_STATUS::val_null:
        return _data.set_null(attr_name, true);
        break;
      case ATTR_STATUS::not_present:
        return _data.erase(attr_name);
        break;
      default:
        break;
      }
      return AttrMap::SETTER::failure;
    }

    template<typename A, typename V>
    AttrMap::SETTER set(V val) {
      return set_attr<V>(AttrNameParseTraits<A,V>::name, val);
    }

    // Can be used to set an attribute to null or not present
    template<typename A>
    AttrMap::SETTER set(ATTR_STATUS status) {
      return set_attr(AttrNameParseTraits<A,ATTR_STATUS>::name, status);
    }


    // use when the attr_name and type are not known until runtime,
    // like dynamic query generation
    template<typename V>
    V get_attr(const string & attr_name, bool & found) const {
      return _data.get<V>(attr_name, found);
    }

    template<typename V>
    V get_attr(const string & attr_name, V fallback, bool & found) const {
      return _data.get<V>(attr_name, fallback, found);
    }

    // The template typename A specifies the attribute name
    template<typename A, typename V>
    V get(bool & found) const {
      return get_attr<V>(AttrNameParseTraits<A,V>::name, found);
    }

    template<typename A, typename V>
    V get(V fallback, bool & found) const {
      return get_attr<V>(AttrNameParseTraits<A,V>::name, fallback, found);
    }

    // check for null or not present
    ATTR_STATUS get(const string & attr_name) const {
      if (_data.is_null(attr_name)) {
        return ATTR_STATUS::val_null;
      }
      return  (_data.is_present(attr_name)
               ? ATTR_STATUS::present
               : ATTR_STATUS::not_present);
    }

    template<typename A>
    ATTR_STATUS get() const {
      string attr_name = AttrNameParseTraits<A,ATTR_STATUS>::name;
      return get(attr_name);
    }

    template<typename A>
    string gets(bool & found) const {
      const string attr_name = AttrNameParseTraits<A,ATTR_STATUS>::name;
      return _data.gets(attr_name, found);
    }

    virtual bool is_persisted() const {
      return _is_persisted;
    }

    // https://stackoverflow.com/questions/20168543/overloading-assignment-operator-with-subscript-operator
    // https://stackoverflow.com/questions/36229320/subscript-assignment-overloading
    // https://stackoverflow.com/questions/3581981/overloading-the-c-indexing-subscript-operator-in-a-manner-that-allows-for-r
    // int operator[](const string & attr_name) {}

  protected:
    bool _create();
    bool _update();

    /**
     * Convert model data to values that conform to their
     * configuration. Indicates null or default value where
     * appropriate. This method is used to handle auto columns and
     * columns with default values.
     *
     * The results of converting data to values are defined as follows
     * (states not listed are not valid):
     *
     * |is nullable|is auto|present default_val|val present|marked null|result|
     * |-----------|-------|-------------------|-----------|-----------|------|
     * | 0 | 0 | 0 | 0 | 0 | Not valid since no default val and not nullable
     * | 0 | 0 | 0 | 0 | 1 | Not valid since not nullable, but marked null
     * | 0 | 0 | 0 | 1 | 0 | val is used
     * | 0 | 0 | 1 | 0 | 0 | default_val is used
     * | 0 | 0 | 1 | 0 | 1 | Not valid since not nullable, but marked null
     * | 0 | 0 | 1 | 1 | 0 | val is used
     * | 0 | 1 | 0 | 0 | 0 | // NULL to always regenerate auto field
     * | 0 | 1 | 0 | 0 | 1 | // Not valid because not nullable implies the value can not be regenerated
     * | 0 | 1 | 0 | 1 | 0 | // NULL to always regenerate auto field // No value is used because this is an auto field
     * | 0 | 1 | 1 | 0 | 0 | // Expression to always regenerate auto field // No value is used because this is an auto field
     * | 0 | 1 | 1 | 0 | 1 | // Not valid because not nullable implies the value can not be regenerated
     * | 0 | 1 | 1 | 1 | 0 | // Expression to always regenerate auto field // No value is used because this is an auto field
     * | 1 | 0 | 0 | 0 | 0 | NULL is used
     * | 1 | 0 | 0 | 0 | 1 | NULL is used
     * | 1 | 0 | 0 | 1 | 0 | val is used
     * | 1 | 0 | 1 | 0 | 0 | default_val is used
     * | 1 | 0 | 1 | 0 | 1 | NULL is used
     * | 1 | 0 | 1 | 1 | 0 | val is used
     * | 1 | 1 | 0 | 0 | 0 | // No value is used because this is an auto field // (except NULL is used when creating new records)
     * | 1 | 1 | 0 | 0 | 1 | // NULL is used because this is an auto field (this allows a new value to be generated)
     * | 1 | 1 | 0 | 1 | 0 | // No value is used because this is an auto field
     * | 1 | 1 | 1 | 0 | 0 | // No value is used because this is an auto field // (except expression is used when creating new records)
     * | 1 | 1 | 1 | 0 | 1 | // Expression is used because this is an auto field (this allows a new value to be generated)
     * | 1 | 1 | 1 | 1 | 0 | // No value is used because this is an auto field
     */
    static AttrMap _getBindValues(const AttrMap & data, unordered_map<string, ATTR_STATUS> & status);

    /**
     * Get a string with named placeholders that can be used in a
     * WHERE condition to constrain the query to primary key values.
     *
     * @param partial When True, returns a string condition even if
     * the attributes are missing. Any missing attributes that are
     * auto initialize/update will be assumed auto-increment fields
     *
     * @return string in the form of "`col0`=:col0 AND ... `colN`=:colN"
     **/
    virtual string pk_condition(bool partial=false) const;

    static const M _single_instance;
    static const vector<string> _primary_key;
    AttrMap _data;
    weak_ptr<IO> _io;
    bool _is_persisted; // see internals activerecord/lib/active_record/core.rb
  };

  /**
   * Multi-row query rowset data template class
   */
  template<typename C>
  class ModelAttrs : public AttrMap {
  public:
    ModelAttrs<C>() : AttrMap(Model<C>::AttributeNames()) {};
    ModelAttrs<C>(attr_config::map attributes) = delete;
  };

  // Implementation
  // See https://stackoverflow.com/a/495056 for linking

  //////////////////
  // Member variables
  template <typename M>
  const M Model<M>::_single_instance;

  template <typename M>
  const vector<string> Model<M>::_primary_key = {"id"};

  ////////////////////////
  // base instance methods (depends on base static data)
  template <typename M>
  const vector<string> Model<M>::primary_key() const {
    return M::_primary_key;
  }

  template <typename M >
  bool Model<M>::save() {
    return _is_persisted ? _update() : _create();
  }

  template <typename M >
  bool Model<M>::del() {
    shared_ptr<IO> io;
    if(! (io =_io.lock()) ) {
      // No db connection
      return false;
    }
    string cond = pk_condition();
    if(!cond.size()) {
      return false;
    }

    soci::session & db = io->db();
    db << "DELETE FROM " << table_name()
       << " WHERE " << cond, use(_data);

    _is_persisted = false;
    _data.clear();

    int n_rows=0;
    db << ("SELECT ROW_COUNT()" + db.get_dummy_from_clause()), into(n_rows);
    return (n_rows > 0);
  }

  template <typename M>
  AttrMap Model<M>::_getBindValues(const AttrMap & data, unordered_map<string, ATTR_STATUS> & status) {
    const attr_config::map attr_configs = data.attribute_names();
    AttrMap retval(attr_configs);

    // Map ATTR_STATUS values to states in the form of
    // nullable|auto|default present?|val present?|null?
    static ATTR_STATUS rules[1<<5] = {
      /* 0b00000 */ ATTR_STATUS::not_valid,
      /* 0b00001 */ ATTR_STATUS::not_valid,
      /* 0b00010 */ ATTR_STATUS::present,
      /* 0b00011 */ ATTR_STATUS::not_valid, // N/A
      /* 0b00100 */ ATTR_STATUS::val_default,
      /* 0b00101 */ ATTR_STATUS::not_valid,
      /* 0b00110 */ ATTR_STATUS::present,
      /* 0b00111 */ ATTR_STATUS::not_valid, // N/A
      /* 0b01000 */ ATTR_STATUS::val_null,
      /* 0b01001 */ ATTR_STATUS::not_valid,
      /* 0b01010 */ ATTR_STATUS::val_null,
      /* 0b01011 */ ATTR_STATUS::not_valid, // N/A
      /* 0b01100 */ ATTR_STATUS::val_default,
      /* 0b01101 */ ATTR_STATUS::not_valid,
      /* 0b01110 */ ATTR_STATUS::val_default,
      /* 0b01111 */ ATTR_STATUS::not_valid, // N/A
      /* 0b10000 */ ATTR_STATUS::val_null,
      /* 0b10001 */ ATTR_STATUS::val_null,
      /* 0b10010 */ ATTR_STATUS::present,
      /* 0b10011 */ ATTR_STATUS::not_valid, // N/A
      /* 0b10100 */ ATTR_STATUS::val_default,
      /* 0b10101 */ ATTR_STATUS::val_null,
      /* 0b10110 */ ATTR_STATUS::present,
      /* 0b10111 */ ATTR_STATUS::not_valid, // N/A
      /* 0b11000 */ ATTR_STATUS::not_present, // NULL when inserting
      /* 0b11001 */ ATTR_STATUS::val_null,
      /* 0b11010 */ ATTR_STATUS::not_present,
      /* 0b11011 */ ATTR_STATUS::not_valid, // N/A
      /* 0b11100 */ ATTR_STATUS::not_present, // expression when inserting
      /* 0b11101 */ ATTR_STATUS::val_default,
      /* 0b11110 */ ATTR_STATUS::not_present,
      /* 0b11111 */ ATTR_STATUS::not_valid, // N/A
    };

    string name;
    attr_config::ptr config;
    for(auto & e: attr_configs) {
      std::tie(name, config) = e;

      // calculate the state
      bool is_nullable        = config->is_nullable;
      bool is_auto            = config->is_auto;
      bool is_present_default = config->default_val.size() > 0;
      bool is_present_val     = data.is_present(name);
      bool is_marked_null     = data.is_null(name);

      int state =
        (is_nullable        ? 1<<4:0) +
        (is_auto            ? 1<<3:0) +
        (is_present_default ? 1<<2:0) +
        (is_present_val     ? 1<<1:0) +
        (is_marked_null     ? 1:0);

      status[name] = rules[state]; // assign to out variable

      switch(rules[state]) {
      case ATTR_STATUS::present:
        // add the current value to data
        AttrMap::copy_value(name, data, retval);
        break;
      case ATTR_STATUS::not_present:
      case ATTR_STATUS::val_default:
        // skip
        break;
      case ATTR_STATUS::val_null:
        // mark null
        retval.set_null(name, true);
        break;
      case ATTR_STATUS::not_valid:
        // skip
      default:
        break;
      }
    }

    return retval;
  }

  template <typename M >
  bool Model<M>::_update() {
    if(!_is_persisted) {
      return false; // precondition
    }
    shared_ptr<IO> io;
    if(! (io =_io.lock()) ) {
      // No db connection
      return false;
    }

    soci::session & db = io->db();

    unordered_map<string, ATTR_STATUS> val_status;
    AttrMap vals = Model<M>::_getBindValues(_data, val_status); // converts data and gets status

    bool first_implode = true;
    std::ostringstream set_list;
    std::ostringstream stmt;
    for(auto & e: attribute_names()) {
      string name = e.first;
      std::ostringstream val_item;

      switch(val_status[name]) {
      case ATTR_STATUS::not_present:
        // skip
        break;
      case ATTR_STATUS::val_default: // TODO skip escaping if this is an auto field to allow SQL expression here?
        val_item << "'" << e.second->default_val << "'";
        break;
      case ATTR_STATUS::present:
      case ATTR_STATUS::val_null:
        val_item << ":" << name;
        break;
      case ATTR_STATUS::not_valid:
      default:
        return false; // error state
      }

      if(val_item.tellp() == 0) {continue;}

      if(!first_implode) {
        set_list << ",";
      } else {first_implode = false;}
      set_list << "`" << name << "`=" << val_item.str();
    }

    string cond = pk_condition();
    if(!cond.size()) {
      return false;
    }
    // make sure primary keys are present as bound values
    for(auto & k: primary_key()) {
      AttrMap::copy_value(k, _data, vals);
    }

    stmt << " UPDATE " << table_name()
         << " SET "   << set_list.str()
         << " WHERE " << cond
      ;
    db << stmt.str(), use(vals);

    int n_rows=0;
    db << ("SELECT ROW_COUNT()" + db.get_dummy_from_clause()), into(n_rows);
    if(n_rows < 1) {
      return false;
    }

    return reload(true);
  }

  template <typename M >
  bool Model<M>::_create() {
    if(_is_persisted) {
      return false; // preconditon
    }
    shared_ptr<IO> io;
    if(! (io =_io.lock()) ) {
      return false;
    }
    soci::session & db = io->db();

    unordered_map<string, ATTR_STATUS> val_status;
    AttrMap vals = Model<M>::_getBindValues(_data, val_status); // converts data and get status

    bool first_implode = true;
    std::ostringstream attr_list;
    std::ostringstream vals_list;
    std::ostringstream stmt;
    for(auto & e: attribute_names()) {
      string name = e.first;
      std::ostringstream val_item;

      switch(val_status[name]) {
      case ATTR_STATUS::not_present:
        if(e.second->is_auto) {
          // initialize auto field
          val_item << (e.second->default_val.size() > 0 ? e.second->default_val : "NULL");
        }
        // otherwise skip value
        break;
      case ATTR_STATUS::val_default:
        val_item << "'" << e.second->default_val << "'";
        break;
      case ATTR_STATUS::val_null:
      case ATTR_STATUS::present:
        val_item << ":" << name;
        break;
      case ATTR_STATUS::not_valid:
      default:
        return false; // error state
      }

      if(val_item.tellp() == 0) {continue;}

      if(first_implode) {
        first_implode = false;
      } else {
        vals_list << ",";
        attr_list << ",";
      }

      attr_list << "`" << name << "`";
      vals_list << val_item.str();
    }

    stmt << "INSERT INTO " << table_name()
         << " (" << attr_list.str() << ") "
         << " VALUES "
         << " (" << vals_list.str() << ")"
      ;
    db << stmt.str(), use(vals);

    int n_rows=0;
    db << ("SELECT ROW_COUNT()" + db.get_dummy_from_clause()), into(n_rows);
    if(n_rows < 1) {
      return false;
    }

    return reload(true, true);
  }

  template <typename M >
  bool Model<M>::reload(bool skip_cache, bool just_created) {
    shared_ptr<IO> io;
    if(! (io =_io.lock()) ) {
      return false;
    }
    soci::session & db = io->db();

    string cond = pk_condition(just_created);
    if(!cond.size()) {
      return false;
    }
    // get primary key(s)
    AttrMap vals(attribute_names());
    for(auto & k: primary_key()) {
      AttrMap::copy_value(k, _data, vals);
    }

    _data.clear();
    db << "SELECT * FROM " << table_name()
       << " WHERE  " << cond, use(vals), into(_data);

    // check if the record was retrieved
    _is_persisted = true;
    for(const std::string & k: primary_key()) {
      if(get(k) != ATTR_STATUS::present) {
        _is_persisted = false;
        break;
      }
    }

    return _is_persisted;
  }

  template <typename M >
  string Model<M>::pk_condition(bool partial) const {
    vector<string> pkComposite = primary_key();
    bool have_pk = false;
    string pk_str;
    bool first_implode = true;
    std::ostringstream cond;
    attr_config::ptr config;
    for(string & pk : pkComposite) {
      pk_str = _data.gets(pk, have_pk);
      if(!first_implode) {
        cond << " AND ";
      } else {first_implode = false;}

      if(have_pk && pk_str.size()) {
        cond << "`" << pk << "`=:" << pk;
        continue;
      }

      if(!partial) {
        return "";
      }

      // determine if this is an auto field
      config = attribute_names().at(pk);
      if(config->is_auto) {
        // Assume using an auto-increment primary key column
        cond << pk << " IN (SELECT LAST_INSERT_ID())";
      }
    }
    return cond.str();
  }


  /////////////////////////////
  // derived instance methods (depends on instance (static) data)
  template <typename M>
  const string Model<M>::table_name() const {
    return M::_table_name;
  }

  template <typename M>
  const attr_config::map Model<M>::attribute_names() const {
    return M::_attribute_names;
  }

  //////////////
  // static methods (these proxy the instance methods)
  template <typename M>
  const string Model<M>::TableName() {
    return Model<M>::_single_instance.table_name();
  }

  template <typename M>
  const vector<string> Model<M>::PrimaryKey() {
    return Model<M>::_single_instance.primary_key();
  }

  template <typename M>
  const attr_config::map Model<M>::AttributeNames() {
    return Model<M>::_single_instance.attribute_names();
  }

}

namespace soci {
  template<typename C>
  struct type_conversion<unum::ModelAttrs<C>> {
    typedef values base_type;
    static void from_base(values const & v, indicator /* ind */, unum::ModelAttrs<C> & p) {
      p.clear(); // starting clean
      soci::type_conversion<unum::AttrMap>::from_base_attributes(v, i_ok, p, p.attribute_names());
      return;
    }
    static void to_base(const unum::ModelAttrs<C> & p, values & v, indicator & ind) {
      // Not implemented
      // soci::type_conversion<unum::AttrMap>::to_base_attributes(p, v, p.attribute_names());
      ind = i_null;
    }
  };
}


#endif
