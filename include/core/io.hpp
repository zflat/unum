/*
 * Access to IO resources like the database or FastCGI output stream.
 */ 

#ifndef unum_io_h
#define unum_io_h

#include <pthread.h>
#include <memory>
#include "fcgiapp.h"

#include "soci/soci.h"
#include "soci/sqlite3/soci-sqlite3.h"
#include "soci/mysql/soci-mysql.h"

using namespace soci;
using namespace std;

namespace unum {
  class IO {
  public:
    IO();
    ~IO();

    soci::session & db();

    void cout_fcgi(char * payload);
    void fcgx_accept(pthread_mutex_t *accept_mutex, int &rc);

  protected:
    unique_ptr<soci::session> db_conn;    
    FCGX_Request _request;
  };
}
#endif
