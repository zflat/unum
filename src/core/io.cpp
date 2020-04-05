#include <iostream>

#include "spdlog/spdlog.h"

#include "core/io.hpp"
#include "soci/soci.h"
#include "soci/mysql/soci-mysql.h"

using namespace soci;
using namespace std;

namespace logger = spdlog;

namespace unum {
  IO::IO() {
    std::ostringstream conn;
    conn << "db="        << std::getenv("DB_NAME")
         << " user="     << std::getenv("DB_USER")
         << " password=" << std::getenv("DB_PW")
         << " host="     << std::getenv("DB_HOST")
      ;
    std::cerr << conn.str() << std::endl;
    std::cerr << std::getenv("DB_NAME") << std::endl;
    db_conn.reset(new soci::session(soci::mysql, conn.str()));

    logger::drop_all();
    auto console = logger::stdout_color_mt("console");
    console->info("Welcome to spdlog!");
  }
  IO::~IO() {
    if (db_conn) {
      db_conn->close();
    }
  }

  void IO::fcgx_accept(pthread_mutex_t *accept_mutex, int &rc) {
    pthread_mutex_lock(accept_mutex);
    rc = FCGX_Accept_r(&_request);
    pthread_mutex_unlock(accept_mutex);
  }
  
  // TODO specific method(s) to output header & body (maybe all at once)
  void IO::cout_fcgi(char * payload) {
    FCGX_FPrintF(_request.out, payload);
  }

  soci::session & IO::db() {
    // TODO: may want to check connection and reconnect if not connected

    // see https://www.reddit.com/r/cpp_questions/comments/50soin/return_unique_ptr_as_a_const_reference/d76p5gj/
    return *db_conn;

    // std::ostringstream conn;
    // conn << "db=" << std::getenv("DB_NAME")
    //      << " user=" << std::getenv("DB_USER")
    //      << " password=" << std::getenv("DB_PW")
    //      << " host=" << std::getenv("DB_HOST")
    //   ;
    // cout << conn.str() << endl;
    // soci::session * db = new soci::session(soci::mysql, conn.str());
    // return *db;
  }

}
