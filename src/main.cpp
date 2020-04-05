#include <stdlib.h>
#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#include <fcntl.h>
extern char ** environ;
#endif
#include "fastcgi.h"
#include "fcgio.h"
#include "fcgi_config.h"  // HAVE_IOSTREAM_WITHASSIGN_STREAMBUF

#include <curl/curl.h>
#include "json/json.h"

#include <iostream>
#include <thread>
#include <vector>
#include <mutex>

#include <cstring>
#include <cerrno>
#include <ctime>

#include <sys/types.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/socket.h>

// #include "core/router.hpp"
#include "core/io.hpp"

#define THREAD_MAX 50
#define DEFAULT_THREAD_COUNT 1

using namespace std;
using namespace unum;

// Maximum number of bytes allowed to be read from stdin
static const unsigned long STDIN_MAX = 1000000;


static long gstdin(FCGX_Request * request, char ** content) {
    fcgi_streambuf cin_fcgi_streambuf(request->in);
    fcgi_streambuf cerr_fcgi_streambuf(request->err);
    std::istream cin_fcgi(&cin_fcgi_streambuf);
    std::ostream cerr_fcgi(&cerr_fcgi_streambuf);

    char * clenstr = FCGX_GetParam("CONTENT_LENGTH", request->envp);
    unsigned long clen = STDIN_MAX;

    if (clenstr)
    {
        clen = strtol(clenstr, &clenstr, 10);
        if (*clenstr)
        {
            cerr_fcgi << "can't parse \"CONTENT_LENGTH="
                 << FCGX_GetParam("CONTENT_LENGTH", request->envp)
                 << "\"\n";
            clen = STDIN_MAX;
        }

        // *always* put a cap on the amount of data that will be read
        if (clen > STDIN_MAX) clen = STDIN_MAX;

        *content = new char[clen];

        cin_fcgi.read(*content, clen);
        clen = cin_fcgi.gcount();
    }
    else
    {
        // *never* read stdin when CONTENT_LENGTH is missing or unparsable
        *content = 0;
        clen = 0;
    }

    // Chew up any remaining stdin - this shouldn't be necessary
    // but is because mod_fastcgi doesn't handle it correctly.

    // ignore() doesn't set the eof bit in some versions of glibc++
    // so use gcount() instead of eof()...
    do cin.ignore(1024); while (cin.gcount() == 1024);

    return clen;
}

static int count = 0;
static std::mutex init_mutex;
static std::mutex accept_mutex;

static void responder_routine(int tid) {

  int rc;
  long pid = getpid();
  FCGX_Request request;
  char *server_name;
  char *uri;
  char *method;

  shared_ptr<IO> io;
  // TODO pass env to IO for connection
  // io.reset(new IO());

  // controller->process(*io)

  std::cerr << " thread " << tid << std::endl;

  init_mutex.lock();
  FCGX_InitRequest(&request, 0, FCGI_FAIL_ACCEPT_ON_INTR);
  init_mutex.unlock();
  std::cerr << " init" << tid << " \n";

  for(;;) {
    accept_mutex.lock();
    std::cerr << " wait" << tid << " \n";
    rc = FCGX_Accept_r(&request);
    std::cerr << " accept" << tid << " \n";
    if(rc < 0) {
      accept_mutex.unlock();
      std::cerr << " finish" << tid << " \n";
      FCGX_Finish_r(&request);
      break;
    }

    server_name = FCGX_GetParam("SERVER_NAME", request.envp);
    server_name = server_name ? server_name : const_cast<char *>("~server_name~");
    method = FCGX_GetParam("REQUEST_METHOD", request.envp);
    method = method ? method : const_cast<char *>("~method~");
    uri = FCGX_GetParam("REQUEST_URI", request.envp);
    uri = uri ? uri : const_cast<char *>("~uri~");

    fcgi_streambuf cin_fcgi_streambuf(request.in);
    fcgi_streambuf cout_fcgi_streambuf(request.out);
    fcgi_streambuf cerr_fcgi_streambuf(request.err);
    std::istream cin_fcgi(&cin_fcgi_streambuf);
    std::ostream cout_fcgi(&cout_fcgi_streambuf);
    std::ostream cerr_fcgi(&cerr_fcgi_streambuf);

    cerr_fcgi << " request handler " << tid;

    char * content;
    unsigned long clen = gstdin(&request, &content);

    if(1) {
      cout_fcgi << "Content-type: application/json\r\n"
        "\r\n"
        "{"
        "\"title\":\"echo\","
        "\"method\":\"" << method <<  "\","
        "\"uri\":\"" << uri <<  "\","
        "\"pid\":\"" << pid <<  "\","
        "\"request_number\":\"" << ++count  << "\""
        "}";
    } else {
        cout_fcgi << "Content-type: text/html\r\n"
          "\r\n"
          "<TITLE>echo</TITLE>\n"
          "<H1>echo-cpp</H1>\n"
          "<H4>PID: " << pid << "</H4>\n"
          "<H4>Request Number: " << ++count << "</H4>\n";

        cout_fcgi << "<H4>Standard Input - " << clen;
        if (clen == STDIN_MAX) cout_fcgi << " (STDIN_MAX)";
        cout_fcgi << " bytes</H4>\n";
        if (clen) cout_fcgi.write(content, clen);
        cout_fcgi << "\n";
        cout_fcgi << "<h4>Request</h4>\n<ul>\n"
                  << "  <li> "<<  server_name << "</li>\n"
                  << "  <li>"<<  method << "</li>\n"
                  << "  <li>"<<  uri << "</li>\n"
                  << "</ul>";
        cout_fcgi << "\n";
    }
    cout_fcgi << "\n";
    if (content) delete []content;

    FCGX_FFlush(request.out);
    FCGX_Finish_r(&request);
    std::cerr<< " sent " << count << " \n";
    accept_mutex.unlock();
  }

  // cleanup I/O resources
}

int main (int argc, char* argv[]) {
  unsigned long thread_count = DEFAULT_THREAD_COUNT;
  if(argc > 1) {
    char * p;
    thread_count = strtol(argv[1], &p, 10);
    if(*argv[1] == '\0' || *p != '\0') {
      std::cerr << "Thread count must be a number" << std::endl;
      exit(EXIT_FAILURE);
    }
    if(thread_count > THREAD_MAX) {
      thread_count = THREAD_MAX;
    }
    if(thread_count < 1) {
      thread_count = 1;
    }
  }

  long pid = getpid();

  // Backup the stdio streambufs
  streambuf * cin_streambuf  = cin.rdbuf();
  streambuf * cout_streambuf = cout.rdbuf();
  streambuf * cerr_streambuf = cerr.rdbuf();

  FCGX_Init();
  std::vector<std::thread> th;
  for(int i=0; i<thread_count; i++) {
    th.push_back(std::thread(responder_routine, i));
  }

  for(std::thread &t : th) {
    t.join();
  }

  // restore stdio streambufs
  cin.rdbuf(cin_streambuf);
  cout.rdbuf(cout_streambuf);
  cerr.rdbuf(cerr_streambuf);

  CURL *curl;
  curl = curl_easy_init();
  Json::Value root;

  return 0;
}
