#include <unistd.h>
#include <iostream>
#include "configuration.hpp"
#include "logging.hpp"
#include "server.hpp"
#include "version.h"

using boost::asio::ip::udp;
using dnstoy::Configuration;
using dnstoy::InitLogging;
using dnstoy::Server;
using std::cout;

int main(int argc, const char **argv) {
  InitLogging();
  LOG_INFO("dnstoy version:" << DNSTOY_VERSION << " pid:" << getpid());
  auto result = Configuration::init(argc, argv);
  if (result < 0) {
    return result;
  }

  Server server;
  server.StartTcp();
  server.StartUdp();
  server.Run();
  LOG_INFO("Exit.");
}