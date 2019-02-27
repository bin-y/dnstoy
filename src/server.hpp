#ifndef DNSTOY_SERVER_H_
#define DNSTOY_SERVER_H_
#include <boost/asio.hpp>
#include <iostream>
#include <vector>
#include "proxy_context.hpp"

namespace dnstoy {

class Server {
 public:
  Server();
  void StartUdp();
  void StartTcp();
  void Run();

 private:
  boost::asio::io_context& io_context_;
  boost::asio::ip::tcp::socket tcp_socket_;
  boost::asio::ip::tcp::acceptor acceptor_;
  boost::asio::signal_set signals_;
  boost::asio::ip::address listen_address_;
  std::weak_ptr<proxy::Context> udp_context_;
  uint16_t listen_port_;

  bool stop_;

  void DoAccept();
  void DoAwaitStop();
};

}  // namespace dnstoy
#endif  // DNSTOY_SERVER_H_