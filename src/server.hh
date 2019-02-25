#ifndef DNSTOY_SERVER_H_
#define DNSTOY_SERVER_H_
#include <boost/asio.hpp>
#include <iostream>
#include <vector>

namespace dnstoy {

class Server {
 public:
  Server();
  void Run();

 private:
  boost::asio::io_context& io_context_;
  boost::asio::ip::udp::socket udp_socket_;
  boost::asio::ip::udp::endpoint udp_endpoint_;
  boost::asio::ip::tcp::socket tcp_socket_;
  boost::asio::ip::tcp::acceptor acceptor_;
  boost::asio::signal_set signals_;
  std::vector<uint8_t> udp_buffer_;

  const uint16_t udp_payload_size_limit_;
  bool stop_;

  void StartUdp();
  void StartTcp();
  void DoAwaitStop();
};

}  // namespace dnstoy
#endif  // DNSTOY_SERVER_H_