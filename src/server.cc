#include "server.hh"
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <chrono>
#include <csignal>
#include <iostream>
#include <string>
#include "configuration.hh"
#include "engine.hh"
#include "logging.hh"
#include "proxy.hh"
#include "query.hh"

using boost::asio::signal_set;
using boost::asio::ip::make_address;
using boost::asio::ip::tcp;
using boost::asio::ip::udp;
using boost::system::error_code;
using std::cout;
using std::endl;
using std::function;
using std::string;
using std::chrono::milliseconds;
namespace dnstoy {

Server::Server()
    : io_context_(Engine::get().GetExecutor()),
      udp_socket_(io_context_),
      tcp_socket_(io_context_),
      acceptor_(io_context_),
      signals_(io_context_),
      udp_payload_size_limit_(
          Configuration::get("udp-paylad-size-limit").as<uint16_t>()),
      udp_buffer_(udp_payload_size_limit_),
      stop_(false) {}

void Server::Run() {
  signals_.add(SIGINT);
  signals_.add(SIGTERM);
#if defined(SIGQUIT)
  signals_.add(SIGQUIT);
#endif  // defined(SIGQUIT)
  error_code error;

  auto listen_address =
      make_address(Configuration::get("listen-address").as<string>(), error);
  auto listen_port = Configuration::get("listen-port").as<uint16_t>();

  auto udp_endpoint = udp::endpoint(listen_address, listen_port);
  udp_socket_.open(udp_endpoint.protocol());
  udp_socket_.bind(udp_endpoint);
  StartUdp();
  LOG_INFO("Listening on " << listen_address << ":" << listen_port << " UDP");

  auto tcp_endpoint = tcp::endpoint(listen_address, listen_port);
  acceptor_.open(tcp_endpoint.protocol());
  acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
  acceptor_.bind(tcp_endpoint);
  acceptor_.listen();
  StartTcp();
  LOG_INFO("Listening on " << listen_address << ":" << listen_port << " TCP");

  DoAwaitStop();
  io_context_.run();
}

void Server::StartUdp() {
  udp_socket_.async_receive_from(
      boost::asio::buffer(udp_buffer_), udp_endpoint_,
      [this](error_code error, size_t data_size) mutable {
        if (stop_) {
          return;
        }
        if (!error) {
          auto proxy_context = proxy::Context::create(
              proxy::CreateUdpUser(udp_socket_, udp_endpoint_));

          proxy_context->StartProcessUdpData(udp_buffer_.data(), data_size);
        }
        StartUdp();
      });
}

void Server::StartTcp() {
  acceptor_.async_accept([this](error_code error, tcp::socket socket) {
    if (stop_) {
      return;
    }
    if (!error) {
      auto user = proxy::CreateStreamRemote<proxy::Remote::Type::TCP_USER>(
          std::move(socket));
      auto proxy_context = proxy::Context::create(user);
      proxy_context->StartProcessStream();
    }

    StartTcp();
  });
}

void Server::DoAwaitStop() {
  signals_.async_wait([this](boost::system::error_code /*ec*/, int /*signo*/) {
    // The server is stopped by cancelling all outstanding asynchronous
    // operations. Once all operations have finished the io_context::run()
    // call will exit.
    stop_ = true;
    udp_socket_.close();
    acceptor_.close();
  });
}

}  // namespace dnstoy
