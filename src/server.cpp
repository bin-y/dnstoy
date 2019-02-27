#include "server.hpp"
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <chrono>
#include <csignal>
#include <iostream>
#include <string>
#include "configuration.hpp"
#include "engine.hpp"
#include "logging.hpp"
#include "proxy.hpp"
#include "query.hpp"

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
      tcp_socket_(io_context_),
      acceptor_(io_context_),
      signals_(io_context_),
      listen_address_(
          make_address(Configuration::get("listen-address").as<string>())),
      listen_port_(Configuration::get("listen-port").as<uint16_t>()),
      stop_(false) {}

void Server::Run() {
  signals_.add(SIGINT);
  signals_.add(SIGTERM);
#if defined(SIGQUIT)
  signals_.add(SIGQUIT);
#endif  // defined(SIGQUIT)

  DoAwaitStop();
  io_context_.run();
}

void Server::StartUdp() {
  auto udp_endpoint = udp::endpoint(listen_address_, listen_port_);
  udp::socket socket(io_context_);
  socket.open(udp_endpoint.protocol());
  socket.bind(udp_endpoint);
  LOG_INFO("Listening on " << listen_address_ << ":" << listen_port_ << " UDP");
  auto udp_context = proxy::Context::create();
  udp_context->Start(std::move(socket));
  udp_context_ = udp_context;
}

void Server::StartTcp() {
  auto tcp_endpoint = tcp::endpoint(listen_address_, listen_port_);
  acceptor_.open(tcp_endpoint.protocol());
  acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
  acceptor_.bind(tcp_endpoint);
  acceptor_.listen();
  DoAccept();
  LOG_INFO("Listening on " << listen_address_ << ":" << listen_port_ << " TCP");
}

void Server::DoAccept() {
  acceptor_.async_accept([this](error_code error, tcp::socket socket) {
    if (stop_) {
      return;
    }
    if (!error) {
      auto proxy_context = proxy::Context::create();
      proxy_context->Start(std::move(socket));
    }

    DoAccept();
  });
}

void Server::DoAwaitStop() {
  signals_.async_wait([this](boost::system::error_code /*ec*/, int /*signo*/) {
    // The server is stopped by cancelling all outstanding asynchronous
    // operations. Once all operations have finished the io_context::run()
    // call will exit.
    stop_ = true;
    auto udp_context = udp_context_.lock();
    if (udp_context) {
      udp_context->Stop();
    }
    acceptor_.close();
  });
}

}  // namespace dnstoy
