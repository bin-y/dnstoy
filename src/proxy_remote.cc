#include <boost/asio/ssl.hpp>
#include <boost/system/system_error.hpp>
#include <iostream>
#include "proxy.hh"

namespace dnstoy {
namespace proxy {
namespace ssl = boost::asio::ssl;
namespace errc = boost::system::errc;
using boost::asio::async_read;
using boost::asio::async_write;
using boost::asio::ip::tcp;
using boost::asio::ip::udp;
using boost::system::error_code;
using std::cout;
using std::endl;

Remote::Remote(Remote::Type type) : type_(type) {}

class UdpUser : public Remote {
 public:
  UdpUser(udp::socket& socket, udp::endpoint& endpoint)
      : Remote(Remote::Type::UDP_USER), socket_(socket), endpoint_(endpoint) {}

  void receive(const boost::asio::mutable_buffers_1& buffers,
               HandlerType&& handler) {
    handler(errc::make_error_code(errc::not_a_stream), 0);
  }

  void send(const boost::asio::const_buffers_1& buffers,
            HandlerType&& handler) {
    socket_.async_send_to(buffers, endpoint_, std::move(handler));
  }

 private:
  udp::socket& socket_;
  udp::endpoint endpoint_;
};

template <typename StreamType>
class StreamRemote : public Remote {
 public:
  StreamRemote(Remote::Type type, StreamType&& stream)
      : Remote(type), stream_(std::move(stream)) {}

  void receive(const boost::asio::mutable_buffers_1& buffers,
               HandlerType&& handler) {
    async_read(stream_, buffers, std::move(handler));
  }

  void send(const boost::asio::const_buffers_1& buffers,
            HandlerType&& handler) {
    async_write(stream_, buffers, std::move(handler));
  }

  boost::asio::ip::tcp::socket* GetTcpHandle() {
    if constexpr (std::is_same<StreamType, tcp::socket>::value) {
      return &stream_;
    }
    return nullptr;
  }
  boost::asio::ssl::stream<boost::asio::ip::tcp::socket>* GetTlsHandle() {
    if constexpr (std::is_same<StreamType, ssl::stream<tcp::socket>>::value) {
      return &stream_;
    }
    return nullptr;
  }

 private:
  StreamType stream_;
};

Remote* CreateUdpUser(boost::asio::ip::udp::socket& socket,
                      boost::asio::ip::udp::endpoint& endpoint) {
  return new UdpUser(socket, endpoint);
}

template <>
Remote* CreateStreamRemote<Remote::Type::TCP_USER>(tcp::socket&& socket) {
  return new StreamRemote<tcp::socket>(Remote::Type::TCP_USER,
                                       std::move(socket));
}

template <>
Remote* CreateStreamRemote<Remote::Type::TLS_SERVER>(
    ssl::stream<tcp::socket>&& socket) {
  return new StreamRemote<decltype(socket)>(Remote::Type::TLS_SERVER,
                                            std::move(socket));
}

}  // namespace proxy
}  // namespace dnstoy