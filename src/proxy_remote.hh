#ifndef DNSTOY_PROXY_REMOTE_H_
#define DNSTOY_PROXY_REMOTE_H_

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <memory>
#include <vector>

namespace dnstoy {
namespace proxy {

class Remote {
 public:
  using pointer = Remote*;
  using HandlerType =
      std::function<void(boost::system::error_code, std::size_t)>;
  struct TypeFlag {
    static constexpr uint32_t USER = 1 << 0;
    static constexpr uint32_t UDP = 1 << 2;
    static constexpr uint32_t TCP = 1 << 3;
    static constexpr uint32_t TLS = (1 << 4) | TypeFlag::TCP;
    // TODO: HTTP
  };

  enum class Type : uint32_t {
    UDP_USER = TypeFlag::UDP | TypeFlag::USER,
    TCP_USER = TypeFlag::TCP | TypeFlag::USER,
    UDP_SERVER = TypeFlag::UDP,
    TCP_SERVER = TypeFlag::TCP,
    TLS_SERVER = TypeFlag::TLS,
  };

  virtual void receive(const boost::asio::mutable_buffers_1& buffers,
                       HandlerType&& handler) = 0;

  void send(const boost::asio::mutable_buffers_1& buffers,
            HandlerType&& handler) {
    return send(boost::asio::const_buffers_1(buffers), std::move(handler));
  }

  virtual void send(const boost::asio::const_buffers_1& buffers,
                    HandlerType&& handler) = 0;

  virtual boost::asio::ip::tcp::socket* GetTcpHandle() { return nullptr; }

  virtual boost::asio::ssl::stream<boost::asio::ip::tcp::socket>*
  GetTlsHandle() {
    return nullptr;
  }
  Type type() { return type_; };
  virtual ~Remote(){};
  Remote(Type type);

 private:
  Type type_;
};

Remote* CreateUdpUser(boost::asio::ip::udp::socket& socket,
                      boost::asio::ip::udp::endpoint& endpoint);

template <Remote::Type UserType, typename StreamType>
Remote* CreateStreamRemote(StreamType&& socket);

}  // namespace proxy
}  // namespace dnstoy
#endif  // DNSTOY_PROXY_REMOTE_H_