#ifndef DNSTOY_RESOLVER_H_
#define DNSTOY_RESOLVER_H_

#include <deque>
#include <string>
#include <unordered_map>
#include <vector>
#include "query.hpp"
#include "tls_resolver.hpp"

namespace dnstoy {

class TlsResolver;

class Resolver {
 public:
  static int init();
  static void Resolve(QueryContext::weak_pointer query,
                      QueryResultHandler&& handler);

 private:
  struct ServerConfiguration {
    std::string hostname;
    std::vector<boost::asio::ip::tcp::endpoint> tls_endpoints;
    // std::vector<boost::asio::ip::tcp::endpoint> https_endpoints;
    // std::vector<boost::asio::ip::tcp::endpoint> tcp_endpoints;
    // std::vector<boost::asio::ip::udp::endpoint> udp_endpoints;
  };

  struct ServerInstanceStore {
    std::unique_ptr<TlsResolver> tls_resolver;
  };

  static std::vector<ServerConfiguration> server_configurations_;
  static thread_local std::vector<ServerInstanceStore> server_instances_;
};

}  // namespace dnstoy
#endif  // DNSTOY_RESOLVER_H_