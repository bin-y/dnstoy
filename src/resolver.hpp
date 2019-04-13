#ifndef DNSTOY_RESOLVER_H_
#define DNSTOY_RESOLVER_H_

#include <set>
#include <string>
#include <unordered_map>
#include <vector>
#include "performance_record.hpp"
#include "query.hpp"
#include "tls_resolver.hpp"

namespace dnstoy {

class TlsResolver;

class Resolver {
 public:
  static int init();
  static void Resolve(QueryContext::pointer&& query,
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
    PerformanceRecord performance_record;
  };

  struct ComparePerformanceRank {
    bool operator()(size_t a, size_t b) const {
      if (server_instances_[a].performance_record.estimated_delay() !=
          server_instances_[b].performance_record.estimated_delay()) {
        return server_instances_[a].performance_record.estimated_delay() <
               server_instances_[b].performance_record.estimated_delay();
      }
      return a < b;
    }
  };

  static std::vector<ServerConfiguration> server_configurations_;
  static thread_local std::vector<ServerInstanceStore> server_instances_;
  static thread_local std::set<size_t, ComparePerformanceRank>
      server_speed_ranking_;
  static thread_local size_t round_robin_for_idle;

  static void ResolveQueryWithServer(size_t server_index,
                                     QueryContext::pointer& query,
                                     QueryResultHandler& handler);
};

}  // namespace dnstoy
#endif  // DNSTOY_RESOLVER_H_