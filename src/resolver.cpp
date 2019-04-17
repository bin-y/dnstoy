#include "resolver.hpp"
#include <chrono>
#include <regex>
#include <string>
#include "configuration.hpp"
#include "dns.hpp"
#include "engine.hpp"
#include "logging.hpp"

namespace ssl = boost::asio::ssl;
using boost::asio::ip::make_address;
using boost::asio::ip::tcp;
using regex_token_iterator = std::regex_token_iterator<std::string::iterator>;
using std::string;
using std::string_view;
using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::chrono::steady_clock;

namespace dnstoy {

std::vector<Resolver::ServerConfiguration> Resolver::server_configurations_;
thread_local std::vector<Resolver::ServerInstanceStore>
    Resolver::server_instances_;
thread_local std::set<size_t, Resolver::ComparePerformanceRank>
    Resolver::server_speed_ranking_;
thread_local size_t Resolver::round_robin_for_idle = 0;

void Resolver::Resolve(QueryContext::pointer&& query,
                       QueryResultHandler&& handler) {
  // TODO: select server & resolver by rule
  if (server_instances_.empty()) {
    server_instances_.resize(server_configurations_.size());
    for (size_t i = 0; i < server_instances_.size(); i++) {
      server_speed_ranking_.insert(i);
    }
  }

  auto fast_server_index = *server_speed_ranking_.begin();
  ResolveQueryWithServer(fast_server_index, query, handler);
  if (server_instances_.size() < 2) {
    return;
  }
  // round robin for idle gives an oppotunity to low ranking server to prove
  // it's performance when idle, some public server may performances bad when
  // busy but performances good when idle
  round_robin_for_idle++;
  round_robin_for_idle %= server_instances_.size();
  if (round_robin_for_idle == fast_server_index) {
    round_robin_for_idle++;
    round_robin_for_idle %= server_instances_.size();
  }
  auto idle_server_index = round_robin_for_idle;
  if (server_instances_[idle_server_index].performance_record.load() > 3) {
    // not idle
    return;
  }
  ResolveQueryWithServer(idle_server_index, query, handler);
}

void Resolver::ResolveQueryWithServer(size_t server_index,
                                      QueryContext::pointer& query,
                                      QueryResultHandler& handler) {
  query->pending_resolve_attempt++;
  auto& server = server_instances_[server_index];
  {
    // update server load and rank
    auto handle = server_speed_ranking_.extract(server_index);
    server.performance_record.increase_load();
    server_speed_ranking_.insert(std::move(handle));
  }
  auto& tls_resolver = server.tls_resolver;
  if (!tls_resolver) {
    tls_resolver = std::make_unique<TlsResolver>(
        server_configurations_[server_index].hostname,
        server_configurations_[server_index].tls_endpoints);
  }

  QueryResultHandler new_handler = [server_index, handler,
                                    begin_time = steady_clock::now()](
                                       QueryContext::pointer&& context,
                                       boost::system::error_code error) {
    context->pending_resolve_attempt--;
    auto context_status = context->status;
    // TODO: consider server may return a message with failed RCODE
    if (context_status == QueryContext::Status::ANSWER_WRITTERN_TO_BUFFER ||
        (context->pending_resolve_attempt == 0 &&
         context_status != QueryContext::Status::ANSWER_ACCEPTED)) {
      handler(std::move(context), error);
    }
    auto time_cost =
        duration_cast<milliseconds>(steady_clock::now() - begin_time);

    if (error && context_status != QueryContext::Status::EXPIRED) {
      // TODO: figure out a better factor
      time_cost *= 1.5;
    }
    auto handle = server_speed_ranking_.extract(server_index);
    // TODO: take handshake into consideration
    server_instances_[server_index].performance_record.record_and_decrease_load(
        time_cost);
    server_speed_ranking_.insert(std::move(handle));
  };
  tls_resolver->Resolve(query, new_handler);
}

int Resolver::init() {
  auto configuration = Configuration::get("remote-servers").as<string>();
  // example: tls@853|udp@53/8.8.8.8|8.8.4.4/dns.google
  std::regex entries_regex("[^,]+");
  std::regex options_regex("/?([^/]*)");
  std::regex sub_option_regex("[^|]+");

  regex_token_iterator regex_token_end;
  regex_token_iterator entry(configuration.begin(), configuration.end(),
                             entries_regex);
  while (entry != regex_token_end) {
    std::vector<string_view> addresses;
    uint16_t tls_port_number = 0;
    ServerConfiguration server;

    regex_token_iterator option(entry->first, entry->second, options_regex,
                                1);  // 1 is regex sub match index
    for (auto i = 0; option != regex_token_end; ++option, i++) {
      if (option->length() == 0) {
        continue;
      }
      switch (i) {
        case 0: {
          // transport_type1@port|transport_type2@port
          regex_token_iterator transport(option->first, option->second,
                                         sub_option_regex);
          while (transport != regex_token_end) {
            auto transport_str = transport->str();
            if (transport_str == "tls") {
              tls_port_number = 853;
            } else if (transport_str.compare(0, 4, "tls@") == 0) {
              auto port_number = std::stoi(transport_str.substr(4));
              if (port_number <= 0 ||
                  port_number > std::numeric_limits<uint16_t>::max()) {
                LOG_ERROR(<< *entry << " invalid port number " << port_number);
                return -1;
              }
              tls_port_number = port_number;
            } else {
              LOG_ERROR(<< "unknown transport type: " << transport_str
                        << " check " << *entry);
              return -1;
            }
            ++transport;
          }
        } break;
        case 1: {
          // address1|address2
          regex_token_iterator address(option->first, option->second,
                                       sub_option_regex);
          while (address != regex_token_end) {
            addresses.emplace_back(&*address->first, address->length());
            ++address;
          }
        } break;
        case 2: {
          // hostname
          server.hostname = option->str();
        } break;
        default:
          assert(false);
          LOG_ERROR("Error on parsing config: " << *entry);
          return -1;
          break;
      }
    }

    if (addresses.empty()) {
      // address not specified, resolve by hostname
      tcp::resolver resolver(Engine::get().GetExecutor());
      LOG_INFO("Resolving " << server.hostname);
      auto endpoints = resolver.resolve(server.hostname, "");
      if (endpoints.empty()) {
        LOG_ERROR(<< *entry << "no available address found");
        return -1;
      }

      for (auto& endpoint_entry : endpoints) {
        auto endpoint = endpoint_entry.endpoint();
        LOG_INFO(<< server.hostname
                 << " resolve result:" << endpoint.address());
        if (tls_port_number) {
          server.tls_endpoints.emplace_back(std::move(endpoint))
              .port(tls_port_number);
        }
      }

    } else {
      // use user specified address
      if (tls_port_number) {
        for (auto& address : addresses) {
          server.tls_endpoints.emplace_back(
              tcp::endpoint(make_address(address), tls_port_number));
        }
      }
    }

    if (!tls_port_number /* && !xxx_port_number*/) {
      LOG_ERROR(<< *entry << "no available transport found");
      return -1;
    }
    server_configurations_.emplace_back(std::move(server));
    ++entry;
  }

  if (server_configurations_.empty()) {
    LOG_ERROR("no available remote server found");
    return -1;
  }
  return 0;
}

}  // namespace dnstoy
