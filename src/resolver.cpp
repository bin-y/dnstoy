#include "resolver.hpp"
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

namespace dnstoy {

std::vector<Resolver::ServerConfiguration> Resolver::server_configurations;
thread_local std::vector<Resolver::ServerInstanceStore>
    Resolver::server_instances;

void Resolver::Resolve(QueryContext::weak_pointer query) {
  // TODO: select server & resolver by rule
  auto& server = server_instances[0];
  auto& tls_resolver = server.tls_resolver;
  if (!tls_resolver) {
    tls_resolver =
        std::make_unique<TlsResolver>(server_configurations[0].hostname,
                                      server_configurations[0].tls_endpoints);
  }
  tls_resolver->Resolve(std::move(query));
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
    for (auto i = 0; option != regex_token_end; option++, i++) {
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
            transport++;
          }
        } break;
        case 1: {
          // address1|address2
          regex_token_iterator address(option->first, option->second,
                                       sub_option_regex);
          while (address != regex_token_end) {
            addresses.emplace_back(&*address->first, address->length());
            address++;
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
      // use user specific address
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
    server_configurations.emplace_back(std::move(server));
    entry++;
  }

  return 0;
}

}  // namespace dnstoy
