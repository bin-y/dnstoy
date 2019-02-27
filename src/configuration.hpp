#ifndef DNSTOY_CONFIGURATION_H_
#define DNSTOY_CONFIGURATION_H_

#include <boost/program_options.hpp>
#include <fstream>
#include <iostream>
#include <string>

namespace dnstoy {

class Configuration {
 private:
  static boost::program_options::variables_map variables_;

 public:
  template <class charT>
  static int init(int argc, const charT* const argv[]) {
    namespace bpo = boost::program_options;
    using std::cerr;
    using std::cout;
    using std::string;

    bpo::options_description commandline_options("Commandline options");
    auto add_commandline_option = commandline_options.add_options();
    add_commandline_option("help", "produce help message");
    add_commandline_option("config",
                           bpo::value<string>()->default_value("./dnstoy.conf"),
                           "specify config file");
    bpo::store(bpo::parse_command_line(argc, argv, commandline_options),
               variables_);
    bpo::notify(variables_);

    if (variables_.count("help")) {
      cout << commandline_options << "\n";
      return 1;
    }

    std::ifstream ifs(variables_["config"].as<string>().c_str());
    if (ifs.fail()) {
      cerr << "Error opening config file: "
           << variables_["config"].as<string>().c_str() << "\n";
      return 1;
    }

    bpo::options_description configurations("Configurations");
    auto add_configuration_option = configurations.add_options();
    add_configuration_option("listen-address",
                             bpo::value<string>()->default_value("0.0.0.0"),
                             "server listen address");
    add_configuration_option("listen-port",
                             bpo::value<uint16_t>()->default_value(53),
                             "server listen port");
    add_configuration_option("udp-paylad-size-limit",
                             bpo::value<uint16_t>()->default_value(65507),
                             "udp payload size limit should between "
                             "4096(rfc5625) ~ 65507(max udp payload size)");
    add_configuration_option("query-timeout",
                             bpo::value<uint32_t>()->default_value(3000),
                             "timeout for every query in milliseconds");
    add_configuration_option("remote-servers",
                             bpo::value<string>()->default_value(
                                 "tls#1.0.0.1#853#cloudflare-dns.com"),
                             "foreign dns server");
    bpo::store(bpo::parse_config_file(ifs, configurations), variables_);
    bpo::notify(variables_);
    return 0;
  }
  static inline const boost::program_options::variable_value& get(
      const std::string& name) {
    return variables_[name];
  }
};

}  // namespace dnstoy

#endif  // DNSTOY_CONFIGURATION_H_