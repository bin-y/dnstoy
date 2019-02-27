#ifndef DNSTOY_ENGINE_H_
#define DNSTOY_ENGINE_H_
#include <boost/asio.hpp>

namespace dnstoy {

// TODO: support seastar

class Engine {
 public:
  static inline Engine& get() {
    static thread_local Engine object;
    return object;
  }

  inline boost::asio::io_context& GetExecutor() {
    return raw_object_;
  }

 private:
  boost::asio::io_context raw_object_;
  Engine();
};

}  // namespace dnstoy
#endif  // DNSTOY_ENGINE_H_