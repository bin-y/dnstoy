#ifndef DNSTOY_WITH_TIMER_H_
#define DNSTOY_WITH_TIMER_H_

#include <boost/asio/steady_timer.hpp>
#include <memory>
#include "engine.hpp"

namespace dnstoy {

template <typename ObjectType>
struct WithTimer {
 public:
  using pointer = std::shared_ptr<WithTimer<ObjectType>>;
  using weak_pointer = std::weak_ptr<WithTimer<ObjectType>>;

  template <typename... ArgumentTypes>
  WithTimer(ArgumentTypes&&... arguments)
      : object(std::forward<ArgumentTypes>(arguments)...),
        timer(Engine::get().GetExecutor()) {}

  ObjectType object;
  boost::asio::steady_timer timer;

  template <typename DurationType>
  static void ExpireSharedPtrAfter(pointer& the_pointer,
                                   DurationType duration) {
    the_pointer->timer.expires_after(duration);
    the_pointer->timer.async_wait([the_pointer](boost::system::error_code) {});
  }
};

}  // namespace dnstoy
#endif  // DNSTOY_WITH_TIMER_H_