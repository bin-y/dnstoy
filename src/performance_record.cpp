#include "performance_record.hpp"

namespace dnstoy {

PerformanceRecord::PerformanceRecord()
    : time_cost_record_(sample_count_, std::chrono::milliseconds(0)),
      time_cost_sum_(0),
      average_time_cost_(0) {}

void PerformanceRecord::record_and_decrease_load(
    std::chrono::milliseconds cost) {
  static_assert(sample_count_ > 0, "");
  time_cost_sum_ -= time_cost_record_[record_front_];
  time_cost_sum_ += cost;
  time_cost_record_[record_front_] = cost;

  record_front_++;
  record_front_ %= sample_count_;
  if (sampled_count_ < sample_count_) {
    sampled_count_++;
  }
  average_time_cost_ = time_cost_sum_ / sampled_count_;
  load_--;
  estimate_delay();
}

void PerformanceRecord::increase_load() {
  load_++;
  estimate_delay();
}

inline void PerformanceRecord::estimate_delay() {
  // TODO: dynamically determin '2' by record
  if (load_ > 4) {
    estimated_delay_ = average_time_cost_.count() * (load_ + 1) / 4;
  } else {
    estimated_delay_ = average_time_cost_.count();
  }
}

}  // namespace dnstoy