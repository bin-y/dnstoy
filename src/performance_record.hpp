#ifndef PERFORMANCE_RECORD_H_
#define PERFORMANCE_RECORD_H_

#include <array>
#include <chrono>

namespace dnstoy {

class PerformanceRecord {
 public:
  PerformanceRecord();
  void record_and_decrease_load(std::chrono::milliseconds cost);
  void increase_load();
  size_t load() { return load_; }
  size_t estimated_delay() { return estimated_delay_; }

 private:
  // TODO: add sample_count to configuration
  static constexpr size_t sample_count_ = 16;
  std::array<std::chrono::milliseconds, sample_count_> time_cost_record_{};
  size_t record_front_ = 0;
  size_t sampled_count_ = 0;
  size_t load_ = 0;
  size_t estimated_delay_ = 0;
  std::chrono::milliseconds time_cost_sum_{0};
  std::chrono::milliseconds average_time_cost_{0};

  void estimate_delay();
};

}  // namespace dnstoy
#endif  // PERFORMANCE_RECORD_H_