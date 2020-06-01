#include "performance_record.hpp"

#include "logging.hpp"

namespace dnstoy {

PerformanceRecord::PerformanceRecord() {}

void PerformanceRecord::record_and_decrease_load(
    std::chrono::milliseconds cost) {
  static_assert(sample_count_ > 0, "");
  LOG_TRACE("last estimation:" << estimated_delay_
                               << " average:" << average_time_cost_.count()
                               << " latest record:" << cost.count());
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
  if (sampled_count_ == sample_count_) {
    int64_t slope_of_best_fit_mul_64;
    {
      // TODO: write a good test
      // slope of best fit
      // = sum((x_i - x_avg) * (y_i - y_avg)) / sum(square(x_i - x_avg))
      constexpr int64_t x_n = sample_count_ - 1;
      constexpr int64_t x_avg = (x_n) / 2;  // x_0 == 0
      int64_t y_avg = average_time_cost_.count();

      int64_t slope_numerator = 0;
      for (size_t i = 0; i < sample_count_; i += 1) {
        auto y_position = (record_front_ + i) % sample_count_;
        slope_numerator +=
            (i - x_avg) * (time_cost_record_[y_position].count() - y_avg);
        // (x_i - x_avg) * (y_i - y_avg)
      }

      // square(x_i - x_avg)
      // = square(x_i - x_n / 2)
      // = square(x_i) - x_i * x_n + square(x_n / 2)
      // = x_i * (x_i - x_n) + square(x_n) >> 2
      // thus
      // sum(square(x_i - x_avg))
      // = n * (square(x_n) >> 2) + sum(x_i * (x_i - x_n))

      int64_t slope_denominator = sample_count_ * ((x_n * x_n) >> 2);
      for (size_t i = 0; i < sample_count_; i += 1) {
        // x_i * (x_i - x_n)
        slope_denominator += i * (i - x_n);
      }

      // multiple 64 to increase calculation accuracy
      slope_of_best_fit_mul_64 = (slope_numerator << 6) / slope_denominator;
    }

    // estimated_delay_ = average_time_cost_ +
    //                    (slope of best fit * 64) * (load_ + 1) / 64
    estimated_delay_ =
        average_time_cost_.count() +
        ((slope_of_best_fit_mul_64 * static_cast<int64_t>(load_ + 1)) >> 6);
    LOG_TRACE("slope x 64:" << slope_of_best_fit_mul_64 << " average:"
                            << average_time_cost_.count() << " load:" << load_
                            << " estimation:" << estimated_delay_);

  } else {
    estimated_delay_ = average_time_cost_.count();
  }
}

}  // namespace dnstoy