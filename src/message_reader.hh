#ifndef DNSTOY_MESSAGE_READER_H_
#define DNSTOY_MESSAGE_READER_H_
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/endian/conversion.hpp>
#include <string>
#include <vector>
#include "dns.hh"
#include "logging.hh"
#include "query.hh"

namespace dnstoy {

class MessageReader {
 public:
  enum class Reason {
    NEW_MESSAGE,
    IO_ERROR,
    MANUAL_STOPPED,
  };
  using HandlerTypeExample =
      std::function<void(Reason, const uint8_t*, uint16_t)>;

  void reset() {
    status_ = Status::STOP;
    data_offset_ = 0;
    data_size_ = 0;
    tcp_message_size_ = 0;
  }

  template <typename StreamType, typename HandlerType>
  void StartRead(StreamType& stream, HandlerType&& handler) {
    if (status_ != Status::RUNNING) {
      status_ = Status::RUNNING;
      DoRead(stream, std::move(handler));
    }
  }

  void Stop() { status_ = Status::STOP; }

 private:
  enum class Status { STOP, RUNNING } status_ = Status::STOP;
  size_t data_offset_ = 0;
  size_t data_size_ = 0;
  uint16_t tcp_message_size_ = 0;

  std::vector<uint8_t> buffer_;

  template <typename StreamType, typename HandlerType>
  void DoRead(StreamType& stream, HandlerType&& handler) {
    if (status_ == Status::STOP) {
      handler(Reason::MANUAL_STOPPED, nullptr, 0);
      status_ = Status::STOP;
      LOG_TRACE("manual stopped");
      return;
    }
    if (!stream.lowest_layer().is_open()) {
      handler(Reason::MANUAL_STOPPED, nullptr, 0);
      status_ = Status::STOP;
      LOG_TRACE("connection closed");
      return;
    }
    auto available_size = buffer_.size() - data_offset_ - data_size_;
    auto read_size = tcp_message_size_ - data_size_;
    if (!read_size) {
      read_size = sizeof(dns::RawTcpMessage::message_length);
    }
    if (available_size < read_size) {
      if (data_offset_ + available_size > read_size) {
        memmove(buffer_.data(), buffer_.data() + data_offset_, data_size_);
        available_size += data_offset_;
        data_offset_ = 0;
      } else {
        buffer_.resize(buffer_.size() + (read_size - available_size));
        available_size = read_size;
      }
    }
    auto read_buffer = buffer_.data() + data_offset_ + data_size_;

    std::function<void(boost::system::error_code, size_t)> boost_handler =
        [this, &stream, handler = std::move(handler)](
            boost::system::error_code error, size_t new_data_size) mutable {
          if (error) {
            if (error == boost::asio::error::eof ||
                error == boost::system::errc::operation_canceled) {
              LOG_TRACE("connection closed");
              // TODO: add a handler reason for this
              return;
            }
            LOG_ERROR(<< error.message());
            handler(Reason::IO_ERROR, nullptr, 0);
            status_ = Status::STOP;
            return;
          }
          LOG_TRACE("Income data " << new_data_size);
          data_size_ += new_data_size;
          do {
            auto data = buffer_.data() + data_offset_;
            if (tcp_message_size_ == 0) {
              if (data_size_ < sizeof(dns::RawTcpMessage)) {
                break;
              }
              auto tcp_message =
                  reinterpret_cast<const dns::RawTcpMessage*>(data);
              tcp_message_size_ =
                  sizeof(dns::RawTcpMessage) +
                  boost::endian::big_to_native(tcp_message->message_length);
            }
            if (data_size_ < tcp_message_size_) {
              LOG_DEBUG("Message " << new_data_size << "/"
                                   << tcp_message_size_);
              break;
            }
            handler(Reason::NEW_MESSAGE, data, tcp_message_size_);
            data_size_ -= tcp_message_size_;
            tcp_message_size_ = 0;
          } while (data_size_ >= tcp_message_size_);
          DoRead(stream, std::move(handler));
        };
    LOG_TRACE("start async_read " << read_size);
    boost::asio::async_read(
        stream, boost::asio::buffer(read_buffer, available_size),
        boost::asio::transfer_at_least(read_size), boost_handler);
  }
};

}  // namespace dnstoy
#endif  // DNSTOY_MESSAGE_READER_H_