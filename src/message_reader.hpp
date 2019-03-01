#ifndef DNSTOY_MESSAGE_READER_H_
#define DNSTOY_MESSAGE_READER_H_
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/endian/conversion.hpp>
#include <string>
#include <vector>
#include "dns.hpp"
#include "logging.hpp"
#include "query.hpp"

namespace dnstoy {

class MessageReader {
 public:
  enum class Reason {
    NEW_MESSAGE,
    IO_ERROR,
    MANUAL_STOPPED,
  };

  using StreamHandlerTypeExample =
      std::function<void(Reason, const uint8_t*, uint16_t)>;
  using UdpHandlerTypeExample = std::function<void(
      Reason, const uint8_t*, uint16_t, boost::asio::ip::udp::endpoint*)>;

  void resize_buffer(size_t size) { buffer_.resize(size); }

  void reset() {
    status_ = Status::STOP;
    data_offset_ = 0;
    data_size_ = 0;
    tcp_message_size_ = 0;
  }

  template <typename StreamType, typename HandlerType>
  void Start(StreamType& stream, HandlerType&& handler) {
    if (status_ != Status::RUNNING) {
      status_ = Status::RUNNING;
      if constexpr (std::is_same<StreamType,
                                 boost::asio::ip::udp::socket>::value) {
        if (buffer_.size() == 0) {
          assert(false);
          LOG_ERROR("Reading udp to empty buffer");
          return;
        }
        DoReadUdp(stream, std::move(handler));
      } else {
        DoReadStream(stream, std::move(handler));
      }
    }
  }

  void Stop() { status_ = Status::STOP; }

 private:
  using TcpSocket = boost::asio::ip::tcp::socket;
  using UdpSocket = boost::asio::ip::udp::socket;

  enum class Status { STOP, RUNNING } status_ = Status::STOP;
  size_t data_offset_ = 0;
  size_t data_size_ = 0;
  uint16_t tcp_message_size_ = 0;
  boost::asio::ip::udp::endpoint udp_endpoint_;

  std::vector<uint8_t> buffer_;

  template <typename StreamType, typename HandlerType>
  void DoReadStream(StreamType& stream, HandlerType&& handler) {
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

    LOG_TRACE("start async_read " << read_size);

    auto boost_handler = [this, &stream, handler = std::move(handler)](
                             boost::system::error_code error,
                             size_t new_data_size) {
      if (error) {
        if (error == boost::asio::error::eof ||
            error == boost::system::errc::operation_canceled) {
          LOG_TRACE("connection closed");
          // TODO: add a handler reason for this
          status_ = Status::STOP;
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
          auto tcp_message = reinterpret_cast<const dns::RawTcpMessage*>(data);
          tcp_message_size_ =
              sizeof(dns::RawTcpMessage) +
              boost::endian::big_to_native(tcp_message->message_length);
        }
        if (data_size_ < tcp_message_size_) {
          LOG_DEBUG("Message " << data_size_ << "/" << tcp_message_size_);
          break;
        }
        handler(Reason::NEW_MESSAGE, data, tcp_message_size_);
        data_size_ -= tcp_message_size_;
        tcp_message_size_ = 0;
      } while (data_size_ >= tcp_message_size_);
      DoReadStream(stream, std::move(handler));
    };

    boost::asio::async_read(
        stream, boost::asio::buffer(read_buffer, available_size),
        boost::asio::transfer_at_least(read_size), boost_handler);
  }

  template <typename HandlerType>
  void DoReadUdp(boost::asio::ip::udp::socket& socket, HandlerType&& handler) {
    if (status_ == Status::STOP) {
      handler(Reason::MANUAL_STOPPED, nullptr, 0, nullptr);
      status_ = Status::STOP;
      LOG_TRACE("manual stopped");
      return;
    }
    if (!socket.is_open()) {
      handler(Reason::MANUAL_STOPPED, nullptr, 0, nullptr);
      status_ = Status::STOP;
      LOG_TRACE("connection closed");
      return;
    }
    socket.async_receive_from(
        boost::asio::buffer(buffer_), udp_endpoint_,
        [this, &socket, handler = std::move(handler)](
            boost::system::error_code error, size_t data_size) {
          if (error) {
            if (error == boost::asio::error::eof ||
                error == boost::system::errc::operation_canceled) {
              LOG_TRACE("connection closed");
              // TODO: add a handler reason for this
              status_ = Status::STOP;
              return;
            }
            LOG_ERROR(<< error.message());
            handler(Reason::IO_ERROR, nullptr, 0, nullptr);
            status_ = Status::STOP;
            return;
          }
          handler(Reason::NEW_MESSAGE, buffer_.data(), data_size,
                  &udp_endpoint_);
          DoReadUdp(socket, std::move(handler));
        });
  }
};

}  // namespace dnstoy
#endif  // DNSTOY_MESSAGE_READER_H_