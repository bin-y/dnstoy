#include "tls_resolver.hpp"
#include <boost/endian/conversion.hpp>
#include <chrono>
#include "configuration.hpp"
#include "engine.hpp"
#include "logging.hpp"
#include "query.hpp"

namespace ssl = boost::asio::ssl;
namespace endian = boost::endian;
using boost::asio::async_read;
using boost::asio::async_write;
using boost::asio::ip::make_address;
using boost::asio::ip::tcp;
using boost::system::error_code;
using std::chrono::seconds;

namespace dnstoy {

TlsResolver::TlsResolver(const std::string& hostname,
                         const tcp_endpoints_type& endpoints)
    : hostname_(hostname),
      endpoints_(endpoints),
      timeout_timer_(Engine::get().GetExecutor()),
      ssl_context_(ssl::context::tls_client) {
  // TODO: support more tls option from configuration
  // Use system cert
  ssl_context_.set_default_verify_paths();
  // minor tls version set to 1.2
  ssl_context_.set_options(ssl::context::default_workarounds |
                           ssl::context::no_tlsv1 | ssl::context::no_tlsv1_1);
}

void TlsResolver::Resolve(QueryContext::pointer& query,
                          QueryResultHandler& handler) {
  query_manager_.QueueQuery(query, handler);
  if (io_status_ == IOStatus::NOT_INITIALIZED) {
    ResetConnection();
  } else {
    DoWrite();
  }
}

template <typename DurationType>
void TlsResolver::UpdateSocketTimeout(DurationType duration) {
  timeout_timer_.expires_after(duration);
  timeout_timer_.async_wait([this](boost::system::error_code error) {
    if (!error) {
      LOG_DEBUG(<< hostname_ << " socket timed out");
      if (sent_queries_.empty()) {
        CloseConnection();
      } else {
        ResetConnection();
      }
    }
  });
}

void TlsResolver::CloseConnection() {
  LOG_TRACE(<< hostname_);
  message_reader_.Stop();
  if (!socket_ || !socket_->lowest_layer().is_open()) {
    return;
  }
  socket_->lowest_layer().cancel();
  socket_->async_shutdown([socket = std::move(socket_)](error_code error) {
    socket->lowest_layer().close();
  });
  io_status_ = IOStatus::NOT_INITIALIZED;
}

void TlsResolver::ResetConnection() {
  if (io_status_ == IOStatus::INITIALIZING) {
    return;
  }
  CloseConnection();
  io_status_ = IOStatus::INITIALIZING;
  message_reader_.reset();
  socket_ =
      std::make_unique<stream_type>(Engine::get().GetExecutor(), ssl_context_);
  LOG_INFO(<< hostname_);

  {
    auto i = sent_queries_.begin();
    while (i != sent_queries_.end()) {
      auto& record = i->second;
      if (record.first->status == QueryContext::Status::WAITING_FOR_ANSWER) {
        query_manager_.CutInQueryRecord(std::move(record));
      } else {
        DropQuery(record);
      }
      i = sent_queries_.erase(i);
    }
  }

  socket_->set_verify_mode(ssl::verify_peer);

  {
    // Enable automatic hostname checks
    auto param = SSL_get0_param(socket_->native_handle());

    X509_VERIFY_PARAM_set_hostflags(param,
                                    X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    X509_VERIFY_PARAM_set1_host(param, hostname_.data(), hostname_.length());
  }

  socket_->set_verify_callback(
      [this](bool preverified, boost::asio::ssl::verify_context& ctx) {
        // FIXME: this example only simply print the certificate's subject
        // name.
        char subject_name[256];
        X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
        X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
        LOG_INFO(" verifying " << hostname_ << " :" << subject_name);
        return preverified;
      });

  UpdateSocketTimeout(seconds(10));

  auto handler = [this](const boost::system::error_code& error,
                        const tcp::endpoint& /*endpoint*/) {
    if (error) {
      LOG_ERROR(<< hostname_ << " connect failed: " << error.message());
      io_status_ = IOStatus::INITIALIZATION_FAILED;
      ResetConnection();
      return;
    }
    Handshake();
  };

  boost::asio::async_connect(socket_->lowest_layer(), endpoints_,
                             std::move(handler));
}

void TlsResolver::Handshake() {
  UpdateSocketTimeout(idle_timeout_);
  socket_->async_handshake(
      boost::asio::ssl::stream_base::client,
      [this](const boost::system::error_code& error) {
        if (error) {
          LOG_ERROR(<< hostname_ << " handshake failed: " << error.message());
          io_status_ = IOStatus::INITIALIZATION_FAILED;
          ResetConnection();
          return;
        }
        io_status_ = IOStatus::READY;
        LOG_TRACE(<< hostname_ << " handshake success");
        UpdateSocketTimeout(idle_timeout_);
        if (query_manager_.QueueSize()) {
          LOG_TRACE("do write");
          DoWrite();
        }
        message_reader_.Start(
            *socket_, std::bind(&TlsResolver::HandleServerMessage, this,
                                std::placeholders::_1, std::placeholders::_2,
                                std::placeholders::_3));
      });
}

void TlsResolver::DoWrite() {
  if (io_status_ == IOStatus::WRITING) {
    LOG_TRACE(<< hostname_ << " already writing");
    return;
  }
  if (io_status_ != IOStatus::READY) {
    LOG_TRACE(<< hostname_ << " IO not ready");
    ResetConnection();
    return;
  }
  UpdateSocketTimeout(idle_timeout_);

  QueryManager::QueryRecord record;
  int16_t id;

  bool got_record = false;
  while (query_manager_.GetRecord(record, id)) {
    if (record.first->status != QueryContext::Status::WAITING_FOR_ANSWER) {
      DropQuery(record);
      continue;
    }
    got_record = true;
    break;
  }
  if (!got_record) {
    LOG_TRACE(<< hostname_ << " queue clear.");
    return;
  }
  io_status_ = IOStatus::WRITING;
  using ResultType = dns::MessageEncoder::ResultType;
  auto& context = *record.first;

  LOG_TRACE(<< hostname_ << " query "
            << (context.query.questions.size() ? context.query.questions[0].name
                                               : "")
            << context.query << "|" << id << " start write");

  auto encode_result = dns::MessageEncoder::RewriteIDToTcpMessage(
      context.raw_message.data(), context.raw_message.size(), id);
  if (encode_result != ResultType::good) {
    LOG_TRACE(<< hostname_ << " query" << context.query.header.id << "|" << id
              << "encode failed");
    DropQuery(record);
    return;
  }
  while (sent_queries_.find(id) != sent_queries_.end()) {
    if (context.status != QueryContext::Status::WAITING_FOR_ANSWER) {
      DropQuery(record);
      return;
    }
    Engine::get().GetExecutor().run_one();
  }
  sent_queries_[id] = record;
  async_write(
      *socket_, boost::asio::buffer(context.raw_message),
      [this, hold_buffer = record.first](const boost::system::error_code& error,
                                         std::size_t bytes_transfered) mutable {
        if (error) {
          if (error == boost::asio::error::operation_aborted) {
            ResetConnection();
            return;
          }
          LOG_ERROR(<< hostname_ << " write failed " << error.message());
          ResetConnection();
          return;
        }
        io_status_ = IOStatus::READY;
        DoWrite();
      });
}

void TlsResolver::HandleServerMessage(MessageReader::Reason reason,
                                      const uint8_t* data, uint16_t data_size) {
  if (reason != MessageReader::Reason::NEW_MESSAGE) {
    LOG_TRACE(<< hostname_ << " ignore reason:" << static_cast<int>(reason));
    return;
  }
  if (!data || !data_size) {
    LOG_ERROR(<< hostname_ << " empty message!");
    return;
  }
  UpdateSocketTimeout(idle_timeout_);
  using ResultType = dns::MessageDecoder::ResultType;
  int16_t id;
  auto decode_result =
      dns::MessageDecoder::ReadIDFromTcpMessage(data, data_size, id);
  if (decode_result != ResultType::good) {
    LOG_ERROR(<< hostname_ << " ?|? answer decode failed");
    return;
  }
  auto query_handle = sent_queries_.extract(id);

#ifndef NDEBUG
  dns::Message message;
  dns::MessageDecoder::DecodeCompleteMesssage(
      message, data + offsetof(dns::RawTcpMessage, message),
      data_size - offsetof(dns::RawTcpMessage, message));
#endif

  if (!query_handle) {
    LOG_ERROR(<< hostname_ << " ?|"
#ifdef NDEBUG
              << id
#else
              << message
#endif
              << " answer find no record");
    return;
  }
  auto& record = query_handle.mapped();
  auto& context = record.first;
  if (context->status != QueryContext::Status::WAITING_FOR_ANSWER) {
    DropQuery(record);
    return;
  }
  context->status = QueryContext::Status::ANSWER_WRITTERN_TO_BUFFER;
  context->raw_message.assign(data, data + data_size);
  dns::MessageEncoder::RewriteIDToTcpMessage(
      context->raw_message.data(), data_size, context->query.header.id);

  LOG_TRACE(<< context->query.header.id << "|" << message << " answered");
  record.second(std::move(record.first), boost::system::errc::make_error_code(
                                             boost::system::errc::success));
}

void TlsResolver::DropQuery(QueryManager::QueryRecord& record) {
  error_code error;
  switch (record.first->status) {
    case QueryContext::Status::EXPIRED:
      LOG_INFO(<< hostname_ << " " << record.first->query.header.id
               << "timed out");
      error = boost::asio::error::timed_out;
      break;
    case QueryContext::Status::ANSWER_WRITTERN_TO_BUFFER:
      // Got error during resolving
    case QueryContext::Status::ANSWER_ACCEPTED:
      // Already resolved by another resolver
      error = boost::system::errc::make_error_code(
          boost::system::errc::operation_canceled);
      break;
    case QueryContext::Status::WAITING_FOR_ANSWER:
      error = boost::system::errc::make_error_code(
          boost::system::errc::bad_message);
    default:
      LOG_ERROR();
      assert(false);
  }
  record.second(std::move(record.first), error);
  return;
}

}  // namespace dnstoy
