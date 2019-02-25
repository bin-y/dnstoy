#include "tls_resolver.hh"
#include <boost/endian/conversion.hpp>
#include <chrono>
#include <string>
#include "configuration.hh"
#include "engine.hh"
#include "logging.hh"
#include "query.hh"
#include "with_timer.hh"

namespace ssl = boost::asio::ssl;
namespace endian = boost::endian;
using boost::asio::async_read;
using boost::asio::async_write;
using boost::asio::ip::tcp;
using boost::system::error_code;
using std::cout;
using std::endl;
using std::make_shared;
using std::string;
using std::chrono::milliseconds;

namespace dnstoy {

TlsResolver::TlsResolver(const string& hostname)
    : hostname_(hostname), timeout_timer_(Engine::get().GetExecutor()) {
  tcp::resolver resolver(Engine::get().GetExecutor());
  endpoints_ = resolver.resolve(hostname, "853");
}

void TlsResolver::Resolve(QueryContextWeakPointer&& query,
                          QueryResultHandler&& handler) {
  query_manager_.QueueQuery(std::move(query), std::move(handler));
  if (consuming_query_record_) {
    return;
  }
  consuming_query_record_ = true;
  if (!socket_) {
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
      LOG_DEBUG("socket timed out");
      CloseConnection();
    }
  });
}

void TlsResolver::CloseConnection() {
  LOG_TRACE();
  message_reader_.Stop();
  if (!socket_ || !socket_->lowest_layer().is_open()) {
    return;
  }
  socket_->lowest_layer().cancel();
  socket_->async_shutdown([socket = std::move(socket_)](error_code error) {
    socket->lowest_layer().close();
  });
}

void TlsResolver::ResetConnection() {
  CloseConnection();
  socket_ = std::make_unique<stream_type>(Engine::get().GetExecutor(),
                                          GetSSLContextForHost(hostname_));
  LOG_INFO("connect to " << hostname_);
  sent_queries_.clear();

  socket_->set_verify_mode(ssl::verify_peer);

  socket_->set_verify_callback(
      [this](bool preverified, boost::asio::ssl::verify_context& ctx) {
        // FIXME: this example only simply print the certificate's subject
        // name.
        char subject_name[256];
        X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
        X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
        LOG_INFO("Verifying " << hostname_ << " :" << subject_name);
        return preverified;
      });

  UpdateSocketTimeout(std::chrono::seconds(10));

  boost::asio::async_connect(
      socket_->lowest_layer(), endpoints_,
      [this](const boost::system::error_code& error,
             const tcp::endpoint& /*endpoint*/) {
        if (!error) {
          Handshake();
        } else {
          LOG_ERROR("Connect failed: " << error.message());
          ResetConnection();
        }
      });
}

void TlsResolver::Handshake() {
  if (!socket_) {
    LOG_INFO("Connection timeout");
    ResetConnection();
    return;
  }
  UpdateSocketTimeout(idle_timeout_);
  socket_->async_handshake(
      boost::asio::ssl::stream_base::client,
      [this](const boost::system::error_code& error) {
        if (error) {
          LOG_ERROR("Handshake failed: " << error.message());
          ResetConnection();
          return;
        }
        LOG_TRACE("Handshake success, do write");
        DoWrite();
        message_reader_.StartRead(
            *socket_, std::bind(&TlsResolver::HandleServerMessage, this,
                                std::placeholders::_1, std::placeholders::_2,
                                std::placeholders::_3));
      });
}

void TlsResolver::DoWrite() {
  if (!socket_) {
    LOG_INFO("Connection timeout");
    ResetConnection();
    return;
  }
  UpdateSocketTimeout(idle_timeout_);

  QueryManager::QueryRecord record;
  int16_t id;
  consuming_query_record_ = query_manager_.GetRecord(record, id);
  if (!consuming_query_record_) {
    LOG_TRACE("Queue clear.");
    return;
  }
  using ResultType = dns::MessageEncoder::ResultType;
  auto context_pointer = record.first.lock();
  // GetRecord ensure context is not expired
  auto& context = context_pointer->object;

  LOG_TRACE("Query" << context.query.header.id << "|" << id << "start write");
  auto encode_result = dns::MessageEncoder::RewriteIDToTcpMessage(
      context.raw_message.data(), context.raw_message.size(), id);
  if (encode_result != ResultType::good) {
    LOG_TRACE("Query" << context.query.header.id << "|" << id
                      << "encode failed");
    return;
  }
  sent_queries_[id] = std::move(record);
  async_write(
      *socket_, boost::asio::buffer(context.raw_message),
      [this, context_pointer, id](const boost::system::error_code& error,
                                  std::size_t bytes_transfered) mutable {
        if (error) {
          LOG_ERROR("Write failed " << error.message());
          auto expired = context_pointer.use_count() == 1;
          if (!expired) {
            context_pointer->object.rcode = dns::RCODE::SERVER_FAILURE;
            sent_queries_[id].second(std::move(context_pointer));
            return;
          }
          ResetConnection();
          return;
        }
        DoWrite();
      });
}

void TlsResolver::HandleServerMessage(MessageReader::Reason reason,
                                      const uint8_t* data, uint16_t data_size) {
  if (reason != MessageReader::Reason::NEW_MESSAGE) {
    LOG_TRACE("ignore reason:" << static_cast<int>(reason));
    return;
  }
  auto header = reinterpret_cast<const dns::RawHeader*>(
      data + offsetof(dns::RawTcpMessage, message));
  using ResultType = dns::MessageDecoder::ResultType;
  int16_t id;
  auto decode_result =
      dns::MessageDecoder::ReadIDFromTcpMessage(data, data_size, id);
  if (decode_result != ResultType::good) {
    LOG_ERROR("?|? answer decode failed");
    return;
  }
  auto query_handle = sent_queries_.extract(id);
  if (!query_handle) {
    LOG_ERROR("?|" << id << " answer find no record");
    return;
  }
  auto& record = query_handle.mapped();
  auto context_pointer = record.first.lock();
  if (!context_pointer) {
    LOG_ERROR("?|" << id << " answer timed out");
    return;
  }
  auto& context = context_pointer->object;
  context.rcode = dns::RCODE::SUCCESS;
  context.raw_message.assign(data, data + data_size);
  dns::MessageEncoder::RewriteIDToTcpMessage(
      context.raw_message.data(), data_size, context.query.header.id);

  LOG_TRACE(<< context.query.header.id << "|" << id << " answered");
  record.second(std::move(context_pointer));
}

boost::asio::ssl::context& TlsResolver::GetSSLContextForHost(
    const std::string& hostname) {
  static thread_local std::unordered_map<string, ssl::context>
      ssl_context_for_hostname_;
  auto emplace_result = ssl_context_for_hostname_.emplace(
      std::make_pair(hostname, ssl::context::tls_client));
  auto& result = emplace_result.first->second;
  if (emplace_result.second) {
    // new context
    // TODO: support more tls option from configuration
    result.set_default_verify_paths();
  }
  return result;
}

}  // namespace dnstoy
