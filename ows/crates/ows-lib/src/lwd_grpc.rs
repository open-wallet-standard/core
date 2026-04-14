use crate::error::OwsLibError;

/// Hand-written prost message types matching the lightwalletd gRPC proto.
/// See: https://github.com/zcash/lightwalletd/blob/master/walletrpc/service.proto

#[derive(Clone, PartialEq, prost::Message)]
pub struct RawTransaction {
    #[prost(bytes = "vec", tag = "1")]
    pub data: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub height: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct SendResponse {
    #[prost(int32, tag = "1")]
    pub error_code: i32,
    #[prost(string, tag = "2")]
    pub error_message: String,
}

/// Send a raw Zcash transaction to a lightwalletd instance via gRPC.
///
/// `endpoint` is the lightwalletd gRPC URL (e.g. `https://zec.rocks:443`).
/// `tx_bytes` is the fully serialized, finalized Zcash transaction.
///
/// Returns the transaction ID (txid) as a hex string on success.
pub fn send_transaction(endpoint: &str, tx_bytes: &[u8]) -> Result<String, OwsLibError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| OwsLibError::BroadcastFailed(format!("failed to create runtime: {e}")))?;

    rt.block_on(async {
        let tls = tonic::transport::ClientTlsConfig::new()
            .with_webpki_roots();
        let channel = tonic::transport::Channel::from_shared(endpoint.to_string())
            .map_err(|e| OwsLibError::BroadcastFailed(format!("invalid endpoint: {e}")))?
            .tls_config(tls)
            .map_err(|e| OwsLibError::BroadcastFailed(format!("TLS config failed: {e}")))?
            .connect()
            .await
            .map_err(|e| OwsLibError::BroadcastFailed(format!("gRPC connect failed: {e}")))?;

        let mut client = tonic::client::Grpc::new(channel);

        client
            .ready()
            .await
            .map_err(|e| OwsLibError::BroadcastFailed(format!("gRPC not ready: {e}")))?;

        let request = RawTransaction {
            data: tx_bytes.to_vec(),
            height: 0,
        };

        let path = tonic::codegen::http::uri::PathAndQuery::from_static(
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/SendTransaction",
        );
        let codec = tonic::codec::ProstCodec::default();

        let response: tonic::Response<SendResponse> = client
            .unary(tonic::Request::new(request), path, codec)
            .await
            .map_err(|e| OwsLibError::BroadcastFailed(format!("gRPC SendTransaction error: {e}")))?;

        let resp = response.into_inner();
        if resp.error_code != 0 {
            return Err(OwsLibError::BroadcastFailed(format!(
                "lightwalletd rejected tx (code {}): {}",
                resp.error_code, resp.error_message
            )));
        }

        // lightwalletd returns the txid in the error_message field on success
        if resp.error_message.is_empty() {
            Err(OwsLibError::BroadcastFailed(
                "broadcast succeeded but lightwalletd did not return a txid".into(),
            ))
        } else {
            Ok(resp.error_message)
        }
    })
}
