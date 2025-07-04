#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LockRequest {
    /// name is the identifier for the distributed shared lock to be acquired.
    #[prost(bytes = "vec", tag = "1")]
    pub name: ::prost::alloc::vec::Vec<u8>,
    /// lease is the ID of the lease that will be attached to ownership of the
    /// lock. If the lease expires or is revoked and currently holds the lock,
    /// the lock is automatically released. Calls to Lock with the same lease will
    /// be treated as a single acquisition; locking twice with the same lease is a
    /// no-op.
    #[prost(int64, tag = "2")]
    pub lease: i64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LockResponse {
    #[prost(message, optional, tag = "1")]
    pub header: ::core::option::Option<super::etcdserverpb::ResponseHeader>,
    /// key is a key that will exist on etcd for the duration that the Lock caller
    /// owns the lock. Users should not modify this key or the lock may exhibit
    /// undefined behavior.
    #[prost(bytes = "vec", tag = "2")]
    pub key: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UnlockRequest {
    /// key is the lock ownership key granted by Lock.
    #[prost(bytes = "vec", tag = "1")]
    pub key: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UnlockResponse {
    #[prost(message, optional, tag = "1")]
    pub header: ::core::option::Option<super::etcdserverpb::ResponseHeader>,
}
/// Generated client implementations.
pub mod lock_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    use tonic::codegen::http::Uri;
    /// The lock service exposes client-side locking facilities as a gRPC interface.
    #[derive(Debug, Clone)]
    pub struct LockClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl<T> LockClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_origin(inner: T, origin: Uri) -> Self {
            let inner = tonic::client::Grpc::with_origin(inner, origin);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> LockClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T::ResponseBody: Default,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
            >>::Error: Into<StdError> + Send + Sync,
        {
            LockClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with the given encoding.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.send_compressed(encoding);
            self
        }
        /// Enable decompressing responses.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.accept_compressed(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_decoding_message_size(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_encoding_message_size(limit);
            self
        }
        /// Lock acquires a distributed shared lock on a given named lock.
        /// On success, it will return a unique key that exists so long as the
        /// lock is held by the caller. This key can be used in conjunction with
        /// transactions to safely ensure updates to etcd only occur while holding
        /// lock ownership. The lock is held until Unlock is called on the key or the
        /// lease associate with the owner expires.
        pub async fn lock(
            &mut self,
            request: impl tonic::IntoRequest<super::LockRequest>,
        ) -> std::result::Result<tonic::Response<super::LockResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/v3lockpb.Lock/Lock");
            let mut req = request.into_request();
            req.extensions_mut().insert(GrpcMethod::new("v3lockpb.Lock", "Lock"));
            self.inner.unary(req, path, codec).await
        }
        /// Unlock takes a key returned by Lock and releases the hold on lock. The
        /// next Lock caller waiting for the lock will then be woken up and given
        /// ownership of the lock.
        pub async fn unlock(
            &mut self,
            request: impl tonic::IntoRequest<super::UnlockRequest>,
        ) -> std::result::Result<tonic::Response<super::UnlockResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/v3lockpb.Lock/Unlock");
            let mut req = request.into_request();
            req.extensions_mut().insert(GrpcMethod::new("v3lockpb.Lock", "Unlock"));
            self.inner.unary(req, path, codec).await
        }
    }
}
