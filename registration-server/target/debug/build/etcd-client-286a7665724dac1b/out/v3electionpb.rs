#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CampaignRequest {
    /// name is the election's identifier for the campaign.
    #[prost(bytes = "vec", tag = "1")]
    pub name: ::prost::alloc::vec::Vec<u8>,
    /// lease is the ID of the lease attached to leadership of the election. If the
    /// lease expires or is revoked before resigning leadership, then the
    /// leadership is transferred to the next campaigner, if any.
    #[prost(int64, tag = "2")]
    pub lease: i64,
    /// value is the initial proclaimed value set when the campaigner wins the
    /// election.
    #[prost(bytes = "vec", tag = "3")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CampaignResponse {
    #[prost(message, optional, tag = "1")]
    pub header: ::core::option::Option<super::etcdserverpb::ResponseHeader>,
    /// leader describes the resources used for holding leadership of the election.
    #[prost(message, optional, tag = "2")]
    pub leader: ::core::option::Option<LeaderKey>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LeaderKey {
    /// name is the election identifier that corresponds to the leadership key.
    #[prost(bytes = "vec", tag = "1")]
    pub name: ::prost::alloc::vec::Vec<u8>,
    /// key is an opaque key representing the ownership of the election. If the key
    /// is deleted, then leadership is lost.
    #[prost(bytes = "vec", tag = "2")]
    pub key: ::prost::alloc::vec::Vec<u8>,
    /// rev is the creation revision of the key. It can be used to test for ownership
    /// of an election during transactions by testing the key's creation revision
    /// matches rev.
    #[prost(int64, tag = "3")]
    pub rev: i64,
    /// lease is the lease ID of the election leader.
    #[prost(int64, tag = "4")]
    pub lease: i64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LeaderRequest {
    /// name is the election identifier for the leadership information.
    #[prost(bytes = "vec", tag = "1")]
    pub name: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LeaderResponse {
    #[prost(message, optional, tag = "1")]
    pub header: ::core::option::Option<super::etcdserverpb::ResponseHeader>,
    /// kv is the key-value pair representing the latest leader update.
    #[prost(message, optional, tag = "2")]
    pub kv: ::core::option::Option<super::mvccpb::KeyValue>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ResignRequest {
    /// leader is the leadership to relinquish by resignation.
    #[prost(message, optional, tag = "1")]
    pub leader: ::core::option::Option<LeaderKey>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ResignResponse {
    #[prost(message, optional, tag = "1")]
    pub header: ::core::option::Option<super::etcdserverpb::ResponseHeader>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProclaimRequest {
    /// leader is the leadership hold on the election.
    #[prost(message, optional, tag = "1")]
    pub leader: ::core::option::Option<LeaderKey>,
    /// value is an update meant to overwrite the leader's current value.
    #[prost(bytes = "vec", tag = "2")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProclaimResponse {
    #[prost(message, optional, tag = "1")]
    pub header: ::core::option::Option<super::etcdserverpb::ResponseHeader>,
}
/// Generated client implementations.
pub mod election_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    use tonic::codegen::http::Uri;
    /// The election service exposes client-side election facilities as a gRPC interface.
    #[derive(Debug, Clone)]
    pub struct ElectionClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl<T> ElectionClient<T>
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
        ) -> ElectionClient<InterceptedService<T, F>>
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
            ElectionClient::new(InterceptedService::new(inner, interceptor))
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
        /// Campaign waits to acquire leadership in an election, returning a LeaderKey
        /// representing the leadership if successful. The LeaderKey can then be used
        /// to issue new values on the election, transactionally guard API requests on
        /// leadership still being held, and resign from the election.
        pub async fn campaign(
            &mut self,
            request: impl tonic::IntoRequest<super::CampaignRequest>,
        ) -> std::result::Result<
            tonic::Response<super::CampaignResponse>,
            tonic::Status,
        > {
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
            let path = http::uri::PathAndQuery::from_static(
                "/v3electionpb.Election/Campaign",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("v3electionpb.Election", "Campaign"));
            self.inner.unary(req, path, codec).await
        }
        /// Proclaim updates the leader's posted value with a new value.
        pub async fn proclaim(
            &mut self,
            request: impl tonic::IntoRequest<super::ProclaimRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ProclaimResponse>,
            tonic::Status,
        > {
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
            let path = http::uri::PathAndQuery::from_static(
                "/v3electionpb.Election/Proclaim",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("v3electionpb.Election", "Proclaim"));
            self.inner.unary(req, path, codec).await
        }
        /// Leader returns the current election proclamation, if any.
        pub async fn leader(
            &mut self,
            request: impl tonic::IntoRequest<super::LeaderRequest>,
        ) -> std::result::Result<tonic::Response<super::LeaderResponse>, tonic::Status> {
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
            let path = http::uri::PathAndQuery::from_static(
                "/v3electionpb.Election/Leader",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("v3electionpb.Election", "Leader"));
            self.inner.unary(req, path, codec).await
        }
        /// Observe streams election proclamations in-order as made by the election's
        /// elected leaders.
        pub async fn observe(
            &mut self,
            request: impl tonic::IntoRequest<super::LeaderRequest>,
        ) -> std::result::Result<
            tonic::Response<tonic::codec::Streaming<super::LeaderResponse>>,
            tonic::Status,
        > {
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
            let path = http::uri::PathAndQuery::from_static(
                "/v3electionpb.Election/Observe",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("v3electionpb.Election", "Observe"));
            self.inner.server_streaming(req, path, codec).await
        }
        /// Resign releases election leadership so other campaigners may acquire
        /// leadership on the election.
        pub async fn resign(
            &mut self,
            request: impl tonic::IntoRequest<super::ResignRequest>,
        ) -> std::result::Result<tonic::Response<super::ResignResponse>, tonic::Status> {
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
            let path = http::uri::PathAndQuery::from_static(
                "/v3electionpb.Election/Resign",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("v3electionpb.Election", "Resign"));
            self.inner.unary(req, path, codec).await
        }
    }
}
