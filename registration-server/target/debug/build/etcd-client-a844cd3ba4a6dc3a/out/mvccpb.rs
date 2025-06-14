#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeyValue {
    /// key is the key in bytes. An empty key is not allowed.
    #[prost(bytes = "vec", tag = "1")]
    pub key: ::prost::alloc::vec::Vec<u8>,
    /// create_revision is the revision of last creation on this key.
    #[prost(int64, tag = "2")]
    pub create_revision: i64,
    /// mod_revision is the revision of last modification on this key.
    #[prost(int64, tag = "3")]
    pub mod_revision: i64,
    /// version is the version of the key. A deletion resets
    /// the version to zero and any modification of the key
    /// increases its version.
    #[prost(int64, tag = "4")]
    pub version: i64,
    /// value is the value held by the key, in bytes.
    #[prost(bytes = "vec", tag = "5")]
    pub value: ::prost::alloc::vec::Vec<u8>,
    /// lease is the ID of the lease that attached to key.
    /// When the attached lease expires, the key will be deleted.
    /// If lease is 0, then no lease is attached to the key.
    #[prost(int64, tag = "6")]
    pub lease: i64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Event {
    /// type is the kind of event. If type is a PUT, it indicates
    /// new data has been stored to the key. If type is a DELETE,
    /// it indicates the key was deleted.
    #[prost(enumeration = "event::EventType", tag = "1")]
    pub r#type: i32,
    /// kv holds the KeyValue for the event.
    /// A PUT event contains current kv pair.
    /// A PUT event with kv.Version=1 indicates the creation of a key.
    /// A DELETE/EXPIRE event contains the deleted key with
    /// its modification revision set to the revision of deletion.
    #[prost(message, optional, tag = "2")]
    pub kv: ::core::option::Option<KeyValue>,
    /// prev_kv holds the key-value pair before the event happens.
    #[prost(message, optional, tag = "3")]
    pub prev_kv: ::core::option::Option<KeyValue>,
}
/// Nested message and enum types in `Event`.
pub mod event {
    /// The kind of event.
    #[derive(
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration
    )]
    #[repr(i32)]
    pub enum EventType {
        Put = 0,
        Delete = 1,
    }
    impl EventType {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                EventType::Put => "PUT",
                EventType::Delete => "DELETE",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "PUT" => Some(Self::Put),
                "DELETE" => Some(Self::Delete),
                _ => None,
            }
        }
    }
}
