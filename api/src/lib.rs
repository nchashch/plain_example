pub use tonic;
pub mod api;
pub mod node {
    tonic::include_proto!("node");
}
