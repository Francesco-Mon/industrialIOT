pub mod handlers;
pub mod types;

// Possiamo anche riesportare le struct e le funzioni più importanti
// per renderle più facili da usare.
pub use handlers::{handle_heartbeat, handle_registration};
pub use types::{CommandRequest, CommandResponse, DeviceInfo};