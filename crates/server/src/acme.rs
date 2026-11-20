//! Built-in ACME: `mirrust --domain NAME` obtains a Let's Encrypt certificate for itself and
//! renews it before it expires.
//!
//! The pieces, from the command line to the wire:
//!
//! - [`domain`] checks the names and derives one from the machine's address for `auto`.
//! - [`CertCache`] keeps the account key and the issued certificate on disk, so a restart
//!   does not ask the CA again.
//! - [`start`] runs the ACME exchange (order, TLS-ALPN-01 validation, finalisation) and
//!   renews in the background.
//! - [`CurrentCert`] is the certificate resolver the TLS configuration uses, so a renewal
//!   takes effect without a restart. HTTP/3 uses the same resolver.
//! - [`AcmeChallenges`] answers the CA's validation connections, which arrive on the same
//!   TCP port as everything else and are told apart by ALPN `acme-tls/1`.

mod cache;
mod cert;
mod challenge;
pub mod domain;
mod order;

pub use cache::{CertCache, CertificateAuthority, StoredCert};
pub use cert::CurrentCert;
pub use challenge::AcmeChallenges;
pub use order::{Settings, start};
