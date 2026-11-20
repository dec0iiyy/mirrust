//! `mirrust` binary: serves the fingerprint API over HTTPS.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, bail};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use server::{Config, ConnectionLimit, RequestLog, self_signed_cert, serve, serve_h3, tls_config};
use tokio::net::TcpListener;

const USAGE: &str = "usage: mirrust [--listen ADDR] [--cert PEM --key PEM] [--cors-key KEY]
                  [--log PATH] [--max-connections N]

  --listen           address to listen on, TCP and UDP for HTTP/3 (default 127.0.0.1:8443)
  --cert/--key       PEM certificate chain and private key; without them a self-signed
                     certificate for localhost is generated
  --cors-key         header prefix that turns on CORS headers (default X-CORS, empty: off)
  --log              append one JSON line per request and per failed TLS handshake to
                     this file (default: no log)
  --max-connections  connections open at once, TCP and QUIC together; more are refused
                     (default 1024)";

struct Args {
    listen: SocketAddr,
    cert: Option<(PathBuf, PathBuf)>,
    log: Option<PathBuf>,
    config: Config,
}

fn parse_args() -> anyhow::Result<Args> {
    let mut listen: SocketAddr = "127.0.0.1:8443".parse().expect("valid default address");
    let mut cert = None;
    let mut key = None;
    let mut log = None;
    let mut config = Config::default();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        if flag == "-h" || flag == "--help" {
            println!("{USAGE}");
            std::process::exit(0);
        }
        let value = args
            .next()
            .with_context(|| format!("{flag} needs a value\n{USAGE}"))?;
        match flag.as_str() {
            "--listen" => {
                listen = value
                    .parse()
                    .with_context(|| format!("bad --listen {value}"))?;
            }
            "--cert" => cert = Some(PathBuf::from(value)),
            "--key" => key = Some(PathBuf::from(value)),
            "--cors-key" => config.cors_key = value,
            "--log" => log = Some(PathBuf::from(value)),
            "--max-connections" => {
                let max = value
                    .parse()
                    .ok()
                    .filter(|&max: &usize| max > 0)
                    .with_context(|| format!("bad --max-connections {value}"))?;
                config.connections = ConnectionLimit::new(max);
            }
            _ => bail!("unknown flag {flag}\n{USAGE}"),
        }
    }
    let cert = match (cert, key) {
        (Some(cert), Some(key)) => Some((cert, key)),
        (None, None) => None,
        _ => bail!("--cert and --key go together"),
    };
    Ok(Args {
        listen,
        cert,
        log,
        config,
    })
}

/// Starts listening for the signals that stop the server: Ctrl-C (SIGINT) and SIGTERM, which
/// is what `systemd` and `kill` send. The returned future resolves when one arrives.
///
/// The handlers are in place when this returns, before the future is first polled, so a
/// signal sent as soon as the listening line is printed is not missed.
#[cfg(unix)]
fn shutdown_signal() -> io::Result<impl Future<Output = io::Result<()>>> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    Ok(async move {
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
        Ok(())
    })
}

/// Resolves on Ctrl-C, the only stop signal off Unix.
#[cfg(not(unix))]
fn shutdown_signal() -> io::Result<impl Future<Output = io::Result<()>>> {
    Ok(tokio::signal::ctrl_c())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = parse_args()?;
    let (certs, key) = match &args.cert {
        Some((cert, key)) => (
            CertificateDer::pem_file_iter(cert)
                .and_then(Iterator::collect)
                .with_context(|| format!("reading {}", cert.display()))?,
            PrivateKeyDer::from_pem_file(key)
                .with_context(|| format!("reading {}", key.display()))?,
        ),
        None => self_signed_cert().context("generating a self-signed certificate")?,
    };
    let tls = Arc::new(tls_config(certs, key).context("building the TLS configuration")?);
    let listener = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("listening on {}", args.listen))?;
    let writer = match &args.log {
        Some(path) => {
            let (log, writer) = RequestLog::open(path)
                .await
                .with_context(|| format!("opening the request log {}", path.display()))?;
            args.config.log = Some(log);
            Some(writer)
        }
        None => None,
    };
    let addr = listener.local_addr()?;
    // HTTP/3 on the same address and port, over UDP.
    let udp = UdpSocket::bind(addr).with_context(|| format!("listening on udp {addr}"))?;
    let mut config = args.config;
    config.h3_port = Some(addr.port());
    let config = Arc::new(config);
    let shutdown = shutdown_signal().context("installing the signal handlers")?;
    println!("listening on https://{addr} (TCP and HTTP/3 over UDP)");

    let served = tokio::select! {
        served = async {
            tokio::try_join!(
                serve(listener, Arc::clone(&tls), Arc::clone(&config)),
                serve_h3(udp, tls, config),
            )
            .map(|_| ())
        } => served,
        // Dropping the other branch stops accepting; connections still in progress end when
        // the process exits.
        signal = shutdown => signal,
    };
    if let Some(writer) = writer {
        let dropped = writer.finish().await;
        if dropped > 0 {
            eprintln!("request log: {dropped} entries dropped (queue full)");
        }
    }
    served?;
    Ok(())
}
