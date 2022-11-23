use std::{
  convert::TryFrom,
  fs::File,
  io::{self, BufReader},
  path::{Path, PathBuf},
  sync::Arc,
  time::Duration,
};

use anyhow::{Context, Result};
use rustls::{client::ServerCertVerifier, Certificate, PrivateKey, RootCertStore};
use rustls_pemfile::{certs, pkcs8_private_keys};
use structopt::StructOpt;
use tokio::{
  io::{AsyncRead, AsyncWrite},
  net::{TcpListener, TcpStream},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[derive(StructOpt, Debug)]
#[structopt(
  name = "retls",
  about = "Re-encrypt TLS connection with a different certificate."
)]
struct Opt {
  /// The address to listen on.
  #[structopt(long, env = "RETLS_LISTEN")]
  listen: String,

  /// The address to connect to.
  #[structopt(long, env = "RETLS_BACKEND")]
  backend: String,

  /// The address to connect to.
  #[structopt(long, env = "RETLS_BACKEND_SERVER_NAME")]
  backend_server_name: String,

  /// Connect timeout in milliseconds.
  #[structopt(long, env = "RETLS_TIMEOUT_MS", default_value = "30000")]
  timeout_ms: u64,

  /// Cert file
  #[structopt(long, env = "RETLS_CERT")]
  cert: PathBuf,

  /// Key file
  #[structopt(long, env = "RETLS_KEY")]
  key: PathBuf,
}

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
  certs(&mut BufReader::new(File::open(path)?))
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
    .map(|mut certs| certs.drain(..).map(Certificate).collect())
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
  pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
    .map(|mut keys| keys.drain(..).map(PrivateKey).collect())
}

#[tokio::main]
async fn main() -> Result<()> {
  let opt: &'static Opt = Box::leak(Box::new(Opt::from_args()));
  pretty_env_logger::init();

  let certs = load_certs(&opt.cert)?;
  let mut keys = load_keys(&opt.key)?;

  let config = rustls::ServerConfig::builder()
    .with_safe_defaults()
    .with_no_client_auth()
    .with_single_cert(certs, keys.remove(0))
    .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

  let acceptor = TlsAcceptor::from(Arc::new(config));

  let sock = TcpListener::bind(&opt.listen).await?;
  log::info!("Listening on {}.", sock.local_addr()?);

  loop {
    let (incoming, peer) = sock.accept().await?;
    log::info!("Accepted connection from {}.", peer);
    let acceptor = acceptor.clone();
    tokio::spawn(async move {
      if let Err(e) = handle(acceptor, incoming, opt).await {
        log::error!("Error handling connection from {}: {}", peer, e);
      }
    });
  }
}

async fn handle(acceptor: TlsAcceptor, incoming: TcpStream, opt: &'static Opt) -> Result<()> {
  let mut stream = acceptor.accept(incoming).await?;
  let timeout = Duration::from_millis(opt.timeout_ms);
  tokio::select! {
    res = establish_backend_connection(&opt.backend, &opt.backend_server_name) => {
      let mut backend = res.with_context(|| "backend connect failed")?;
      let _ = tokio::io::copy_bidirectional(&mut stream, &mut backend).await;
    }
    _ = tokio::time::sleep(timeout) => {
      anyhow::bail!("timeout after {:?}", timeout);
    }
  }
  Ok(())
}

async fn establish_backend_connection(
  addr: &str,
  server_name: &str,
) -> Result<Box<dyn GenericStream>> {
  if addr.starts_with("tls:") {
    let addr = addr.strip_prefix("tls:").unwrap();
    // do not verify remote cert
    let mut config = rustls::ClientConfig::builder()
      .with_safe_defaults()
      .with_root_certificates(RootCertStore::empty())
      .with_no_client_auth();
    config
      .dangerous()
      .set_certificate_verifier(Arc::new(DangerouslyAcceptAnyCert));

    let connector = TlsConnector::from(Arc::new(config));

    let stream = TcpStream::connect(addr).await?;
    let server_name = rustls::ServerName::try_from(server_name)
      .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid server name"))?;
    let stream = connector.connect(server_name, stream).await?;
    Ok(Box::new(stream))
  } else {
    let stream = TcpStream::connect(addr).await?;
    Ok(Box::new(stream))
  }
}

trait GenericStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl GenericStream for TcpStream {}
impl GenericStream for tokio_rustls::client::TlsStream<TcpStream> {}

struct DangerouslyAcceptAnyCert;

impl ServerCertVerifier for DangerouslyAcceptAnyCert {
  fn verify_server_cert(
    &self,
    _end_entity: &Certificate,
    _intermediates: &[Certificate],
    _server_name: &rustls::ServerName,
    _scts: &mut dyn Iterator<Item = &[u8]>,
    _ocsp_response: &[u8],
    _now: std::time::SystemTime,
  ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
    Ok(rustls::client::ServerCertVerified::assertion())
  }
}
