//! The suite's TLS front: a TLS end before a spawned daemon.
//!
//! The daemon serves plain HTTP, and on a hosted board TLS is its proxy's.
//! [`TlsFront`] stands where that proxy does: it accepts TLS on a loopback
//! port, finishes the handshake under the fixture certificate
//! (`tests/fixtures/`, whose README says how the pair was made), and then
//! carries the connection's plain bytes to the daemon's port and the
//! daemon's back, until the daemon closes its answer. It reads no byte it
//! carries: no request is parsed and none is answered here.
//!
//! The daemon is dialed only once a handshake has finished, so a client the
//! handshake turns away — one that does not trust the certificate — puts no
//! connection and no byte before the daemon. [`TlsFront::carried`] and
//! [`TlsFront::refused`] count the two outcomes, for the cells that pin
//! which one a dial met.
//!
//! It runs on threads, one accepting and two per connection carried, over
//! `rustls`'s server side; no runtime is added.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection};

/// The fixture certificate, the one the front serves.
const CERTIFICATE_PEM: &[u8] = include_bytes!("../../fixtures/tls-front-test-cert.pem");

/// The fixture certificate's key, a test key that signs nothing else.
const TEST_KEY_PEM: &[u8] = include_bytes!("../../fixtures/tls-front-test-key.pem");

/// The bound on each read and write the front makes of either side.
///
/// A connection neither side ends is dropped at it, so no thread outlives a
/// cell by more.
const FRONT_TIMEOUT: Duration = Duration::from_secs(60);

/// Returns the front's certificate in DER.
///
/// It is the one root a cell hands the client's dialer to reach the front
/// (`PlainHttp::trusting_test_root`); no platform trusts it.
pub fn tls_front_test_root() -> Vec<u8> {
    CertificateDer::from_pem_slice(CERTIFICATE_PEM).expect("the fixture certificate reads").as_ref().to_vec()
}

/// A TLS end on a loopback port before one daemon.
///
/// Dropped, it stops accepting; a connection it is carrying ends with its
/// two sides.
pub struct TlsFront {
    port: u16,
    counts: Arc<Counts>,
    stopped: Arc<AtomicBool>,
    accepting: Option<thread::JoinHandle<()>>,
}

/// What became of the connections the front accepted.
#[derive(Default)]
struct Counts {
    accepted: AtomicU64,
    carried: AtomicU64,
    refused: AtomicU64,
}

impl TlsFront {
    /// Stands a front before the daemon at `daemon_port`.
    ///
    /// # Panics
    ///
    /// Panics where no loopback port binds or the fixture pair does not
    /// read as a server's certificate and key.
    pub fn before(daemon_port: u16) -> TlsFront {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port for the TLS front");
        let port = listener.local_addr().expect("the front's address").port();
        let config = server_config();
        let counts = Arc::new(Counts::default());
        let stopped = Arc::new(AtomicBool::new(false));
        let accepting = thread::spawn({
            let (counts, stopped) = (counts.clone(), stopped.clone());
            move || {
                for client in listener.incoming() {
                    if stopped.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(client) = client else { continue };
                    counts.accepted.fetch_add(1, Ordering::SeqCst);
                    let (config, counts) = (config.clone(), counts.clone());
                    thread::spawn(move || carry(&client, config, daemon_port, &counts));
                }
            }
        });
        TlsFront { port, counts, stopped, accepting: Some(accepting) }
    }

    /// Returns the loopback port the front accepts TLS on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Returns the front's origin, `https://127.0.0.1:<port>`.
    pub fn origin(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    /// Returns how many connections the front carried to the daemon.
    ///
    /// Each is one whose handshake finished: the daemon is dialed for no
    /// other, so a count that did not move is a daemon no byte reached.
    pub fn carried(&self) -> u64 {
        self.counts.carried.load(Ordering::SeqCst)
    }

    /// Returns how many connections the front accepted and did not carry.
    ///
    /// Each is one whose handshake did not finish — the client hung up, sent
    /// an alert, or sent no TLS — or, past a handshake, one the daemon took
    /// no connection for.
    pub fn refused(&self) -> u64 {
        self.counts.refused.load(Ordering::SeqCst)
    }

    /// Waits until every connection accepted so far is carried or refused.
    ///
    /// A dial has returned by the time a cell asks, but the front's own
    /// thread may not have counted its connection yet; this waits for the
    /// counts to account for every connection, and through `settle` more for
    /// one the front has yet to accept.
    ///
    /// # Panics
    ///
    /// Panics where a connection is still in its handshake after ten
    /// seconds.
    pub fn settled(&self, settle: Duration) -> &TlsFront {
        let began = Instant::now();
        loop {
            let accepted = self.counts.accepted.load(Ordering::SeqCst);
            if self.carried() + self.refused() == accepted && began.elapsed() >= settle {
                return self;
            }
            assert!(began.elapsed() < Duration::from_secs(10), "a connection of {accepted} is still in its handshake");
            thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for TlsFront {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        // One last connection wakes the accepting thread to read the flag.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(accepting) = self.accepting.take() {
            let _ = accepting.join();
        }
    }
}

/// Returns the front's TLS configuration: the fixture pair, no client asked
/// for a certificate, the provider the client's dialer names.
fn server_config() -> Arc<ServerConfig> {
    let certificate = CertificateDer::from_pem_slice(CERTIFICATE_PEM).expect("the fixture certificate reads");
    let key = PrivateKeyDer::from_pem_slice(TEST_KEY_PEM).expect("the fixture key reads");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("the provider's protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .expect("the fixture pair is a server's certificate and key");
    Arc::new(config)
}

/// Carries one accepted connection: the handshake, then the bytes.
///
/// The handshake runs to its end before the daemon is dialed. One that does
/// not finish — the client hung up, sent an alert, or sent no TLS — is
/// counted refused and nothing is dialed.
fn carry(client: &TcpStream, config: Arc<ServerConfig>, daemon_port: u16, counts: &Counts) {
    let _ = client.set_read_timeout(Some(FRONT_TIMEOUT));
    let _ = client.set_write_timeout(Some(FRONT_TIMEOUT));
    let mut socket = client;
    let handshake = ServerConnection::new(config).map_err(io::Error::other).and_then(|mut tls| {
        while tls.is_handshaking() {
            tls.complete_io(&mut socket)?;
        }
        Ok(tls)
    });
    let Ok(tls) = handshake else {
        counts.refused.fetch_add(1, Ordering::SeqCst);
        return;
    };
    let daemon = TcpStream::connect(("127.0.0.1", daemon_port)).and_then(|daemon| {
        daemon.set_read_timeout(Some(FRONT_TIMEOUT))?;
        daemon.set_write_timeout(Some(FRONT_TIMEOUT))?;
        Ok(daemon)
    });
    let Ok(daemon) = daemon else {
        counts.refused.fetch_add(1, Ordering::SeqCst);
        return;
    };
    counts.carried.fetch_add(1, Ordering::SeqCst);
    let tls = Mutex::new(tls);
    thread::scope(|scope| {
        scope.spawn(|| carry_answer(&tls, client, &daemon));
        carry_request(&tls, client, &daemon);
    });
}

/// Carries the client's plain bytes to the daemon until the client ends.
///
/// The first pass reads nothing off the socket: the handshake's last read
/// may already hold the request, which is taken before any wait.
fn carry_request(tls: &Mutex<ServerConnection>, client: &TcpStream, daemon: &TcpStream) {
    let (mut client, mut daemon) = (client, daemon);
    let mut sealed = [0u8; 16 * 1024];
    let mut read = 0;
    loop {
        let mut plain = Vec::new();
        let ended = {
            let mut tls = tls.lock().unwrap();
            let ended = open(&mut tls, &sealed[..read], &mut plain);
            flush(&mut tls, client).is_err() || ended
        };
        if daemon.write_all(&plain).is_err() || ended {
            break;
        }
        match client.read(&mut sealed) {
            Ok(0) | Err(_) => break,
            Ok(n) => read = n,
        }
    }
    let _ = daemon.shutdown(Shutdown::Write);
}

/// Carries the daemon's bytes to the client until the daemon closes.
///
/// The daemon ends every answer by closing, and the front says so in TLS —
/// a `close_notify` — so the client reads a whole answer and never a
/// connection cut short.
fn carry_answer(tls: &Mutex<ServerConnection>, client: &TcpStream, daemon: &TcpStream) {
    let mut daemon = daemon;
    let mut plain = [0u8; 16 * 1024];
    loop {
        let read = match daemon.read(&mut plain) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let mut tls = tls.lock().unwrap();
        if tls.writer().write_all(&plain[..read]).is_err() || flush(&mut tls, client).is_err() {
            return;
        }
    }
    let mut tls = tls.lock().unwrap();
    tls.send_close_notify();
    let _ = flush(&mut tls, client);
    let _ = client.shutdown(Shutdown::Write);
}

/// Feeds `sealed` to the connection and takes the plain bytes it opens.
///
/// What is already open is taken before each feed, so the connection's own
/// buffer never fills. Answers whether the client's side has ended: its
/// `close_notify`, or bytes the connection refuses.
fn open(tls: &mut ServerConnection, mut sealed: &[u8], plain: &mut Vec<u8>) -> bool {
    loop {
        match tls.reader().read_to_end(plain) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Ok(_) | Err(_) => return true,
        }
        if sealed.is_empty() {
            return false;
        }
        if tls.read_tls(&mut sealed).is_err() || tls.process_new_packets().is_err() {
            return true;
        }
    }
}

/// Writes every TLS byte the connection holds for the client.
///
/// Both carrying threads write the client's socket through here, under the
/// connection's lock, so no record of one lands inside another's.
fn flush(tls: &mut ServerConnection, client: &TcpStream) -> io::Result<()> {
    let mut client = client;
    while tls.wants_write() {
        tls.write_tls(&mut client)?;
    }
    Ok(())
}
