use std::io;
use std::net::SocketAddr;

use bytes::Bytes;
use s2n_quic as quic;
use s2n_quic_h3 as quic_h3;
use quic_h3::h3::server as h3;
use s2n_quic::provider::tls::rustls::{rustls, DEFAULT_CIPHERSUITES};
use s2n_quic::provider::tls::rustls::Server as H3TlsServer;

use tokio::sync::Mutex;

use crate::listener::{Bindable, Listener};
use crate::tls::TlsConfig;

use super::{Connection, Endpoint};

pub struct QuicBindable {
    address: SocketAddr,
    tls: TlsConfig,
}

pub struct QuicListener {
    listener: Mutex<quic::Server>,
    local_addr: SocketAddr,
}

pub struct QuicConnection {
    pub(crate) handle: quic::connection::Handle,
    pub(crate) stream: QuicStream,
}

pub struct QuicStream {
    inner: h3::RequestStream<quic_h3::BidiStream<Bytes>, Bytes>,
}

impl Bindable for QuicBindable {
    type Listener = QuicListener;

    type Error = io::Error;

    async fn bind(self) -> Result<Self::Listener, Self::Error> {
        // FIXME: Remove this as soon as `s2n_quic` is on rustls 0.22.
        let cert_chain = crate::tls::util::load_cert_chain(&mut self.tls.certs_reader().unwrap())
            .unwrap()
            .into_iter()
            .map(|v| v.to_vec())
            .map(rustls::Certificate)
            .collect::<Vec<_>>();

        let key = crate::tls::util::load_key(&mut self.tls.key_reader().unwrap())
            .unwrap()
            .secret_der()
            .to_vec();

        let mut tls = rustls::server::ServerConfig::builder()
            .with_cipher_suites(DEFAULT_CIPHERSUITES)
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("bad TLS config: {}", e)))?
            .with_client_cert_verifier(rustls::server::NoClientAuth::boxed())
            .with_single_cert(cert_chain, rustls::PrivateKey(key))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("bad TLS config: {}", e)))?;

        tls.alpn_protocols = vec![b"h3".to_vec()];
        tls.ignore_client_order = self.tls.prefer_server_cipher_order;
        tls.session_storage = rustls::server::ServerSessionMemoryCache::new(1024);
        tls.ticketer = rustls::Ticketer::new()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("bad TLS ticketer: {}", e)))?;

        let listener = quic::Server::builder()
            .with_tls(H3TlsServer::new(tls))
            .unwrap_or_else(|e| match e { })
            .with_io(self.address)?
            .start()
            .map_err(io::Error::other)?;

        let local_addr = listener.local_addr()?;

        Ok(QuicListener { listener: Mutex::new(listener), local_addr })
    }
}

#[derive(Copy, Clone)]
pub struct Void<T>(pub T);

impl Listener for QuicListener {
    type Accept = quic::Connection;

    type Connection = Void<SocketAddr>;

    async fn accept(&self) -> io::Result<Self::Accept> {
        self.listener
            .lock().await
            .accept().await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "server closed"))
    }

    async fn connect(&self, accept: Self::Accept) -> io::Result<Self::Connection> {
        let addr = accept.handle().local_addr()?;
        Ok(Void(addr))
    }

    fn socket_addr(&self) -> io::Result<Endpoint> {
        Ok(self.local_addr.into())
    }
}

impl<T: Clone + Into<Endpoint> + Send + Sync + Unpin> Connection for Void<T> {
    fn peer_address(&self) -> io::Result<Endpoint> {
        Ok(self.0.clone().into())
    }
}

mod async_traits {
    use std::task::{Context, Poll};
    use std::pin::Pin;

    use super::*;

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    impl<T> AsyncRead for Void<T> {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl<T> AsyncWrite for Void<T> {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(0))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}
