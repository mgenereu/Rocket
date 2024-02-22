use std::io;
use std::net::SocketAddr;

use bytes::Bytes;
use pin_project_lite::pin_project;
use s2n_quic as quic;
use s2n_quic_h3 as quic_h3;
use quic_h3::h3::server as h3;
use s2n_quic::provider::tls::rustls::{rustls, DEFAULT_CIPHERSUITES};
use s2n_quic::provider::tls::rustls::Server as H3TlsServer;

use tokio::sync::Mutex;
use tokio_util::io::StreamReader;

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

pin_project! {
    pub struct QuicStream {
        handle: quic::connection::Handle,
        req: http::Request<()>,
        #[pin]
        rx: StreamReader<QuicRx, Bytes>,
        #[pin]
        tx: QuicTx,
    }
}

pub struct QuicRx(h3::RequestStream<quic_h3::RecvStream, Bytes>);

pub struct QuicTx(h3::RequestStream<quic_h3::SendStream<Bytes>, Bytes>);

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

type H3Conn = quic_h3::h3::server::Connection<quic_h3::Connection, bytes::Bytes>;

impl Listener for QuicListener {
    type Accept = quic::Connection;

    type Connection = QuicStream;

    async fn accept(&self) -> io::Result<Self::Accept> {
        self.listener
            .lock().await
            .accept().await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
    }

    async fn connect(&self, accept: Self::Accept) -> io::Result<Self::Connection> {
        let handle = accept.handle();
        let quic_conn = quic_h3::Connection::new(accept);
        let mut h3 = H3Conn::new(quic_conn).await.map_err(io::Error::other)?;
        let (req, stream) = h3.accept().await
            .map_err(io::Error::other)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "closed"))?;

        let (tx, rx) = stream.split();
        let tx = QuicTx(tx);
        let rx = StreamReader::new(QuicRx(rx));
        Ok(QuicStream { handle, req, rx, tx })
    }

    fn socket_addr(&self) -> io::Result<Endpoint> {
        Ok(self.local_addr.into())
    }
}

impl Connection for QuicStream {
    fn peer_address(&self) -> io::Result<Endpoint> {
        Ok(self.handle.local_addr()?.into())
    }
}

mod async_traits {
    use std::task::{ready, Context, Poll};
    use std::pin::Pin;

    use super::*;

    use futures::Stream;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    impl Stream for QuicRx {
        type Item = io::Result<Bytes>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            use bytes::Buf;

            match ready!(self.0.poll_recv_data(cx)) {
                Ok(Some(mut buf)) => Poll::Ready(Some(Ok(buf.copy_to_bytes(buf.remaining())))),
                Ok(None) => Poll::Ready(None),
                Err(e) => Poll::Ready(Some(Err(io::Error::other(e)))),
            }
        }
    }

    impl AsyncWrite for QuicTx {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let len = buf.len();
            let result = ready!(self.0.poll_send_data(cx, Bytes::copy_from_slice(buf)));
            result.map_err(io::Error::other)?;
            Poll::Ready(Ok(len))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for QuicStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.project().rx.poll_read(cx, buf)
        }
    }

    impl AsyncWrite for QuicStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.project().tx.poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.project().tx.poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.project().tx.poll_shutdown(cx)
        }
    }
}
