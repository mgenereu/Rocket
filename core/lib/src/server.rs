use std::io;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use futures::{Future, TryFutureExt, future::{select, Either::*}};

use crate::{Data, Orbit, Request, Rocket};
use crate::request::ConnectionMeta;
use crate::erased::{ErasedRequest, ErasedResponse, ErasedIoHandler};
use crate::listener::{Listener, CancellableExt, BouncedExt};
use crate::data::{IoStream, RawStream};
use crate::util::ReaderStream;
use crate::http::Status;

type Result<T, E = crate::Error> = std::result::Result<T, E>;

impl Rocket<Orbit> {
    async fn service<T: Into<RawStream<'static>>>(
        self: Arc<Self>,
        parts: http::request::Parts,
        stream: T,
        upgrade: Option<hyper::upgrade::OnUpgrade>,
        connection: ConnectionMeta,
    ) -> Result<hyper::Response<ReaderStream<ErasedResponse>>, http::Error> {
        let request = ErasedRequest::new(self, parts, |rocket, parts| {
            Request::from_hyp(rocket, parts, connection).unwrap_or_else(|e| e)
        });

        let mut response = request.into_response(
            Data::from(stream),
            |rocket, request, data| Box::pin(rocket.preprocess(request, data)),
            |token, rocket, request, data| Box::pin(async move {
                if !request.errors.is_empty() {
                    return rocket.dispatch_error(Status::BadRequest, request).await;
                }

                let mut response = rocket.dispatch(token, request, data).await;
                response.body_mut().size().await;
                response
            })
        ).await;

        let io_handler = response.to_io_handler(Rocket::extract_io_handler);
        if let (Some(handler), Some(upgrade)) = (io_handler, upgrade) {
            let upgrade = upgrade.map_ok(IoStream::from).map_err(io::Error::other);
            tokio::task::spawn(io_handler_task(upgrade, handler));
        }

        let mut builder = hyper::Response::builder();
        builder = builder.status(response.inner().status().code);
        for header in response.inner().headers().iter() {
            builder = builder.header(header.name().as_str(), header.value());
        }

        if let Some(size) = response.inner().body().preset_size() {
            builder = builder.header("Content-Length", size);
        }

        let chunk_size = response.inner().body().max_chunk_size();
        builder.body(ReaderStream::with_capacity(response, chunk_size))
    }
}

async fn io_handler_task<S>(stream: S, mut handler: ErasedIoHandler)
    where S: Future<Output = io::Result<IoStream>>
{
    let stream = match stream.await {
        Ok(stream) => stream,
        Err(e) => return warn_!("Upgrade failed: {e}"),
    };

    info_!("Upgrade succeeded.");
    if let Err(e) = handler.take().io(stream).await {
        match e.kind() {
            io::ErrorKind::BrokenPipe => warn!("Upgrade I/O handler was closed."),
            e => error!("Upgrade I/O handler failed: {e}"),
        }
    }
}

impl Rocket<Orbit> {
    pub(crate) async fn serve<L>(self: Arc<Self>, listener: L) -> Result<()>
        where L: Listener + 'static
    {
        let mut builder = Builder::new(TokioExecutor::new());
        let keep_alive = Duration::from_secs(self.config.keep_alive.into());
        builder.http1()
            .half_close(true)
            .timer(TokioTimer::new())
            .keep_alive(keep_alive > Duration::ZERO)
            .preserve_header_case(true)
            .header_read_timeout(Duration::from_secs(15));

        #[cfg(feature = "http2")] {
            builder.http2().timer(TokioTimer::new());
            if keep_alive > Duration::ZERO {
                builder.http2()
                    .timer(TokioTimer::new())
                    .keep_alive_interval(keep_alive / 4)
                    .keep_alive_timeout(keep_alive);
            }
        }

        let listener = listener.bounced().cancellable(self.shutdown(), &self.config.shutdown);
        let (server, listener) = (Arc::new(builder), Arc::new(listener));
        while let Some(accept) = listener.accept_next().await {
            let (listener, rocket, server) = (listener.clone(), self.clone(), server.clone());
            tokio::spawn({
                let result = async move {
                    let conn = TokioIo::new(listener.connect(accept).await?);
                    let meta = ConnectionMeta::from(conn.inner());
                    let service = service_fn(|mut req| {
                        let upgrade = hyper::upgrade::on(&mut req);
                        let (parts, incoming) = req.into_parts();
                        rocket.clone().service(parts, incoming, Some(upgrade), meta.clone())
                    });

                    let serve = pin!(server.serve_connection_with_upgrades(conn, service));
                    match select(serve, rocket.shutdown()).await {
                        Left((result, _)) => result,
                        Right((_, mut conn)) => {
                            conn.as_mut().graceful_shutdown();
                            conn.await
                        }
                    }
                };

                result.inspect_err(crate::error::log_server_error)
            });
        }

        Ok(())
    }
}

#[cfg(feature = "http3")]
impl Rocket<Orbit> {
    pub(crate) async fn serve3<L>(self: Arc<Self>, listener: L) -> Result<()>
        where L: Listener<Accept = s2n_quic::Connection> + 'static
    {
        use crate::listener::quic::Void;
        use tokio_stream::StreamExt;
        use s2n_quic_h3 as quic_h3;

        type H3Conn = quic_h3::h3::server::Connection<quic_h3::Connection, bytes::Bytes>;

        let listener = listener.bounced().cancellable(self.shutdown(), &self.config.shutdown);
        let listener = Arc::new(listener);
        while let Some(accept) = listener.accept_next().await {
            let rocket = self.clone();
            tokio::spawn({
                let result = async move {
                    let void = Void(accept.handle().local_addr()?);
                    let quic_conn = quic_h3::Connection::new(accept);
                    let mut h3 = H3Conn::new(quic_conn).await.map_err(io::Error::other)?;
                    while let Some((req, stream)) = h3.accept().await.map_err(io::Error::other)? {
                        let rocket = rocket.clone();
                        // tokio::spawn(async move {
                        //     let (mut tx, rx) = stream.split();
                        //     let (parts, _) = req.into_parts();
                        //     let response = rocket
                        //         .service(parts, rx, None, ConnectionMeta::from(&void)).await
                        //         .map_err(io::Error::other)?;
                        //
                        //     let (r, mut stream) = response.into_parts();
                        //     let response = http::Response::from_parts(r, ());
                        //     tx.send_response(response).await.map_err(io::Error::other)?;
                        //
                        //     while let Some(Ok(bytes)) = stream.next().await {
                        //         tx.send_data(bytes).await.map_err(io::Error::other)?;
                        //     }
                        //
                        //     tx.finish().await.map_err(io::Error::other)
                        // }).await.map_err(io::Error::other)??;
                    }

                    Ok(())
                };

                result.inspect_err(crate::error::log_server_error)
            });
        }

        Ok(())
    }
}
