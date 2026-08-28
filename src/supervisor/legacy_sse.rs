//! Legacy MCP HTTP+SSE transport used by ida-pro-mcp compatibility clients.

use axum::body::Body;
use bytes::Bytes;
use futures_util::{Sink, Stream};
use http::{
    header::{CACHE_CONTROL, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE},
    Method, Request, Response, StatusCode,
};
use http_body::Frame;
use http_body_util::{combinators::BoxBody, BodyExt, Full, LengthLimitError, Limited, StreamBody};
use rmcp::{
    model::{ClientJsonRpcMessage, ServerJsonRpcMessage},
    ServerHandler, ServiceExt,
};
use std::{
    collections::HashMap,
    convert::Infallible,
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tower_service::Service;

type LegacyResponse = Response<BoxBody<Bytes, Infallible>>;
type ResponseFuture =
    Pin<Box<dyn Future<Output = Result<LegacyResponse, Infallible>> + Send + 'static>>;
const INPUT_CHANNEL_CAPACITY: usize = 16;

#[derive(Clone)]
pub struct LegacySseConfig {
    keep_alive: Option<Duration>,
    max_request_body_bytes: usize,
    cancellation_token: CancellationToken,
}

impl LegacySseConfig {
    pub fn new(
        keep_alive: Option<Duration>,
        max_request_body_bytes: usize,
        cancellation_token: CancellationToken,
    ) -> Self {
        Self {
            keep_alive,
            max_request_body_bytes,
            cancellation_token,
        }
    }
}

pub struct LegacySseService<F> {
    factory: Arc<F>,
    sessions: Arc<Mutex<HashMap<String, LegacySession>>>,
    config: LegacySseConfig,
}

impl<F> LegacySseService<F> {
    pub fn new(factory: F, config: LegacySseConfig) -> Self {
        Self {
            factory: Arc::new(factory),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            config,
        }
    }

    fn sessions(&self) -> MutexGuard<'_, HashMap<String, LegacySession>> {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn session_id(uri: &http::Uri) -> Option<String> {
        url::form_urlencoded::parse(uri.query()?.as_bytes())
            .find_map(|(key, value)| (key == "session").then(|| value.into_owned()))
    }
}

impl<F> Clone for LegacySseService<F> {
    fn clone(&self) -> Self {
        Self {
            factory: self.factory.clone(),
            sessions: self.sessions.clone(),
            config: self.config.clone(),
        }
    }
}

impl<F, H> Service<Request<Body>> for LegacySseService<F>
where
    F: Fn() -> H + Send + Sync + 'static,
    H: ServerHandler + Send + 'static,
{
    type Response = LegacyResponse;
    type Error = Infallible;
    type Future = ResponseFuture;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let service = self.clone();
        Box::pin(async move {
            let response = match *request.method() {
                Method::GET => service.open_stream(),
                Method::POST => service.handle_post(request).await,
                _ => method_not_allowed(),
            };
            Ok(response)
        })
    }
}

impl<F> LegacySseService<F> {
    fn open_stream<H>(&self) -> LegacyResponse
    where
        F: Fn() -> H + Send + Sync + 'static,
        H: ServerHandler + Send + 'static,
    {
        let session_id = uuid::Uuid::new_v4().to_string();
        let (input_tx, input_rx) = mpsc::channel(INPUT_CHANNEL_CAPACITY);
        let (output_tx, output_rx) = mpsc::unbounded_channel();
        let session_token = self.config.cancellation_token.child_token();

        self.sessions().insert(
            session_id.clone(),
            LegacySession {
                input: input_tx,
                cancellation_token: session_token.clone(),
            },
        );

        let endpoint = format!("/sse?session={session_id}");
        let _ = output_tx.send(sse_event("endpoint", &endpoint));

        if let Some(interval) = self.config.keep_alive {
            let keep_alive_tx = output_tx.clone();
            let keep_alive_token = session_token.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = keep_alive_token.cancelled() => break,
                        _ = tokio::time::sleep(interval) => {
                            if keep_alive_tx.send(sse_event("ping", "{}")).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }

        let handler = (self.factory)();
        let transport = (
            LegacyOutput { sender: output_tx },
            LegacyInput { receiver: input_rx },
        );
        let server_token = session_token.clone();
        tokio::spawn(async move {
            match handler.serve_with_ct(transport, server_token).await {
                Ok(running) => {
                    if let Err(error) = running.waiting().await {
                        tracing::warn!(%error, "legacy SSE server task failed");
                    }
                }
                Err(error) => {
                    tracing::debug!(%error, "legacy SSE session ended during initialization");
                }
            }
        });

        let stream = LegacyBodyStream {
            receiver: Mutex::new(output_rx),
            session_id,
            sessions: self.sessions.clone(),
            cancellation_token: session_token,
        };
        let body = StreamBody::new(stream).boxed();
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/event-stream")
            .header(CACHE_CONTROL, "no-cache")
            .header(CONNECTION, "keep-alive")
            .header("X-Accel-Buffering", "no")
            .body(body)
            .expect("valid legacy SSE response")
    }

    async fn handle_post(&self, request: Request<Body>) -> LegacyResponse {
        let Some(session_id) = Self::session_id(request.uri()) else {
            return text_response(StatusCode::BAD_REQUEST, "Missing ?session for SSE POST");
        };
        let Some(session) = self.sessions().get(&session_id).cloned() else {
            return text_response(
                StatusCode::BAD_REQUEST,
                format!("No active SSE connection found for session {session_id}"),
            );
        };

        let body = match Limited::new(request.into_body(), self.config.max_request_body_bytes)
            .collect()
            .await
        {
            Ok(collected) => collected.to_bytes(),
            Err(error) if error.downcast_ref::<LengthLimitError>().is_some() => {
                return text_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    format!(
                        "Payload Too Large: request body exceeds {} bytes",
                        self.config.max_request_body_bytes
                    ),
                );
            }
            Err(error) => {
                return text_response(
                    StatusCode::BAD_REQUEST,
                    format!("Bad Request: failed to read request body: {error}"),
                );
            }
        };

        let message = match serde_json::from_slice::<ClientJsonRpcMessage>(&body) {
            Ok(message) => message,
            Err(error) => {
                return text_response(
                    StatusCode::BAD_REQUEST,
                    format!("Bad Request: invalid JSON-RPC message: {error}"),
                );
            }
        };
        if session.input.send(message).await.is_err() {
            session.cancellation_token.cancel();
            self.sessions().remove(&session_id);
            return text_response(
                StatusCode::BAD_REQUEST,
                format!("No active SSE connection found for session {session_id}"),
            );
        }

        Response::builder()
            .status(StatusCode::ACCEPTED)
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_LENGTH, body.len())
            .body(Full::new(body).boxed())
            .expect("valid legacy SSE POST response")
    }
}

#[derive(Clone)]
struct LegacySession {
    input: mpsc::Sender<ClientJsonRpcMessage>,
    cancellation_token: CancellationToken,
}

struct LegacyInput {
    receiver: mpsc::Receiver<ClientJsonRpcMessage>,
}

impl Stream for LegacyInput {
    type Item = ClientJsonRpcMessage;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.poll_recv(cx)
    }
}

struct LegacyOutput {
    sender: mpsc::UnboundedSender<Bytes>,
}

impl Sink<ServerJsonRpcMessage> for LegacyOutput {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.sender.is_closed() {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "legacy SSE client disconnected",
            )))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(self: Pin<&mut Self>, message: ServerJsonRpcMessage) -> Result<(), Self::Error> {
        let data = serde_json::to_string(&message)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        self.sender.send(sse_event("message", &data)).map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "legacy SSE client disconnected")
        })
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

struct LegacyBodyStream {
    receiver: Mutex<mpsc::UnboundedReceiver<Bytes>>,
    session_id: String,
    sessions: Arc<Mutex<HashMap<String, LegacySession>>>,
    cancellation_token: CancellationToken,
}

impl Stream for LegacyBodyStream {
    type Item = Result<Frame<Bytes>, Infallible>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut receiver = self
            .receiver
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        receiver
            .poll_recv(cx)
            .map(|item| item.map(Frame::data).map(Ok))
    }
}

impl Drop for LegacyBodyStream {
    fn drop(&mut self) {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.session_id);
        self.cancellation_token.cancel();
    }
}

fn sse_event(event: &str, data: &str) -> Bytes {
    let mut encoded = format!("event: {event}\n");
    if data.is_empty() {
        encoded.push_str("data:\n");
    } else {
        for line in data.lines() {
            encoded.push_str("data: ");
            encoded.push_str(line);
            encoded.push('\n');
        }
    }
    encoded.push('\n');
    Bytes::from(encoded)
}

fn method_not_allowed() -> LegacyResponse {
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header(http::header::ALLOW, "GET, POST")
        .body(Full::new(Bytes::from_static(b"Method Not Allowed")).boxed())
        .expect("valid method-not-allowed response")
}

fn text_response(status: StatusCode, message: impl Into<String>) -> LegacyResponse {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(message.into())).boxed())
        .expect("valid text response")
}

#[cfg(test)]
mod tests {
    use super::{LegacySseConfig, LegacySseService};
    use axum::body::Body;
    use http::{Method, Request, StatusCode};
    use http_body_util::BodyExt;
    use rmcp::ServerHandler;
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;
    use tower_service::Service;

    #[derive(Clone)]
    struct TestServer;

    impl ServerHandler for TestServer {}

    fn service() -> LegacySseService<impl Fn() -> TestServer + Send + Sync + 'static> {
        LegacySseService::new(
            || TestServer,
            LegacySseConfig::new(None, 1024 * 1024, CancellationToken::new()),
        )
    }

    #[tokio::test]
    async fn get_announces_endpoint_and_post_delivers_response_on_stream() {
        let mut service = service();
        let mut stream_response = service
            .call(
                Request::builder()
                    .method(Method::GET)
                    .uri("/sse")
                    .body(Body::empty())
                    .expect("GET request"),
            )
            .await
            .expect("infallible service");
        assert_eq!(stream_response.status(), StatusCode::OK);

        let endpoint_frame = stream_response
            .body_mut()
            .frame()
            .await
            .expect("endpoint frame")
            .expect("infallible body")
            .into_data()
            .expect("endpoint data");
        let endpoint = std::str::from_utf8(&endpoint_frame).expect("UTF-8 endpoint event");
        assert!(endpoint.starts_with("event: endpoint\ndata: /sse?session="));
        let session_id = endpoint
            .split_once("?session=")
            .and_then(|(_, value)| value.lines().next())
            .expect("session ID");

        let initialize = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"legacy-test","version":"0.1"},"capabilities":{}}}"#;
        let post_response = service
            .call(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/sse?session={session_id}"))
                    .body(Body::from(initialize.as_slice()))
                    .expect("POST request"),
            )
            .await
            .expect("infallible service");
        assert_eq!(post_response.status(), StatusCode::ACCEPTED);

        let message_frame =
            tokio::time::timeout(Duration::from_secs(2), stream_response.body_mut().frame())
                .await
                .expect("initialize response timeout")
                .expect("message frame")
                .expect("infallible body")
                .into_data()
                .expect("message data");
        let message = std::str::from_utf8(&message_frame).expect("UTF-8 message event");
        assert!(message.starts_with("event: message\ndata: "));
        assert!(message.contains(r#""id":1"#));
        assert!(message.contains(r#""protocolVersion":"2024-11-05""#));
    }

    #[tokio::test]
    async fn post_requires_an_active_stream_session() {
        let mut service = service();
        let response = service
            .call(
                Request::builder()
                    .method(Method::POST)
                    .uri("/sse?session=missing")
                    .body(Body::from("{}"))
                    .expect("POST request"),
            )
            .await
            .expect("infallible service");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
