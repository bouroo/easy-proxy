use crate::errors::Errors;
use bytes::Bytes;
use pingora::{
    http::ResponseHeader,
    protocols::http::HttpTask,
    proxy::Session,
    ErrorType,
    Result,
};
use serde::Serialize;
use tracing::error;

pub struct Response<'a> {
    headers: ResponseHeader,
    body: Bytes,
    session: &'a mut Session,
}

impl<'a> Response<'a> {
    /// Create a 200-response with empty body.
    pub async fn new(session: &'a mut Session) -> Result<Self> {
        let headers = ResponseHeader::build(200, None).map_err(|e| {
            pingora::Error::because(
                ErrorType::InternalError,
                "[Response]".into(),
                Errors::InternalServerError(e.to_string()),
            )
        })?;
        Ok(Self { headers, body: Bytes::new(), session })
    }

    /// Set HTTP status code.
    pub fn status(&mut self, status: u16) -> &mut Self {
        if let Err(e) = self.headers.set_status(status) {
            error!("Error setting status: {:?}", e);
        }
        self
    }

    /// Append or overwrite a header.
    pub fn header<K, V>(&mut self, key: K, value: V) -> &mut Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        if let Err(e) = self.headers.append_header(key.into(), value.into()) {
            error!("Error adding header: {:?}", e);
        }
        self
    }

    /// 301-redirect to HTTPS, auto‐prepends ':' if `port` is Some.
    pub fn redirect_https<H, P>(&mut self, host: H, path: P, port: Option<P>) -> &mut Self
    where
        H: AsRef<str>,
        P: AsRef<str>,
    {
        self.status(301);
        let port = port.map(|p| format!(":{}", p.as_ref())).unwrap_or_default();
        let location = format!("https://{}{}{}", host.as_ref(), port, path.as_ref());
        self.header("Location", location)
            .header("Content-Length", "0")
    }

    /// Set raw body and update Content-Length.
    pub fn body(&mut self, body: Bytes) -> &mut Self {
        self.body = body;
        self.header("Content-Length", self.body.len().to_string())
    }

    /// Serialize JSON body, set Content-Type & Content-Length.
    pub fn body_json<T>(&mut self, body: &T) -> Result<&mut Self>
    where
        T: Serialize,
    {
        let buf = serde_json::to_vec(body).map_err(|e| {
            pingora::Error::because(
                ErrorType::InternalError,
                "[Response]".into(),
                Errors::InternalServerError(e.to_string()),
            )
        })?;
        self.body(Bytes::from(buf));
        self.header("Content-Type", "application/json");
        Ok(self)
    }

    /// Send headers and body in order, return `true` on success.
    pub async fn send(&mut self) -> Result<bool> {
        let tasks = vec![
            HttpTask::Header(Box::new(self.headers.clone()), false),
            HttpTask::Body(Some(self.body.clone()), false),
            HttpTask::Done,
        ];
        self.session
            .response_duplex_vec(tasks)
            .await
            .map_err(|e| {
                error!("Error sending response: {:?}", e);
                pingora::Error::because(
                    ErrorType::InternalError,
                    "[Response]".into(),
                    Errors::InternalServerError(e.to_string()),
                )
            })?;
        Ok(true)
    }
}
