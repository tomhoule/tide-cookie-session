// #[deny(missing_docs)]

#![feature(associated_type_defaults)]
#![feature(async_await)]
#![feature(await_macro)]
#![feature(futures_api)]

pub mod storage;

use storage::*;

use futures::future::{FutureExt, FutureObj};
use log::error;
use std::sync::Arc;
use storage::*;
use tide::IntoResponse;
use tide::{Extract, Request, Response, RouteMatch};

/// The extractable handle to a session. Users can read, set and delete the session data from this.
///
/// `SessionShape` is the user-defined contents of the session. It has to be `Clone` and gets
/// copied often, so it is preferrable not to store large amounts of data in the session.
pub struct Session<SessionShape>(Handle<SessionShape>);

impl<SessionShape> Session<SessionShape> {
    fn new(handle: Handle<SessionShape>) -> Self {
        Session(handle)
    }

    pub async fn get(&self) -> Result<Option<SessionShape>, failure::Error> {
        await! { self.0.storage.get(&self.0.session_id) }
    }

    pub async fn set(&self, new_state: SessionShape) -> Result<(), failure::Error> {
        await! { self.0.storage.set(&self.0.session_id, new_state) }
    }

    pub async fn delete(&self) -> Result<(), failure::Error> {
        await! { self.0.storage.delete(&self.0.session_id) }
    }

    // see rails security guide, reset_session
    // could be implemented with a channel signaling the reset to the middleware
    // pub fn reset(&self) {
    //   self.0.
    // }
}

impl<Data, SessionShape> Extract<Data> for Session<SessionShape>
where
    Data: 'static + Send,
    SessionShape: Send + 'static,
{
    type Fut = futures::future::Ready<Result<Self, Response>>;

    fn extract<'a>(
        _data: &'a mut Data,
        req: &'a mut Request,
        _options: &'a Option<RouteMatch<'a>>,
        _store: &'a tide::configuration::Store,
    ) -> Self::Fut {
        let handle: Option<Handle<SessionShape>> = req.extensions_mut().remove();
        let result = handle
            .map(Session::new)
            .ok_or_else(|| {
                error!("Application error: attempted to extract a session shape for which no middleware is configured (URI: {:?})", req.uri());
                http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
            });
        futures::future::ready(result)
    }
}

type SessionId = String;

// What the middleware puts in request context.
#[derive(Clone)]
struct Handle<SessionShape> {
    session_id: SessionId,
    storage: Storage<SessionShape>,
}

type Storage<SessionShape> = Arc<dyn SessionStorage<Value = SessionShape> + Send + Sync>;

/// The session middleware.
///
/// The `SessionShape` parameter is the user-defined shape of the sessions managed by the
/// middleware.
pub struct CookieSessionMiddleware<SessionShape> {
    /// The name of the cookie used to store the session id.
    cookie_name: String,
    /// Used for extracting the cookie. We do not use the Cookies extractor from tide (yet) because
    /// composing extractors and middlewares is difficult.
    cookie_matcher: regex::Regex,
    storage: Storage<SessionShape>,
}

impl<SessionShape> CookieSessionMiddleware<SessionShape>
where
    SessionShape: Send + Sync + 'static + Clone,
{
    /// `cookie_name` will be the name of the cookie used to store the session id.
    pub fn new(cookie_name: String, storage: Storage<SessionShape>) -> Result<Self, regex::Error> {
        let cookie_matcher = regex::Regex::new(&format!(r"{}=([a-z0-9-]+)", cookie_name))?;
        Ok(CookieSessionMiddleware {
            cookie_name,
            cookie_matcher,
            storage,
        })
    }

    /// Attempt to read the session id from the cookies on a request.
    fn extract_session_id(&self, req: &Request) -> Option<String> {
        let cookies = req.headers().get(http::header::COOKIE);
        cookies
            .and_then(|cookies| {
                self.cookie_matcher
                    .captures_iter(cookies.to_str().ok()?)
                    .next()
            })
            .and_then(|captures| captures.get(1))
            .map(|s| s.as_str().to_owned())
    }

    async fn handle<'a, Data>(
        &'a self,
        mut ctx: tide::middleware::RequestContext<'a, Data>,
    ) -> tide::Response
    where
        Data: Send + 'static + Clone,
    {
        let session_id = self
            .extract_session_id(&ctx.req)
            .unwrap_or_else(new_session_id);

        let set_cookie_header =
            http::header::HeaderValue::from_str(&format!("{}={}", &self.cookie_name, &session_id))
                .expect("TODO: error handling");

        let self_handle: Handle<_> = self.create_handle(session_id);

        ctx.req.extensions_mut().insert(self_handle);

        let mut res = await! { ctx.next() };

        res.headers_mut().insert("Set-Cookie", set_cookie_header);

        res
    }

    fn create_handle(&self, session_id: String) -> Handle<SessionShape> {
        Handle {
            session_id,
            storage: self.storage.clone(),
        }
    }
}

impl<Data, SessionShape> tide::Middleware<Data> for CookieSessionMiddleware<SessionShape>
where
    Data: Clone + Send + 'static,
    SessionShape: Clone + Send + Sync + 'static,
{
    fn handle<'a>(
        &'a self,
        ctx: tide::middleware::RequestContext<'a, Data>,
    ) -> FutureObj<'a, tide::Response> {
        use futures::future::FutureExt;
        let fut = self.handle(ctx).boxed();
        futures::future::FutureObj::new(fut)
    }
}

/// Generate a new session id.
fn new_session_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_session_id_extraction_works() {
        let middleware = CookieSessionMiddleware::<()>::new(
            "my_app_p".to_owned(),
            Arc::new(InMemorySession::new()),
        )
        .unwrap();

        let mut req = Request::new(http_service::Body::empty());
        req.headers_mut()
            .insert("Cookie", http::header::HeaderValue::from_static("abcd=3"));

        assert!(middleware.extract_session_id(&req).is_none());

        req.headers_mut().insert(
            "Cookie",
            http::header::HeaderValue::from_static("my_app_p=3"),
        );

        assert_eq!(&middleware.extract_session_id(&req).unwrap(), "3");

        req.headers_mut().insert(
            "Cookie",
            http::header::HeaderValue::from_static("something_else=44; my_app_p=3-4; other_app=2"),
        );

        assert_eq!(&middleware.extract_session_id(&req).unwrap(), "3-4");
    }
}
