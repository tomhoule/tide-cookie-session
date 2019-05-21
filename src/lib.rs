// #[deny(missing_docs)]

#![feature(associated_type_defaults)]
#![feature(async_await)]
#![feature(futures_api)]

pub mod storage;

use storage::*;
use tide_core::{error::StringError, Context, box_async};
use futures::channel::oneshot;
use futures::future::BoxFuture;
use tide_cookies::ContextExt as _;
use cookie::{Cookie,SameSite};
const MIDDLEWARE_MISSING_MSG: &str =
    "SessionMiddleware must be used to populate request and response cookies";

pub trait ContextExt {
    fn set_session<T: 'static + Sync + Send + Default>(&mut self, new_session: T) -> Result<(), StringError>;
    fn take_session<T: 'static + Sync + Send + Default>(&mut self) -> Result<T, StringError>;

    // see rails security guide, reset_session
    // could be implemented with a channel signaling the reset to the middleware
    // fn reset(&self);
}

impl<AppData> ContextExt for tide::Context<AppData> {
    fn set_session<T: 'static + Sync + Send + Default>(&mut self, new_session: T) -> Result<(), StringError> {
       let session = self
           .extensions_mut()
           .remove::<Session<T>>()
           .ok_or_else(|| StringError(MIDDLEWARE_MISSING_MSG.to_owned()))?;
       session
           .sender
           .send(new_session)
           .map_err(|_| StringError("Unable to handle session".to_owned()))
    }

    fn take_session<T: 'static + Sync + Send + Default>(&mut self) -> Result<T, StringError> {
        let session = self
            .extensions_mut()
            .remove::<Session<T>>()
            .ok_or_else(|| StringError(MIDDLEWARE_MISSING_MSG.to_owned()));
        session
            .map(|s| s.data)
    }
}

/// `SessionShape` is the user-defined contents of the session. It has to be `Clone` and gets
/// copied often, so it is preferrable not to store large amounts of data in the session.
pub struct Session<Shape> {
    data: Shape,
    sender: oneshot::Sender<Shape>,
}

impl<SessionShape> Session<SessionShape>
where
    SessionShape: Default,
{
    fn new(data: SessionShape) -> (Self, oneshot::Receiver<SessionShape>) {
        let (sender, receiver) = oneshot::channel();
        (Session { data, sender }, receiver)
    }
}

type SessionId = String;

/// The cookie session middleware.
pub struct CookieSessionMiddleware<Storage> {
    /// The name of the cookie used to store the session id.
    cookie_name: String,
    storage: Storage,
}

/// The `Shape` parameter is the user-defined shape of the sessions managed by the
/// middleware.
impl<Storage, Shape> CookieSessionMiddleware<Storage>
where
    Storage: SessionStorage<Value = Shape>,
    //Shape: Send + Sync + 'static + Clone + Default,
    Shape: 'static,
{
    /// `cookie_name` will be the name of the cookie used to store the session id.
    pub fn new(cookie_name: String, storage: Storage) -> Self {
        CookieSessionMiddleware {
            cookie_name,
            storage,
        }
    }

    /// Attempt to read the session id from the cookies on a request.
    fn extract_session_id<A>(&self, ctx: &mut tide::Context<A>) -> Option<String> {
        ctx.get_cookie(&self.cookie_name).expect("can't read cookies").map(|c| c.value().to_owned())
    }

}

impl<AppData, Storage, Shape> tide::middleware::Middleware<AppData>
    for CookieSessionMiddleware<Storage>
where
    AppData: Send + Sync + 'static,
    Storage: SessionStorage<Value = Shape> + Sync + Send + 'static,
    Shape: Clone + Send + Sync + 'static + Default,
{
    fn handle<'a>(
        &'a self,
        mut ctx: tide::Context<AppData>,
        next: tide::middleware::Next<'a, AppData>,
    ) -> BoxFuture<'a, tide::Response> {
        box_async! {
            let session_id = self
                .extract_session_id(&mut ctx)
                .unwrap_or_else(new_session_id);

            let session_shape = self.storage.get(&session_id).await
                .ok()
                .and_then(|a| a)
                .unwrap_or_default();

            let (session, mut receiver) = Session::new(session_shape);
            ctx.extensions_mut().insert::<Session<Shape>>(session);

            let mut session_cookie = Cookie::new(self.cookie_name.clone(), session_id.clone());
            session_cookie.set_path("/");
            session_cookie.set_http_only(true);
            session_cookie.set_same_site(SameSite::Strict);
            ctx.set_cookie(session_cookie);

            let res = next.run(ctx).await;

            let received = receiver.try_recv().ok().and_then(|a| a);

            if let Some(received) = received {
                self.storage.set(&session_id, received).await.expect("TODO: error handling");
            }

            res
        }
    }
}

/// Generate a new session id.
fn new_session_id() -> SessionId {
    uuid::Uuid::new_v4().to_string()
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn cookie_session_id_extraction_works() {
//         let middleware = CookieSessionMiddleware::<()>::new(
//             "my_app_p".to_owned(),
//             Arc::new(InMemorySession::new()),
//         )
//         .unwrap();

//         let mut req = Request::new(http_service::Body::empty());

//         req.headers_mut()
//             .insert("Cookie", http::header::HeaderValue::from_static("abcd=3"));

//         assert!(middleware.extract_session_id(&req).is_none());

//         req.headers_mut().insert(
//             "Cookie",
//             http::header::HeaderValue::from_static("my_app_p=3"),
//         );

//         assert_eq!(&middleware.extract_session_id(&req).unwrap(), "3");

//         req.headers_mut().insert(
//             "Cookie",
//             http::header::HeaderValue::from_static("something_else=44; my_app_p=3-4; other_app=2"),
//         );

//         assert_eq!(&middleware.extract_session_id(&req).unwrap(), "3-4");
//     }
// }
