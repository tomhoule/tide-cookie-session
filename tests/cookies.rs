#![feature(async_await)]
#![feature(await_macro)]
#![feature(futures_api)]

use http_service::Body;
use http_service_mock::{make_server, TestBackend};
use std::sync::Arc;
use tide::Response;
use tide_session::*;

#[derive(Clone, Debug)]
enum UserCategory {
    Admin,
}

#[derive(Clone, Debug)]
struct AppSession {
    user_id: String,
    user_category: UserCategory,
}

async fn logout(session: Session<AppSession>) -> Response {
    let res = await! { session.delete() };
    res.unwrap();
    Response::new(Body::empty())
}

async fn authenticate_user(session: Session<AppSession>) -> Response {
    let res = Response::new(Body::empty());

    let result = await! { session.set(AppSession {
        user_id: "george".into(),
        user_category: UserCategory::Admin,
    }) };
    result.unwrap();

    res
}

async fn print_session(session: Session<AppSession>) -> Response {
    let session: Option<AppSession> = await! { session.get() }.unwrap();
    let printed_session = format!("{:?}", session);
    let res = Response::new(printed_session.into());
    res
}

struct WrongSession { _something: String }

// It is going to fail because the middleware does not provide this shape of sessions.
async fn bad_endpoint(_session: Session<WrongSession>) -> Response {
    Response::new(Body::empty())
}

fn app() -> TestBackend<tide::Server<()>> {
    let mut app = tide::App::new(());

    app.at("/login").post(authenticate_user);
    app.at("/logout").get(logout);
    app.at("/print_session").get(print_session);
    app.at("/bad-endpoint").get(bad_endpoint);

    app.middleware(
        CookieSessionMiddleware::new(
            "test_app".into(),
            Arc::new(InMemorySession::<AppSession>::new()),
        )
        .unwrap(),
    );

    make_server(app.into_http_service()).unwrap()
}

fn login() -> (TestBackend<tide::Server<()>>, http::header::HeaderValue) {
    let mut app = app();

    let req = http::Request::builder()
        .uri("/login")
        .method("POST")
        .body(Body::empty())
        .unwrap();

    let res = app.simulate(req).unwrap();

    assert_eq!(res.status(), 200);
    assert!(res.headers().get("Set-Cookie").is_some());
    let cookie = res.headers().get("Set-Cookie").cloned().unwrap();

    // now let's check the session has been set

    let req = http::Request::builder()
        .header("Cookie", cookie.clone())
        .uri("/print_session")
        .body(Body::empty())
        .unwrap();

    let res = app.simulate(req).unwrap();

    assert_eq!(res.status(), 200);

    // the cookie with the session id is still the same
    assert_eq!(res.headers().get("Set-Cookie").cloned().unwrap(), cookie);

    let (_headers, body) = res.into_parts();
    let body_str = futures::executor::block_on(body.into_vec()).unwrap();

    assert_eq!(
        String::from_utf8_lossy(&body_str),
        "Some(AppSession { user_id: \"george\", user_category: Admin })"
    );

    (app, cookie)
}

#[test]
fn login_works() {
    login();
}

#[test]
fn logout_works() {
    let (mut app, cookie) = login();

    let logout_request = http::Request::builder()
        .uri("/logout")
        .header("Cookie", cookie.clone())
        .body(Body::empty())
        .unwrap();

    let res = app.simulate(logout_request).unwrap();

    assert_eq!(res.status(), 200);
    assert_eq!(res.headers().get("Set-Cookie").cloned().unwrap(), cookie);

    let print_request = http::Request::builder()
        .header("Cookie", cookie.clone())
        .uri("/print_session")
        .body(Body::empty())
        .unwrap();

    let res = app.simulate(print_request).unwrap();

    assert_eq!(res.status(), 200);

    // the cookie with the session id is still the same
    assert_eq!(res.headers().get("Set-Cookie").cloned().unwrap(), cookie);

    let (_headers, body) = res.into_parts();
    let body_str = futures::executor::block_on(body.into_vec()).unwrap();

    assert_eq!(String::from_utf8_lossy(&body_str), "None");
}

#[test]
fn extractor_with_bad_session_shape_does_not_crash() {
    let mut app = app();

    pretty_env_logger::init();

    let req = http::Request::builder().uri("/bad-endpoint").body(Body::empty()).unwrap();

    let res = app.simulate(req).unwrap();

    assert_eq!(res.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
}
