# tide-session

This is an experimental middleware and extractor for cookie-based sessions within the [tide framework](https://github.com/rustasync/tide).

It only stores a session id in a cookie, and relies on a configurable session
store (implementing the `SessionStorage` trait)

## Examples

### Reading the contents of the session

```rust
async fn print_session(session: Session<AppSession>) -> Response {
    let session: Option<AppSession> = await! { session.get() }.unwrap();
    let printed_session = format!("{:?}", session);
    let res = Response::new(printed_session.into());
    res
}

```

### Modiying the contents of the session

```rust
async fn authenticate_user(session: Session<AppSession>) -> Response {
    let res = Response::new(Body::empty());

    let result: Result<(), failure::Error> = await! { session.set(AppSession {
        user_id: "george".into(),
        user_category: UserCategory::Admin,
    }) };

    res
}
```

For a more complete example, read the tests in `tests/cookies.rs`.

## TODO

- [session id reset](https://guides.rubyonrails.org/security.html#session-fixation-countermeasures)
- documentation
- general polish, more tests
- more backends
- Signed and encrypted cookies, more configurable cookies.
