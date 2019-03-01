use futures::future::{FutureExt, FutureObj};
use futures::lock::Mutex;
use std::collections::HashMap;

pub struct InMemorySession<S>(Mutex<HashMap<String, S>>);
pub struct RedisSession;

impl<S> InMemorySession<S> {
    pub fn new() -> Self {
        InMemorySession(Mutex::new(HashMap::new()))
    }
}

impl<S> SessionStorage for InMemorySession<S>
where
    S: Clone + Send,
{
    type Value = S;

    fn get(&self, key: &str) -> FutureObj<Result<Option<Self::Value>, failure::Error>> {
        let key = key.to_owned();
        FutureObj::new(
            self.0
                .lock()
                .map(move |guard| Ok(guard.get(&key).cloned()))
                .boxed(),
        )
    }

    fn set(&self, key: &str, value: Self::Value) -> FutureObj<Result<(), failure::Error>> {
        let key = key.to_owned();
        FutureObj::new(
            self.0
                .lock()
                .map(move |mut guard| {
                    guard.insert(key, value);
                    Ok(())
                })
                .boxed(),
        )
    }

    fn delete(&self, key: &str) -> FutureObj<Result<(), failure::Error>> {
        let key = key.to_owned();
        FutureObj::new(
            self.0
                .lock()
                .map(move |mut guard| {
                    guard.remove(&key);
                    Ok(())
                })
                .boxed(),
        )
    }
}

pub trait SessionStorage {
    type Value;

    fn get(&self, key: &str) -> FutureObj<Result<Option<Self::Value>, failure::Error>>;

    fn set(&self, key: &str, value: Self::Value) -> FutureObj<Result<(), failure::Error>>;

    fn delete(&self, key: &str) -> FutureObj<Result<(), failure::Error>>;
}
