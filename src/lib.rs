use async_trait::async_trait;

#[async_trait]
pub trait MiddleMan<K> {
    async fn request(&self, data: &[u8]) -> K;
    async fn response(&self, key: &K, data: &[u8], closed: bool);
}

pub struct MitmProxy<T> {
    middle_man: T,
}

impl<T> MitmProxy<T> {
    pub fn new(middle_man: T) -> Self {
        Self { middle_man }
    }
}
