use std::sync::Arc;

use http_mitm_proxy::MitmProxy;

#[tokio::main]
async fn main() {
    let proxy = MitmProxy::new(());
    MitmProxy::<()>::serve(Arc::new(proxy), "127.0.0.1:3003")
        .await
        .unwrap();
}
