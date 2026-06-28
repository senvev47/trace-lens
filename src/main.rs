mod api;
mod app;
mod cli;
mod collector;
mod connectors;
mod engine;
mod model;
mod storage;

#[tokio::main]
async fn main() {
    if let Err(err) = app::run().await {
        eprintln!("trace-lens error: {err:#}");
        std::process::exit(1);
    }
}
