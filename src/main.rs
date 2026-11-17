#[tokio::main]
async fn main() {
    if let Err(err) = hickory_chinadns::cli().await {
        eprintln!("hickory-chinadns: {err}");
        std::process::exit(1);
    }
}
