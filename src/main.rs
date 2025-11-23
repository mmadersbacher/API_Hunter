mod cli;
mod runner;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = cli::parse_cli();
    runner::run_from_cli(cli).await
}
