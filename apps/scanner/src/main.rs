use clap::Parser;

#[derive(Parser)]
#[command(name = "atlas")]
#[command(about = "Prometheus Atlas Security Drift Scanner")]
struct Cli {
    target: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    match cli.target {
        Some(target) => {
            println!("Scanning target: {}", target);
        }
        None => {
            println!("Prometheus Atlas Scanner");
        }
    }
}
