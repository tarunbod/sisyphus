use clap::{Parser, Subcommand};
use arboard::Clipboard;
use sisyphus_api::{
    generate_site_password,
    PasswordType
};

#[derive(Parser)]
#[command(version)]
#[command(about = "CLI for sisyphus password manager.")]
struct Args {
    #[command(subcommand)]
    command: Command
}

#[derive(Clone, clap::ValueEnum)]
enum ArgPasswordType {
    Max,
    Long,
    Medium,
    Short,
    Basic,
    PIN
}

#[derive(Subcommand)]
enum Command {
    Get {
        site_name: String,

        #[arg(default_value_t = 1)]
        counter: u32,

        #[arg(value_enum, default_value_t = ArgPasswordType::Long)]
        password_type: ArgPasswordType,
    },

    SetUser {
        username: String
    }
}

impl Into<PasswordType> for ArgPasswordType {
    fn into(self) -> PasswordType {
        match self {
            Self::Max => PasswordType::MaximumSecurity,
            Self::Long => PasswordType::Long,
            Self::Medium => PasswordType::Medium,
            Self::Short => PasswordType::Short,
            Self::Basic => PasswordType::Basic,
            Self::PIN => PasswordType::PIN
        }
    }
}

fn main() {
    let args = Args::parse();
    match args.command {
        Command::Get { site_name, counter, password_type} => get_password(site_name, counter, password_type.into()),
        Command::SetUser { username } => todo!()
    }
}

fn get_username() -> Option<String> {
    Some("Tarun Boddupalli".into())
}

fn get_password(site_name: String, counter: u32, password_type: PasswordType) {
    let username = match get_username() {
        Some(name) => name,
        None => {
            println!("No username found. Please set your username with `spm set-user` first.");
            return;
        }
    };
    let user_key = rpassword::prompt_password("Enter your master password: ").unwrap();
    let password = generate_site_password(username, user_key, site_name, counter, password_type);
    let mut clipboard = Clipboard::new().unwrap();
    clipboard.set_text(password).unwrap();
    println!("Password copied to clipboard");
}
