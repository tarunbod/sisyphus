use clap::Parser;
use arboard::Clipboard;
use sisyphus_api::{
    generate_site_password,
    PasswordType
};

#[derive(Parser, Debug)]
#[command(version, about = "CLI for sisyphus password manager.")]
struct Args {
    username: String,

    site_name: String,

    #[arg(default_value_t = 1)]
    counter: u32,

    #[arg(value_enum, default_value_t = ArgPasswordType::Long)]
    password_type: ArgPasswordType,
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum ArgPasswordType {
    Max,
    Long,
    Medium,
    Short,
    Basic,
    PIN
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
    let user_key = rpassword::prompt_password("Enter your master password: ").unwrap();
    let password = generate_site_password(args.username, user_key, args.site_name, args.counter, args.password_type.into());
    let mut clipboard = Clipboard::new().unwrap();
    clipboard.set_text(password).unwrap();
    println!("Password copied to clipboard");
}
