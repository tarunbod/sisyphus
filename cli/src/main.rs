use clap::{Parser, Subcommand};
use arboard::Clipboard;
use keyring::error::Error as KeyringError;
use sisyphus_api::{
    generate_site_password,
    PasswordType
};

const SERVICE_NAME: &str = "sisyphus_password_manager";
const USERNAME_ENTRY_NAME: &str = "username";
const USER_KEY_ENTRY_NAME: &str = "user_key";

#[derive(Parser)]
#[command(version)]
#[command(about = "CLI for sisyphus password manager.")]
struct Args {
    #[command(subcommand)]
    command: Command
}

#[derive(Subcommand)]
enum Command {
    Get(PasswordArgs),

    Login {
        username: String
    },

    Logout
}

#[derive(clap::Args)]
struct PasswordArgs {
    #[arg(short, long)]
    username: Option<String>,

    site_name: String,

    #[arg(default_value_t = 1)]
    counter: u32,

    #[arg(value_enum, default_value_t = ArgPasswordType::Long)]
    password_type: ArgPasswordType,
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

enum Error {
    NoSavedCredentials,
    Keyring(KeyringError),
    IO(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::NoSavedCredentials => {
                write!(f, "No saved credentials found. Please log in with `spm login`, or specify a username with the -u flag.")
            }
            Self::Keyring(err) => {
                write!(f, "Unable to access secure credential store ({err:?}): ")?;
                err.fmt(f)
            }
            Self::IO(err) => {
                write!(f, "IO Error: ")?;
                err.fmt(f)
            }
        }
    }
}

impl From<KeyringError> for Error {
    fn from(err: KeyringError) -> Self {
        match err {
            KeyringError::NoEntry => Self::NoSavedCredentials,
            err => Self::Keyring(err)
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::IO(err)
    }
}

type Result<T> = std::result::Result<T, Error>;

fn main() {
    let args = Args::parse();
    let result = match args.command {
        Command::Get(password_args) => get_password(password_args),
        Command::Login { username } => login(username),
        Command::Logout => {
            match logout() {
                Ok(()) | Err(Error::Keyring(_)) => Ok(()),
                err => err
            }
        }
    };
    match result {
        Err(e) => println!("{}", e),
        _ => ()
    }
}

fn get_password(args: PasswordArgs) -> Result<()> {
    let (username, user_key) = match args.username {
        Some(username) => {
            let user_key = rpassword::prompt_password("Enter your master password: ").unwrap();
            (username, user_key)
        },
        None => get_saved_credentials()?
    };
    let password = generate_site_password(username, user_key, args.site_name, args.counter, args.password_type.into());
    let copied = match Clipboard::new() {
        Ok(mut clipboard) => clipboard.set_text(&password).is_ok(),
        _ => false
    };
    if copied {
        println!("Password copied to clipboard");
    } else {
        println!("{password}");
    }
    Ok(())
}

fn get_saved_credentials() -> Result<(String, String)> {
    let username_entry = keyring::Entry::new(SERVICE_NAME, USERNAME_ENTRY_NAME)?;
    let user_key_entry = keyring::Entry::new(SERVICE_NAME, USER_KEY_ENTRY_NAME)?;
    let username = username_entry.get_password()?;
    let user_key = user_key_entry.get_password()?;
    Ok((username, user_key))
}


fn login(username: String) -> Result<()> {
    let username_entry = keyring::Entry::new(SERVICE_NAME, USERNAME_ENTRY_NAME)?;
    let user_key_entry = keyring::Entry::new(SERVICE_NAME, USER_KEY_ENTRY_NAME)?;
    let user_key = rpassword::prompt_password("Enter your master password: ")?;
    username_entry.set_password(&username)?;
    user_key_entry.set_password(&user_key)?;
    Ok(())
}

fn logout() -> Result<()> {
    let username_entry = keyring::Entry::new(SERVICE_NAME, USERNAME_ENTRY_NAME)?;
    let user_key_entry = keyring::Entry::new(SERVICE_NAME, USER_KEY_ENTRY_NAME)?;
    username_entry.delete_password()?;
    user_key_entry.delete_password()?;
    Ok(())
}
