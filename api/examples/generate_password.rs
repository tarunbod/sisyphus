use api::{generate_site_password, PasswordType};

fn main() {
    let password = generate_site_password("pink fluffy door frame", "Robert Lee Mitchell", "apple.com", 1, PasswordType::Long);
    println!("{password}");
}
