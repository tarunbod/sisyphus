use api::{generate_site_password, PasswordType};

fn main() {
    let password = generate_site_password("banana colored duckling", "Robert Lee Mitchell", "twitter.com", 1, PasswordType::Long);
    println!("{password}");
}