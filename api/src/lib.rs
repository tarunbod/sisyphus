pub type MasterKey = [u8; 64];
pub type TemplateSeed = [u8; 32];

pub fn generate_master_key<S: AsRef<str>>(name: S, master_password: S) -> MasterKey {
    let mut output = [0; 64];
    let mut salt_bytes = b"com.lyndir.masterpassword".to_vec();
    salt_bytes.extend_from_slice(&(name.as_ref().len() as u32).to_be_bytes());
    salt_bytes.extend_from_slice(name.as_ref().as_bytes());
    scrypt::scrypt(
        master_password.as_ref().as_bytes(), // password
        &salt_bytes,
        &scrypt::Params::new(15, 8, 2).unwrap(),
        &mut output
    ).unwrap();
    output
}

pub fn generate_template_seed<S: AsRef<str>>(master_key: MasterKey, site_name: S, site_counter: u32) -> TemplateSeed {
    use hmac::Mac;

    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&master_key).unwrap();
    let mut message_bytes = b"com.lyndir.masterpassword".to_vec();
    message_bytes.extend_from_slice(&(site_name.as_ref().len() as u32).to_be_bytes());
    message_bytes.extend_from_slice(site_name.as_ref().as_bytes());
    message_bytes.extend_from_slice(&site_counter.to_be_bytes());
    mac.update(&message_bytes);
    mac.finalize().into_bytes().into()
}

pub enum PasswordType {
    MaximumSecurity,
    Long,
    Medium,
    Short,
    Basic,
    PIN,
}

impl PasswordType {
    pub fn generate(&self, template_seed: &TemplateSeed) -> String {
        let templates: &[&str] = match self {
            Self::MaximumSecurity => &["anoxxxxxxxxxxxxxxxxx", "axxxxxxxxxxxxxxxxxno"],
            Self::Long => &["CvcvnoCvcvCvcv", "CvcvCvcvnoCvcv", "CvcvCvcvCvcvno", "CvccnoCvcvCvcv", "CvccCvcvnoCvcv", "CvccCvcvCvcvno", "CvcvnoCvccCvcv", "CvcvCvccnoCvcv", "CvcvCvccCvcvno", "CvcvnoCvcvCvcc", "CvcvCvcvnoCvcc", "CvcvCvcvCvccno", "CvccnoCvccCvcv", "CvccCvccnoCvcv", "CvccCvccCvcvno", "CvcvnoCvccCvcc", "CvcvCvccnoCvcc", "CvcvCvccCvccno", "CvccnoCvcvCvcc", "CvccCvcvnoCvcc", "CvccCvcvCvccno"],
            Self::Medium => &["CvcnoCvc", "CvcCvcno"],
            Self::Short => &["Cvcn"],
            Self::Basic => &["aaanaaan", "aannaaan", "aaannaaa"],
            Self::PIN => &["nnnn"]
        };
        let template = templates[(template_seed[0] as usize % templates.len()) as usize];
        let mut password = String::new();
        for (i, c) in template.chars().enumerate() {
            let template_chars = match c {
                'V' => "AEIOU",
                'C' => "BCDFGHJKLMNPQRSTVWXYZ",
                'v' => "aeiou",
                'c' => "bcdfghjklmnpqrstvwxyz",
                'A' => "AEIOUBCDFGHJKLMNPQRSTVWXYZ",
                'a' => "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz",
                'n' => "0123456789",
                'o' => "@&%?,=[]_:-+*$#!'^~;()/.",
                'x' => "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()",
                _ => unreachable!("Invalid template char")
            };
            let password_char = template_chars.as_bytes()[template_seed[i + 1] as usize % template_chars.len()] as char;
            password.push(password_char);
        }
        password
    }
}

pub fn generate_site_password<S: AsRef<str>>(name: S, master_password: S, site_name: S, site_counter: u32, password_type: PasswordType) -> String {
    let master_key = generate_master_key(name, master_password);
    let template_seed = generate_template_seed(master_key, site_name, site_counter);
    password_type.generate(&template_seed)
}

#[cfg(test)]
mod test {
    use super::*;

    const TEST_NAME: &str = "Robert Lee Mitchell";
    const TEST_MPW: &str = "pink fluffy door frame";
    const TEST_SITE: &str = "apple.com";

    const TEST_MASTER_KEY: MasterKey = [
        55, 250, 107, 56, 17, 126, 135, 155,
        57, 100, 135, 232, 93, 70, 190, 160,
        68, 64, 163, 221, 163, 160, 106, 128,
        247, 148, 172, 39, 53, 204, 107, 71,
        236, 47, 200, 124, 12, 70, 49, 4,
        10, 89, 191, 59, 135, 59, 230, 15,
        201, 161, 50, 130, 148, 120, 197, 180,
        78, 176, 120, 164, 166, 154, 197, 197
    ];

    const TEST_TEMPLATE_SEED: TemplateSeed = [
        107, 169, 50, 133, 141, 227, 116, 247,
        53, 184, 120, 225, 78, 172, 46, 229,
        71, 10, 187, 157, 111, 132, 94, 7,
        75, 120, 114, 45, 206, 123, 29, 154
    ];

    #[test]
    fn test_generate_master_key() {
        assert_eq!(generate_master_key(TEST_NAME, TEST_MPW), TEST_MASTER_KEY);
    }

    #[test]
    fn test_generate_template_seed() {
        assert_eq!(generate_template_seed(TEST_MASTER_KEY, TEST_SITE, 1), TEST_TEMPLATE_SEED);
    }

    #[test]
    fn test_generate_passwords() {
        assert_eq!(generate_site_password(TEST_NAME, TEST_MPW, TEST_SITE, 1, PasswordType::MaximumSecurity), "Fy9*Crb1mwueXtF)Bq7!");
        assert_eq!(generate_site_password(TEST_NAME, TEST_MPW, TEST_SITE, 1, PasswordType::Long), "CakeWevoVato2/");
        assert_eq!(generate_site_password(TEST_NAME, TEST_MPW, TEST_SITE, 2, PasswordType::Long), "Hawa5!DekeJumw");
        assert_eq!(generate_site_password(TEST_NAME, TEST_MPW, TEST_SITE, 1, PasswordType::Medium), "CakTip7=");
        assert_eq!(generate_site_password(TEST_NAME, TEST_MPW, TEST_SITE, 1, PasswordType::Short), "Cak1");
        assert_eq!(generate_site_password(TEST_NAME, TEST_MPW, TEST_SITE, 1, PasswordType::Basic), "FyY17DlE");
        assert_eq!(generate_site_password(TEST_NAME, TEST_MPW, TEST_SITE, 1, PasswordType::PIN), "9031");
    }
}
