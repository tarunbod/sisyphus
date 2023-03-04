pub type MasterKey = [u8; 64];
pub type TemplateSeed = [u8; 32];

pub fn generate_master_key<S: AsRef<str>>(master_password: S, name: S) -> MasterKey {
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

pub fn generate_site_password<S: AsRef<str>>(master_password: S, name: S, site_name: S, site_counter: u32, password_type: PasswordType) -> String {
    let master_key = generate_master_key(master_password, name);
    let template_seed = generate_template_seed(master_key, site_name, site_counter);
    password_type.generate(&template_seed)
}
