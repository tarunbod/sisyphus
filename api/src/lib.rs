#![allow(non_upper_case_globals)] // FIXME

type MasterKey = [u8; 64];
type TemplateSeed = [u8; 32];

const TEMPLATE_GROUP_V: &str = "AEIOU";
const TEMPLATE_GROUP_C: &str = "BCDFGHJKLMNPQRSTVWXYZ";
const TEMPLATE_GROUP_v: &str = "aeiou";
const TEMPLATE_GROUP_c: &str = "bcdfghjklmnpqrstvwxyz";
const TEMPLATE_GROUP_A: &str = "AEIOUBCDFGHJKLMNPQRSTVWXYZ";
const TEMPLATE_GROUP_a: &str = "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz";
const TEMPLATE_GROUP_n: &str = "0123456789";
const TEMPLATE_GROUP_o: &str = "@&%?,=[]_:-+*$#!'^~;()/.";
const TEMPLATE_GROUP_x: &str = "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()";

fn generate_master_key<S: AsRef<str>>(master_password: S, name: S) -> MasterKey {
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

fn generate_template_seed<S: AsRef<str>>(master_key: MasterKey, site_name: S, site_counter: u32) -> TemplateSeed {
    use hmac::Mac;

    type HmacSha256 = hmac::Hmac<sha2::Sha256>;
    let mut mac = HmacSha256::new_from_slice(&master_key).unwrap();
    let mut message_bytes = b"com.lyndir.masterpassword".to_vec();
    message_bytes.extend_from_slice(&(site_name.as_ref().len() as u32).to_be_bytes());
    message_bytes.extend_from_slice(site_name.as_ref().as_bytes());
    message_bytes.extend_from_slice(&site_counter.to_be_bytes());
    mac.update(&message_bytes);
    let output = mac.finalize().into_bytes().into();
    output
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
    fn get_template(&self, seed: TemplateSeed) -> &'static str {
        let templates: &[&str] = match self {
            Self::MaximumSecurity => &["anoxxxxxxxxxxxxxxxxx", "axxxxxxxxxxxxxxxxxno"],
            Self::Long => &["CvcvnoCvcvCvcv", "CvcvCvcvnoCvcv", "CvcvCvcvCvcvno", "CvccnoCvcvCvcv", "CvccCvcvnoCvcv", "CvccCvcvCvcvno", "CvcvnoCvccCvcv", "CvcvCvccnoCvcv", "CvcvCvccCvcvno", "CvcvnoCvcvCvcc", "CvcvCvcvnoCvcc", "CvcvCvcvCvccno", "CvccnoCvccCvcv", "CvccCvccnoCvcv", "CvccCvccCvcvno", "CvcvnoCvccCvcc", "CvcvCvccnoCvcc", "CvcvCvccCvccno", "CvccnoCvcvCvcc", "CvccCvcvnoCvcc", "CvccCvcvCvccno"],
            Self::Medium => &["CvcnoCvc", "CvcCvcno"],
            Self::Short => &["Cvcn"],
            Self::Basic => &["aaanaaan", "aannaaan", "aaannaaa"],
            Self::PIN => &["nnnn"]
        };
        templates[(seed[0] as usize % templates.len()) as usize]
    }
}

pub fn generate_site_password<S: AsRef<str>>(master_password: S, name: S, site_name: S, site_counter: u32, password_type: PasswordType) -> String {
    let master_key = generate_master_key(master_password, name);
    let template_seed = generate_template_seed(master_key, site_name, site_counter);
    let template = password_type.get_template(template_seed);
    let mut password = String::new();
    for (i, c) in template.chars().enumerate() {
        let password_char = match c {
            'V' => TEMPLATE_GROUP_V.as_bytes()[template_seed[i + 1] as usize % TEMPLATE_GROUP_V.len()],
            'C' => TEMPLATE_GROUP_C.as_bytes()[template_seed[i + 1] as usize % TEMPLATE_GROUP_C.len()],
            'v' => TEMPLATE_GROUP_v.as_bytes()[template_seed[i + 1] as usize % TEMPLATE_GROUP_v.len()],
            'c' => TEMPLATE_GROUP_c.as_bytes()[template_seed[i + 1] as usize % TEMPLATE_GROUP_c.len()],
            'A' => TEMPLATE_GROUP_A.as_bytes()[template_seed[i + 1] as usize % TEMPLATE_GROUP_A.len()],
            'a' => TEMPLATE_GROUP_a.as_bytes()[template_seed[i + 1] as usize % TEMPLATE_GROUP_a.len()],
            'n' => TEMPLATE_GROUP_n.as_bytes()[template_seed[i + 1] as usize % TEMPLATE_GROUP_n.len()],
            'o' => TEMPLATE_GROUP_o.as_bytes()[template_seed[i + 1] as usize % TEMPLATE_GROUP_o.len()],
            'x' => TEMPLATE_GROUP_x.as_bytes()[template_seed[i + 1] as usize % TEMPLATE_GROUP_x.len()],
            _ => continue
        };
        password.push(password_char as char);
    }
    password
}
