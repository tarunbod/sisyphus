type MasterKey = [u8; 64];
type TemplateSeed = [u8; 32];

const TEMPLATE_GROUP_V: &'static str = "AEIOU";
const TEMPLATE_GROUP_C: &'static str = "BCDFGHJKLMNPQRSTVWXYZ";
const TEMPLATE_GROUP_v: &'static str = "aeiou";
const TEMPLATE_GROUP_c: &'static str = "bcdfghjklmnpqrstvwxyz";
const TEMPLATE_GROUP_A: &'static str = "AEIOUBCDFGHJKLMNPQRSTVWXYZ";
const TEMPLATE_GROUP_a: &'static str = "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz";
const TEMPLATE_GROUP_n: &'static str = "0123456789";
const TEMPLATE_GROUP_o: &'static str = "@&%?,=[]_:-+*$#!'^~;()/.";
const TEMPLATE_GROUP_x: &'static str = "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()";

fn generate_master_key<S: AsRef<str>>(master_password: S, name: S) -> MasterKey {
    let mut output = [0; 64];
    let salt = format!("com.lyndir.masterpassword{}{}", name.as_ref().len(), name.as_ref());
    scrypt::scrypt(
        master_password.as_ref().as_bytes(), // password
        salt.as_bytes(),
        &scrypt::Params::new(15, 8, 2).unwrap(),
        &mut output
    ).unwrap();
    output
}

fn generate_template_seed<S: AsRef<str>>(master_key: MasterKey, site_name: S, site_counter: u32) -> TemplateSeed {
    use hmac::Mac;

    type HmacSha256 = hmac::Hmac<sha2::Sha256>;
    let mut mac = HmacSha256::new_from_slice(&master_key).unwrap();
    let message = format!("com.lyndir.masterpassword{}{}{}", site_name.as_ref().len(), site_name.as_ref(), site_counter);
    mac.update(message.as_bytes());
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
    fn get_template(&self, seed: TemplateSeed) -> &'static str {
        match self {
            Self::MaximumSecurity => ["anoxxxxxxxxxxxxxxxxx", "axxxxxxxxxxxxxxxxxno"][(seed[0] % 2) as usize],
            Self::Long => {
                let templates = [
                    "CvcvnoCvcvCvcv",
                    "CvcvCvcvnoCvcv",
                    "CvcvCvcvCvcvno",
                    "CvccnoCvcvCvcv",
                    "CvccCvcvnoCvcv",
                    "CvccCvcvCvcvno",
                    "CvcvnoCvccCvcv",
                    "CvcvCvccnoCvcv",
                    "CvcvCvccCvcvno",
                    "CvcvnoCvcvCvcc",
                    "CvcvCvcvnoCvcc",
                    "CvcvCvcvCvccno",
                    "CvccnoCvccCvcv",
                    "CvccCvccnoCvcv",
                    "CvccCvccCvcvno",
                    "CvcvnoCvccCvcc",
                    "CvcvCvccnoCvcc",
                    "CvcvCvccCvccno",
                    "CvccnoCvcvCvcc",
                    "CvccCvcvnoCvcc",
                    "CvccCvcvCvccno",
                ];
                templates[(seed[0] % 21) as usize]
            },
            Self::Medium => ["CvcnoCvc", "CvcCvcno"][(seed[0] % 2) as usize],
            Self::Short => "Cvcn",
            Self::Basic => ["aaanaaan", "aannaaan", "aaannaaa"][(seed[0] % 3) as usize],
            Self::PIN => "nnnn"
        }
    }
}

pub fn generate_site_password<S: AsRef<str>>(master_password: S, name: S, site_name: S, site_counter: u32, password_type: PasswordType) -> String {
    let master_key = generate_master_key(master_password, name);
    let template_seed = generate_template_seed(master_key, site_name, site_counter);
    let template = password_type.get_template(template_seed);
    let mut password = String::new();
    for (i, c) in template.chars().enumerate() {
        let password_char = match c {
            'V' => TEMPLATE_GROUP_V.as_bytes()[(template_seed[i + 1] as usize % TEMPLATE_GROUP_V.len()) as usize],
            'C' => TEMPLATE_GROUP_C.as_bytes()[(template_seed[i + 1] as usize % TEMPLATE_GROUP_C.len()) as usize],
            'v' => TEMPLATE_GROUP_v.as_bytes()[(template_seed[i + 1] as usize % TEMPLATE_GROUP_v.len()) as usize],
            'c' => TEMPLATE_GROUP_c.as_bytes()[(template_seed[i + 1] as usize % TEMPLATE_GROUP_c.len()) as usize],
            'A' => TEMPLATE_GROUP_A.as_bytes()[(template_seed[i + 1] as usize % TEMPLATE_GROUP_A.len()) as usize],
            'a' => TEMPLATE_GROUP_a.as_bytes()[(template_seed[i + 1] as usize % TEMPLATE_GROUP_a.len()) as usize],
            'n' => TEMPLATE_GROUP_n.as_bytes()[(template_seed[i + 1] as usize % TEMPLATE_GROUP_n.len()) as usize],
            'o' => TEMPLATE_GROUP_o.as_bytes()[(template_seed[i + 1] as usize % TEMPLATE_GROUP_o.len()) as usize],
            'x' => TEMPLATE_GROUP_x.as_bytes()[(template_seed[i + 1] as usize % TEMPLATE_GROUP_x.len()) as usize],
            _ => continue
        };
        password.push(password_char as char);
    }
    println!("Done.");
    password
}