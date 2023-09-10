
use serde::{Serialize, Deserialize};
use rsa::{RsaPrivateKey,pkcs1::DecodeRsaPrivateKey,sha2::Sha256};
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier};
use serde_json::json;
use base64::{encode_config, URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use jwt_compact::{prelude::*};
use log::*;
use std::collections::BTreeMap;
use jwt_compact::alg::Hs256;
use jwt_compact::alg::Hs256Key;
use std::io;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct CustomClaims {
        /// `sub` is a standard claim which denotes claim subject:
        /// https://tools.ietf.org/html/rfc7519#section-4.1.2
        #[serde(rename = "sub")]
        subject: String,
        #[serde(rename = "iss")]
        issuer: String,
        #[serde(rename = "aud")]
        audience: String,
        #[serde(rename = "exp")]
        expiration: i64,
        #[serde(flatten)]
        additional_claims: BTreeMap<String, String>,
    }
    
    impl CustomClaims {
        fn new(subject: &str, audience: &str,iss:&str, expiration: i64) -> Self {
            CustomClaims {
                subject: subject.to_owned(),
                issuer:iss.to_owned(),
                audience: audience.to_owned(),
                expiration,
                additional_claims: BTreeMap::new(),
            }
        }
    
        fn add_claim(&mut self, key: &str, value: &str) {
            self.additional_claims.insert(key.to_owned(), value.to_owned());
        }
    }

fn main() {
    let mut additional_claims:BTreeMap<String, String> = BTreeMap::new();
    additional_claims.insert("God1".to_string(),"JaiBajrangbali".to_string());
    additional_claims.insert("God2".to_string(),"HareKrishana".to_string());

    let hmac_token = generate_jwt_token(
        "HS256",
        "MySceretKey",
        "TokenCreateionDemo",
        "JaiShreeRam",
        3600,
        "JaiBajrangBali",
        additional_claims.clone());
    println!("hmac_token = {}",hmac_token.unwrap());
    println!("");

    let rsa_pkcs1_token = generate_jwt_token(
        "RS256-PKCS#1",
        "", // Secret key dont have any meaning in RSA
        "TokenCreateionDemo",
        "JaiShreeRam",
        3600,
        "JaiBajrangBali",
        additional_claims.clone());
    
    println!("rsa_pkcs1_token = {}",rsa_pkcs1_token.unwrap());
    println!("");

    let rsa_pkcs8_token = generate_jwt_token(
        "RS256-PKCS#8",
        "", // Secret key dont have any meaning in RSA
        "TokenCreateionDemo",
        "JaiShreeRam",
        3600,
        "JaiBajrangBali",
        additional_claims);
    
    println!("rsa_pkcs8_token = {}",rsa_pkcs8_token.unwrap());
    
}


pub fn generate_jwt_token(
    algorithm: &str,
    secret_key: &str,
    subject: &str,
    iss: &str,
    expires_in: i64,
    aud: &str,
    additional_claims: BTreeMap<String, String>) -> Result<String, Box<dyn std::error::Error>> {
        info!("generate_jwt_token entered");
        let token_string = String::new();
        let token = match algorithm {
            "HS256" => {
                println!("Enter the Secret key for Hmac");
                let mut secret_key = String::new();
                // Read input from the console
                io::stdin()
                    .read_line(&mut secret_key)
                    .expect("Failed to read input");

        // Trim any trailing whitespace or newline characters
            secret_key = secret_key.trim().to_string();
                create_hmac_token(
                    algorithm,
                    &secret_key,
                    subject,
                    iss,
                    expires_in,
                    aud,
                    additional_claims)
            },
            "RS256-PKCS#1" | 
            "RS256-PKCS#1.5" |
            "RS256-PKCS#8"=> {
                println!("For now RSA private key is hardcoaded");
                create_rsa_token(
                    algorithm,
                    subject,
                    iss,
                    expires_in,
                    aud,
                    additional_claims)
            },
            &_ => {
                debug!("Invalid algo");
                Err("Error: Token creation error - Invlid algo".into())
            }
        };
        token
    }

    fn create_hmac_token(algorithm: &str,
        secret_key: &str,
        sub: &str,
        iss: &str,
        expires_in: i64,
        aud: &str,
        additional_claims: BTreeMap<String, String>) -> Result<String, Box<dyn std::error::Error>> {
            // Choose time-related options for token creation / validation.
        let time_options = TimeOptions::default();
        // Create a symmetric HMAC key, which will be used both to create and verify tokens.
        let key = Hs256Key::new(secret_key.as_bytes());
        // Create a token.
        let header = Header::default();

        // Create custom claims.
        let mut custom_claims = CustomClaims::new(sub, aud, iss,expires_in);

        // Add additional claims to the custom claims struct.
        for (key, value) in additional_claims.iter() {
            custom_claims.add_claim(key, value);
        }

        let claims = Claims::new(custom_claims)
        .set_duration_and_issuance(&time_options, Duration::seconds(expires_in))
        .set_not_before(Utc::now() - Duration::hours(1));

        match Hs256.token(header.clone(), &claims, &key) {
            Ok(token) => {
                info!("Token = {}", token);
                Ok(token)
            }
            Err(_) => {
                info!("Token creation error");
                Err("Token creation error".into())
            }
        }
    }

    fn create_rsa_token(
        algorithm: &str,
        sub: &str,
        iss: &str,
        expires_in: i64,
        aud: &str,
        additional_claims: BTreeMap<String, String>)-> Result<String, Box<dyn std::error::Error>> {
        let rsa_key = create_rsa_key(algorithm);

        let time_options = TimeOptions::default();

        let mut custom_claims = Claims::new(CustomClaims::new(sub, aud, iss,expires_in))
            .set_duration_and_issuance(&time_options, Duration::seconds(expires_in))
            .set_not_before(Utc::now() - Duration::hours(1));

        // Add additional claims to the custom claims struct.
        for (key, value) in additional_claims.iter() {
            custom_claims.custom.add_claim(key, value);
        }

        let payload = serde_json::to_string(&custom_claims).unwrap();
        let encoded_payload = base64url_encode(payload.as_bytes());

        let header = serde_json::json!({"alg": "RS256","typ": "JWT"}).to_string();
        let encoded_header = base64url_encode(header.as_bytes());
        let header_payload = format!("{}.{}", encoded_header, encoded_payload);
        debug!("Header and Payload: {:#?}", header_payload);

        // Sign
        let mut rng = rand::thread_rng();
        let signature = rsa_key.signing_key.as_ref().expect("Signing Key has not been created").
            sign_with_rng(&mut rng, header_payload.as_bytes());
        assert_ne!(signature.to_bytes().as_ref(), header_payload.as_bytes());

        let encoded_signature = base64url_encode(&signature.to_bytes().as_ref());
        debug!("Signature: {:#?}", encoded_signature);

        let jwt = format!("{}.{}", header_payload, encoded_signature);
        debug!("JWT Token: {:#?}", jwt);
        
        Ok(jwt.to_string())
    }

    // Keys
    #[derive(Default, Clone)]
    pub struct CustomKeys {
        signing_key: Option<SigningKey<Sha256>>,
        verifying_key: Option<VerifyingKey<Sha256>>
    }

    fn base64url_encode(input: &[u8]) -> String {
        encode_config(input, URL_SAFE_NO_PAD)
    } 

    fn create_rsa_key(
        algorithm: &str) -> CustomKeys {

        let mut keys: CustomKeys = CustomKeys::default();
        if algorithm ==  "RS256-PKCS#1"  {
            info!("**************RsaPrivateKey-PKCS#1 **************");
            keys.signing_key = Some(RsaPrivateKey::from_pkcs1_pem(RSA_PKCS1_PRIVATE_KEY_2048).unwrap().into());
        } else if algorithm ==  "RS256-PKCS#1.5" ||
            algorithm == "RS256-PKCS#8" {
            keys.signing_key = Some(RsaPrivateKey::from_pkcs8_pem(RSA_PKCS8_PRIVATE_KEY_2048).unwrap().into());
        }
        keys
    }

    fn base64_url_encode(data: &str) -> String {
        let base64_url = data
            .chars()
            .map(|c| match c {
                '+' => '-',
                '/' => '_',
                '=' => ' ', // Omit the '=' character
                _ => c,
            })
            .collect::<String>()
            .replace(" ", ""); // Remove any remaining spaces (due to omitted '=')
        base64_url
    }

const RSA_2048_PKCS1_PRIV_PEM: &str = include_str!("rsa2048-pkcs1-priv.pem");
const RSA_2048_PKCS8_PRIV_PEM: &str = include_str!("rsa2048-pkcs8-priv.pem");

const RSA_PKCS1_PRIVATE_KEY_2048: &str = "\
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtsQsUV8QpqrygsY+2+JCQ6Fw8/omM71IM2N/R8pPbzbgOl0p
78MZGsgPOQ2HSznjD0FPzsH8oO2B5Uftws04LHb2HJAYlz25+lN5cqfHAfa3fgmC
38FfwBkn7l582UtPWZ/wcBOnyCgb3yLcvJrXyrt8QxHJgvWO23ITrUVYszImbXQ6
7YGS0YhMrbixRzmo2tpm3JcIBtnHrEUMsT0NfFdfsZhTT8YbxBvA8FdODgEwx7u/
vf3J9qbi4+Kv8cvqyJuleIRSjVXPsIMnoejIn04APPKIjpMyQdnWlby7rNyQtE4+
CV+jcFjqJbE/Xilcvqxt6DirjFCvYeKYl1uHLwIDAQABAoIBAH7Mg2LA7bB0EWQh
XiL3SrnZG6BpAHAM9jaQ5RFNjua9z7suP5YUaSpnegg/FopeUuWWjmQHudl8bg5A
ZPgtoLdYoU8XubfUH19I4o1lUXBPVuaeeqn6Yw/HZCjAbSXkVdz8VbesK092ZD/e
0/4V/3irsn5lrMSq0L322yfvYKaRDFxKCF7UMnWrGcHZl6Msbv/OffLRk19uYB7t
4WGhK1zCfKIfgdLJnD0eoI6Q4wU6sJvvpyTe8NDDo8HpdAwNn3YSahSewKp9gHgg
VIQlTZUdsHxM+R+2RUwJZYj9WSTbq+s1nKICUmjQBPnWbrPW963BE5utQPFt3mOe
EWRzdsECgYEA3MBhJC1Okq+u5yrFE8plufdwNvm9fg5uYUYafvdlQiXsFTx+XDGm
FXpuWhP/bheOh1jByzPZ1rvjF57xiZjkIuzcvtePTs/b5fT82K7CydDchkc8qb0W
2dI40h+13e++sUPKYdC9aqjZHzOgl3kOlkDbyRCF3F8mNDujE49rLWcCgYEA0/MU
dX5A6VSDb5K+JCNq8vDaBKNGU8GAr2fpYAhtk/3mXLI+/Z0JN0di9ZgeNhhJr2jN
11OU/2pOButpsgnkIo2y36cOQPf5dQpSgXZke3iNDld3osuLIuPNJn/3C087AtOq
+w4YxZClZLAxiLCqX8SBVrB2IiFCQ70SJ++n8vkCgYEAzmi3rBsNEA1jblVIh1PF
wJhD/bOQ4nBd92iUV8m9jZdl4wl4YX4u/IBI9MMkIG24YIe2VOl7s9Rk5+4/jNg/
4QQ2998Y6aljxOZJEdZ+3jQELy4m49OhrTRq2ta5t/Z3CMsJTmLe6f9NXWZpr5iK
8iVdHOjtMXxqfYaR2jVNEtsCgYAl9uWUQiAoa037v0I1wO5YQ9IZgJGJUSDWynsg
C4JtPs5zji4ASY+sCipsqWnH8MPKGrC8QClxMr51ONe+30yw78a5jvfbpU9Wqpmq
vOU0xJwnlH1GeMUcY8eMfOFocjG0yOtYeubvBIDLr0/AFzz9WHp+Z69RX7m53nUR
GDlyKQKBgDGZVAbUBiB8rerqNbONBAxfipoa4IJ+ntBrFT2DtoIZNbSzaoK+nVbH
kbWMJycaV5PVOh1lfAiZeWCxQz5RcZh/RS8USnxyMG1j4dP/wLcbdasI8uRaSC6Y
hFHL5HjhLrIo0HRWySS2b2ztBI2FP1M+MaaGFPHDzm2OyZg85yr3
-----END RSA PRIVATE KEY-----";



const RSA_PKCS1_PRIVATE_KEY_4096: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIJKQIBAAKCAgEAp6dFcoEeomF+Sehb1zDd4w8QP32I7j92XlQNPdmTu7C6FAAC
hZ0LQIl0NmN/WLgo6nTfgyFjQHf5nUqi1UyjdYUu9ZdmHTcTzh7ztP1qjiICOORn
ZoosfuOGHSISrmoevd+oi2LfEPa8957/SsKY+yVj3xuHZDga+bH7DM0IXgJrCtn2
chojUXfQOWtIdUrUp1JCJQqHO/L25+48dd1hPjZbpPMhCmzGa5Ci+j92LKaIQIe2
v4Fh6xRIGfD1cvIfbI4nPnDUWjZbiygZznNGE8wjsBMpoXkB8XB4QDhh9UxSoFHi
pYx1wtnYAJG7mAihBsH37LQDThUFi+7HJcX5GdYuqiNLYmKNNGxgu5GecIUdqzhX
Hm8O12NBKfmU6jaP7nNz397AREXrykf6IO0VQKhgyUi6vJjaWRyh3i4uJVQO+bfL
NT9gITuBSkXTWe+puBHu/wjGWZO/ioXCv+qqftXmtD4YrmBEZM5flhUBNufQn4sk
+tQ9eHARjPp7wkh1UG67wyG5d+CGGupQEoYgEh8LOUqc3QpCQRoTUMB3DZddcbAK
kENiQMlnoMOlwgoPbed/Pyyv2pTtAUPB9uNPc+DKwnnu63xjdyOisCbIKALhpK66
qIRt+Y55GUmHc+DU8xmVb03jqtAO+5oUfWazrBoB01ss+0jUALDnqA3JdVECAwEA
AQKCAgEAn+MJeyMiuQ+rZgbAF6CV6+ZAw5wQC87gLyOPoU2v846eV1aPESftRDYS
a5BGMbEn7Dlbs+4SfrgsiNJWKn+1X+2NFFC35OLS839XQmNvzG8omWNSLVtXBggs
rfoBwO6ZtNDpJ006mS4Gl0y+AWlGhjVpYqwZWf2b1EfluZaMBUPfG/E0dCrzRc2y
+h+TcbDUz2HGjRbWU9jpmdT9OhbPl4o1qkDoYM3OCWVd2LTPGdQUGx6SrV5RqOSl
wn+nRWEdkOSdDpKCIiq28SZkPhx3V4gW/OO5jzIdJUnylKRw34RTRGvzb5hd8l7Y
/en98wc/sncn30jp4fxwVrx4llCQt4UBJkBkYsglMFHvhONO48POuPlsZYw4vkVV
jS9k4p0iM1BVX8Hvoo7B9K+1ukCA8JqGzcNTjBrXyXLm16NhLmhFupr73xnwkGDR
p3neljXi0vjgxRC6JMbESzDJvfr4W+kXrsXUOvqxqjrdM8yD2pPKxpIY9qNutH8Z
nVQkyV/Z7Xsei+KuqmQzsickExbCDueSZQzrSL/WNERrGdKGtOoXIkmNoaNpcyEO
w4JHUaWAjZqu9ZxEnhmlB3z+yhJr2ajdSZZWHU4ns2Cf+CxbGyHmJ4RdRJYbM7h1
1cT6n/NX72vjNklp4TN8kbKaB7mpE83kDOLVUwyQDnN1FoXmVDECggEBANAhOnlC
W2ZbcZEYRIiT7DJ1YA9j2/hbd/To6Z7zAvboJZYEj23Kdy3mu/ESTbhLCv5hsDqG
BKsAee1T8zBHl60Bs4xE/ielpF43hIOoBLVqSpZ/SPAahm5yHmfkyaEEivaJJ/qk
PWqF2T579wdNunl1Y/yr4SMJt2ZTxtthTcIxzFVtnyWsSEGgLTHN8wFbISMH+dDH
n+tdOVbOU8yPoWUb5gdh8Z90ZySJ6vnyFUCfOZVud6ghg/H3K7L+3fG5+/xK2J6k
RYCd29W9WVJ3mQwL6TZvuy7PewV8wcPcj7d7+EVtB7vJWzwYFfSOYrgUaMPU2dls
D0jasEmTvo2R7eUCggEBAM42xoEFIqvl1kZfNusTfaO56kpfHSfGYUcp645eLly4
jj7xpHOiGUS2ZVez3CzkYuS/NEbLSZADflZysXBcuugbZbr5Z6Jm3Bjv6A9Nu/4a
WQYyBc4pQ8rfQhzOdK9wY/0ag688Oa+EUl9ZvcH/VIFfUq/R6NSGKyw2VPbPqD3A
jiqdUrn4M8ZGr3aURn38X31617RBiV/Lf/vtUmMksBVKFYI/UQfIlUjt3LYdpTCM
bMg01KDBbfpsodZ7YaZWd+sXGc0SXQ7w24gC+3bPwXV3vLJRCuKU4b+KkXOiuFwW
prUIyY8tdwt/PeSNnnIMU+JjaAtX5xCUEAFXRVcGUv0CggEAdItGzQPlXmmyLEdk
iP4b8x1azwNh965we4m42DLH5C6WbWzcS+Rl3CQp9ZIER0BuRYe6QOsuzfqUS9sI
gG52doBPZCp2DwloAwIfiAGbsWJ1pdRcqWaRBGOOtyqb5ThAAFFJO8agRXfx8FVG
PKa/1qdvd9tfVFlqgzhCUDIqcqWj/+pEhbn1NBpXdF4YxxeadJ1QvCIsYIVxSDR9
JD0BaTa4FkY4IMvzvbglBhUS5X7DpfOXuWQbGHEJ3U9uRJ+ahOn8ZskhyiWbJhLD
Y7Ro1SAOVVc3f7za7HWxotVs/JfErEujWvojxoDOOoVIrj9vcslLu74QyQD8WhcL
Swb+KQKCAQB1yk4LBp7uZ8PEwMCC+MgsjJbq0ne575RDbQuTb/K1neoKxEa2kmIy
oKk0tpVOw0pF9X3r7lTfwU8aHDuEvkM5L+UlLy9mUbDpQahhjXqTxAMUCeDNCT8j
E/IUuE1opR9IRSvxHcqpmkDfHEjLFojzuTpnGdUQCG+Cuqo/rRAh7eqHJwRJHCCe
4mN5rWqyrkTxTQkHeuP4Zyp9AeusnBlEn+O3WWl0s7uqQ8xt7nMcTyoYFi1aggLL
J+Atvp5hwESRccmYHSQw053ijCmNjVCpQ7LyfF5mXLqyiXlZ/xml6H5jLFjNwx+b
3pvBAK//31DPIQ8eY6CmFJ0r1ujRs9gVAoIBAQCMVXxINei0BmYGpdwlXbw+tfFY
bHMomIyOJCQD+Vde+w0oASwGNLckF2itciBJOCkG1jWvyx0qBb3/yAX+ZwOJt/qQ
1l+Ur7wgCNm8DTzO5CXfxyQCBQYDyfV57oUQ7MaTrG3TKDa24V49xSA2ahukr8kd
Pkik1nJMpCRD9IA+OxJjSwQ4Vy2OE7xy8agoU7jZ/KYZnXqQq2TZ5595OsKH+aGQ
EQgqUmjyCTMtVNmNbhkDCQf9nmuC7xJGd7oIrWeXpEIhPQl6NRxQoIko3XMtaymm
z2cG2vXyD3j4cXD7J5QDxSIbXlxwwrqg5ppy4NHzJn29jJvd/yivqS83yY02
-----END RSA PRIVATE KEY-----";

const RSA_PKCS8_PRIVATE_KEY_2048: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC2xCxRXxCmqvKC
xj7b4kJDoXDz+iYzvUgzY39Hyk9vNuA6XSnvwxkayA85DYdLOeMPQU/Owfyg7YHl
R+3CzTgsdvYckBiXPbn6U3lyp8cB9rd+CYLfwV/AGSfuXnzZS09Zn/BwE6fIKBvf
Ity8mtfKu3xDEcmC9Y7bchOtRVizMiZtdDrtgZLRiEytuLFHOaja2mbclwgG2ces
RQyxPQ18V1+xmFNPxhvEG8DwV04OATDHu7+9/cn2puLj4q/xy+rIm6V4hFKNVc+w
gyeh6MifTgA88oiOkzJB2daVvLus3JC0Tj4JX6NwWOolsT9eKVy+rG3oOKuMUK9h
4piXW4cvAgMBAAECggEAfsyDYsDtsHQRZCFeIvdKudkboGkAcAz2NpDlEU2O5r3P
uy4/lhRpKmd6CD8Wil5S5ZaOZAe52XxuDkBk+C2gt1ihTxe5t9QfX0jijWVRcE9W
5p56qfpjD8dkKMBtJeRV3PxVt6wrT3ZkP97T/hX/eKuyfmWsxKrQvfbbJ+9gppEM
XEoIXtQydasZwdmXoyxu/8598tGTX25gHu3hYaErXMJ8oh+B0smcPR6gjpDjBTqw
m++nJN7w0MOjwel0DA2fdhJqFJ7Aqn2AeCBUhCVNlR2wfEz5H7ZFTAlliP1ZJNur
6zWcogJSaNAE+dZus9b3rcETm61A8W3eY54RZHN2wQKBgQDcwGEkLU6Sr67nKsUT
ymW593A2+b1+Dm5hRhp+92VCJewVPH5cMaYVem5aE/9uF46HWMHLM9nWu+MXnvGJ
mOQi7Ny+149Oz9vl9PzYrsLJ0NyGRzypvRbZ0jjSH7Xd776xQ8ph0L1qqNkfM6CX
eQ6WQNvJEIXcXyY0O6MTj2stZwKBgQDT8xR1fkDpVINvkr4kI2ry8NoEo0ZTwYCv
Z+lgCG2T/eZcsj79nQk3R2L1mB42GEmvaM3XU5T/ak4G62myCeQijbLfpw5A9/l1
ClKBdmR7eI0OV3eiy4si480mf/cLTzsC06r7DhjFkKVksDGIsKpfxIFWsHYiIUJD
vRIn76fy+QKBgQDOaLesGw0QDWNuVUiHU8XAmEP9s5DicF33aJRXyb2Nl2XjCXhh
fi78gEj0wyQgbbhgh7ZU6Xuz1GTn7j+M2D/hBDb33xjpqWPE5kkR1n7eNAQvLibj
06GtNGra1rm39ncIywlOYt7p/01dZmmvmIryJV0c6O0xfGp9hpHaNU0S2wKBgCX2
5ZRCIChrTfu/QjXA7lhD0hmAkYlRINbKeyALgm0+znOOLgBJj6wKKmypacfww8oa
sLxAKXEyvnU4177fTLDvxrmO99ulT1aqmaq85TTEnCeUfUZ4xRxjx4x84WhyMbTI
61h65u8EgMuvT8AXPP1Yen5nr1FfubnedREYOXIpAoGAMZlUBtQGIHyt6uo1s40E
DF+Kmhrggn6e0GsVPYO2ghk1tLNqgr6dVseRtYwnJxpXk9U6HWV8CJl5YLFDPlFx
mH9FLxRKfHIwbWPh0//Atxt1qwjy5FpILpiEUcvkeOEusijQdFbJJLZvbO0EjYU/
Uz4xpoYU8cPObY7JmDznKvc=
-----END PRIVATE KEY-----";

const RSA_PKCS8_PRIVATE_KEY_FROM_JWTIO_2048: &str = "-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
dn/RsYEONbwQSjIfMPkvxF+8HQ==
-----END PRIVATE KEY-----";

const RSA_PKCS8_PUBLIC_KEY_FROM_JWTIO_2048: &str = "-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAtsQsUV8QpqrygsY+2+JCQ6Fw8/omM71IM2N/R8pPbzbgOl0p78MZ
GsgPOQ2HSznjD0FPzsH8oO2B5Uftws04LHb2HJAYlz25+lN5cqfHAfa3fgmC38Ff
wBkn7l582UtPWZ/wcBOnyCgb3yLcvJrXyrt8QxHJgvWO23ITrUVYszImbXQ67YGS
0YhMrbixRzmo2tpm3JcIBtnHrEUMsT0NfFdfsZhTT8YbxBvA8FdODgEwx7u/vf3J
9qbi4+Kv8cvqyJuleIRSjVXPsIMnoejIn04APPKIjpMyQdnWlby7rNyQtE4+CV+j
cFjqJbE/Xilcvqxt6DirjFCvYeKYl1uHLwIDAQAB
-----END RSA PUBLIC KEY-----";