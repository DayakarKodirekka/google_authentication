use actix_files::Files;
use actix_identity::{Identity, IdentityMiddleware};
use actix_session::{storage::CookieSessionStore, config::PersistentSession, Session, SessionMiddleware};
use actix_web::{cookie::Key, get, web, App, HttpResponse, HttpServer, HttpRequest, Responder, HttpMessage};
use dotenv::dotenv;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env, fs::File, io::BufReader, sync::Arc};
use std::fmt;
use std::path::Path;
use urlencoding::encode;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert, ResolvesServerCertUsingSni};
use rustls::sign::CertifiedKey;
use rustls::crypto::aws_lc_rs::sign::any_supported_type;
use base64::{engine::general_purpose, Engine as _};

use rustls_pemfile;
use rustls::{ServerConfig};

#[derive(Deserialize, Debug)]
struct TokenResponse {
    access_token: String,
    // expires_in: i64,
    // refresh_token: Option<String>,
    // scope: String,
    // token_type: String,
    // id_token: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
struct GoogleUser {
    id: String,
    email: String,
    name: String,
    picture: Option<String>,
}

pub fn sensitive_config_folder_path() -> String {
    if env::consts::OS == "windows" { // On windows, use USERDOMAIN, instead of USERNAME, because USERNAME can be the same on multiple machines (e.g. "gyantal" on both GYANTAL-PC and GYANTAL-LAPTOP)
        let userdomain = env::var("USERDOMAIN").expect("Failed to get USERDOMAIN environment variable");
        match userdomain.as_str() {
            "GYANTAL-PC" => "h:/.shortcut-targets-by-id/0BzxkV1ug5ZxvVmtic1FsNTM5bHM/GDriveHedgeQuant/shared/GitHubRepos/NonCommitedSensitiveData/RqCore/".to_string(),
            "GYANTAL-LAPTOP" => "h:/.shortcut-targets-by-id/0BzxkV1ug5ZxvVmtic1FsNTM5bHM/GDriveHedgeQuant/shared/GitHubRepos/NonCommitedSensitiveData/RqCore/".to_string(),
            "BALAZS-PC" => "h:/.shortcut-targets-by-id/0BzxkV1ug5ZxvVmtic1FsNTM5bHM/GDriveHedgeQuant/shared/GitHubRepos/NonCommitedSensitiveData/RqCore/".to_string(),
            "BALAZS-LAPTOP" => "g:/.shortcut-targets-by-id/0BzxkV1ug5ZxvVmtic1FsNTM5bHM/GDriveHedgeQuant/shared/GitHubRepos/NonCommitedSensitiveData/RqCore/".to_string(),
            "DAYA-DESKTOP" => "g:/.shortcut-targets-by-id/0BzxkV1ug5ZxvVmtic1FsNTM5bHM/GDriveHedgeQuant/shared/GitHubRepos/NonCommitedSensitiveData/RqCore/".to_string(),
            "DAYA-LAPTOP" => "g:/.shortcut-targets-by-id/0BzxkV1ug5ZxvVmtic1FsNTM5bHM/GDriveHedgeQuant/shared/GitHubRepos/NonCommitedSensitiveData/RqCore/".to_string(),
            "DRCHARMAT-LAPTOP" => "c:/Agy/NonCommitedSensitiveData/RqCore/".to_string(),
            _ => panic!("Windows user name is not recognized. Add your username and folder here!"),
        }
    } else { // Linux and MacOS
        let username = env::var("LOGNAME").expect("Failed to get LOGNAME environment variable"); // when running in "screen -r" session, LOGNAME is set, but USER is not
        format!("/home/{}/RQ/sensitive_data/", username) // e.g. "/home/rquser/RQ/sensitive_data/https_certs";
    }
}

// SNI (Server Name Indication): the hostname sent by the client. Used for selecting HTTPS cert.
struct SniWithDefaultFallbackResolver {
    inner: ResolvesServerCertUsingSni, // the main SNI resolver
    default_ck: Arc<CertifiedKey>, // default certified key to use when no SNI match
}

impl fmt::Debug for SniWithDefaultFallbackResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SniWithDefault").finish()
    }
}

impl ResolvesServerCert for SniWithDefaultFallbackResolver {
    fn resolve(&self, ch: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.inner.resolve(ch).or_else(|| Some(self.default_ck.clone()))
    }
}


// ================================
//  Step 1: Redirect User to Google Login
// ================================
// This endpoint builds the Google OAuth2 consent screen URL and redirects
// the user to it. Once they log in and grant permission, Google redirects
// them back to /UserAccount/login/callback with an authorization code.

#[get("/UserAccount/login")]
async fn login(id: Option<Identity>, query: web::Query<HashMap<String, String>>) -> impl Responder {

    // If user is already loggedin redirect to returnUrl or home
    if let Some(_id) = id {
        let return_url = query.get("returnUrl").cloned().unwrap_or("/".to_string());
        return HttpResponse::Found()
            .append_header(("Location", return_url))
            .finish();
    }

    // Otherwise continue to Google OAuth
    let client_id = env::var("GOOGLE_CLIENT_ID").expect("Missing GOOGLE_CLIENT_ID");
    let redirect_uri = env::var("GOOGLE_REDIRECT_URI").expect("Missing GOOGLE_REDIRECT_URI");
    let return_url = query.get("returnUrl").cloned().unwrap_or("/".to_string());

    let scope = encode("https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile");
    let auth_url = format!("https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope={}&access_type=offline&prompt=consent&state={}",
        client_id, redirect_uri, scope, encode(&return_url));

    HttpResponse::Found()
        .append_header(("Location", auth_url))
        .finish()
}
// ================================
// Step 2: Handle Google Redirect Callback
// ================================
//
// Google sends the user back here with a temporary "code".
// We exchange that code for an access token, then fetch the user's profile.
// Finally, we store the session and issue a cookie using actix-identity.

#[get("/UserAccount/login/callback")]
async fn google_callback(
     req: HttpRequest,                     // Used for Identity::login()
    query: web::Query<HashMap<String, String>>, // Extract "code" query param
    session: Session,                     // Used to store session data
) -> impl Responder {
    // Ensure that the "code" parameter exists
    if let Some(code) = query.get("code") {
        // Load environment variables
        let client_id = env::var("GOOGLE_CLIENT_ID").unwrap();
        let client_secret = env::var("GOOGLE_CLIENT_SECRET").unwrap();
        let redirect_uri = env::var("GOOGLE_REDIRECT_URI").unwrap();
        // Step 1: Exchange authorization code for access token
        let client = Client::new();
        let params = [
            ("code", code.as_str()),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("grant_type", "authorization_code"),
        ];
        // Call Google OAuth2 token endpoint
        let token_resp = client
            .post("https://oauth2.googleapis.com/token")
            .form(&params)
            .send()
            .await
            .expect("Failed to get token")
            .json::<TokenResponse>()
            .await
            .expect("Failed to parse token response");
        // Step 2: Use the access token to fetch user profile
        let user_info = client
            .get("https://www.googleapis.com/oauth2/v2/userinfo")
            .bearer_auth(&token_resp.access_token)
            .send()
            .await
            .expect("Failed to get user info")
            .json::<GoogleUser>()
            .await
            .expect("Failed to parse user info");
        // Step 3: Store data in session (encrypted cookie)
        // This persists across requests and can be read later
        session.insert("user_email", &user_info.email).unwrap();
        session.insert("user_name", &user_info.name).unwrap();

        Identity::login(&req.extensions(), user_info.email.clone())
        .expect("Failed to create identity");

        let mut redirect_url = "/".to_string();
        // check if the query contains a "state" key
        if let Some(encoded) = query.get("state") {
            if let Ok(decoded) = urlencoding::decode(encoded) {
                redirect_url = decoded.into_owned(); //store the redirect target
            }
        }
        return HttpResponse::Found()
            .append_header(("Location", redirect_url))
            .finish();

    }
// If no code is provided (user declined or invalid request)
    HttpResponse::BadRequest().body("Missing code parameter")
}

#[get("/UserAccount/logout")]
async fn logout(id: Option<Identity>, session: Session) -> impl Responder {
    if let Some(identity) = id {
        identity.logout();
    }
    session.clear(); // Clear all session data
    // Redirect to /UserAccount/login
    let html = format!(
            "<html><body>
            You are not logged in : 
            <a href=\"/UserAccount/login\">Login</a>
            </body></html>"
        );
        HttpResponse::Ok().content_type("text/html").body(html)
}

#[get("/UserAccount/userinfo")]
async fn user_infor(session: Session) -> impl Responder {
    if let Ok(Some(email)) = session.get::<String>("user_email") {
        let name = session.get::<String>("user_name").unwrap_or(Some("Anonymous".to_string())).unwrap();
        let html = format!(
            "<html><body>
            Hello, {}!<br>
            Your email: {}<br>
            <a href=\"/UserAccount/logout\">Logout</a>
            </body></html>",
            name, email
        );
        HttpResponse::Ok().content_type("text/html").body(html)
    } else {
        HttpResponse::Unauthorized().body("Google Authorization Required. Please log in.")
    }
}

#[get("/UserAccount/authorized-sample")]
async fn authorized_sample(session: Session) -> impl Responder {
    let allowed_users = vec!["dayakar.kodirekka@gmail.com", "dayakarkodirekka2216@gmail.com"];

    if let Ok(Some(email)) = session.get::<String>("user_email") {
        if allowed_users.contains(&email.as_str()) {
            return HttpResponse::Ok().body(format!("You are authorized. Welcome, {}!", email));
        } else {
            return HttpResponse::Forbidden()
                .body(format!("Access denied. Your email ({}) is not authorized.", email));
        }
    }

    HttpResponse::Unauthorized().body("You are not logged in.")
}

// Custom root handler that serves different index based on login state
#[get("/")]
async fn root_index(id: Option<Identity>, session: Session) -> impl Responder {
    // check if user is logged in
    let is_logged_in = id.as_ref().is_some_and(|i| i.id().is_ok());
    // 1. Choose which file to serve
    let filename = if is_logged_in { "index.html" } else { "index_nouser.html" };
    let file_path = Path::new("./static").join(filename);

    // 2. Read the file content
    let mut html = match std::fs::read_to_string(&file_path) {
        Ok(content) => content,
        Err(_) => return HttpResponse::NotFound().body("File not found"),
    };

    // 3. If user is logged in give email + logout link
    if id.is_some() {
        if let Ok(Some(email)) = session.get::<String>("user_email") {
            let user_email = html_escape::encode_text(&email);

            let user_info_html = format!(
                r#"<div style="margin:20px 0; font-weight:bold; color:#2c3e50;">
                    {user_email} | <a href="/UserAccount/logout">Logout</a>
                   </div>"#
            );

            html = html.replace("</body>", &format!("{user_info_html}\n</body>")); // Insert before </body>
        }
    }

    // 4. Serve the modified HTML
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok(); // Load environment variables from .env file

    // let secret_key = Key::generate(); // Generate or load your encryption key
    let secret_key =  Key::from(&general_purpose::STANDARD.decode(env::var("APP_SECRET_KEY").unwrap()).expect("Invalid APP_SECRET_KEY"),);

    println!("Server running at: https://localhost:8080");
    // Load certificates and keys
    fn load_certs(filename: &str) -> Vec<CertificateDer<'static>> {
        let certfile = File::open(filename).expect(&format!("cannot open certificate file {}", filename));
        let mut reader = BufReader::new(certfile);
        rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>().expect(&format!("invalid certificate in file {}", filename))
    }
    // Load private keys
    fn load_private_key(filename: &str) -> PrivateKeyDer<'static> {
        let keyfile = File::open(filename).expect(&format!("cannot open private key file {}", filename));
        let mut reader = BufReader::new(keyfile);
        rustls_pemfile::private_key(&mut reader).expect(&format!("invalid private key in file {}", filename)).expect(&format!("no private key found in {}", filename))
    }
    
    let sensitive_config_folder_path = sensitive_config_folder_path();
    let cert_base_path = format!("{}https_certs/", sensitive_config_folder_path);
    let theta_certs = load_certs(&format!("{}thetaconite.com/fullchain.pem", cert_base_path));
    let theta_key = load_private_key(&format!("{}thetaconite.com/privkey.pem", cert_base_path));
    let theta_signing_key = any_supported_type(&theta_key).expect("unsupported thetaconite private key type");
    let theta_certified_key = CertifiedKey::new(theta_certs, theta_signing_key);

    // Default cert for 'localhost' and IP. Created as: openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout privkey.pem -out fullchain.pem -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,DNS:127.0.0.1"
    let default_certs = load_certs(&format!("{}localhost/fullchain.pem", cert_base_path));
    let default_key = load_private_key(&format!("{}localhost/privkey.pem", cert_base_path));
    let default_signing_key = any_supported_type(&default_key).expect("unsupported default key");
    let default_certified_key = CertifiedKey::new(default_certs, default_signing_key);

     // the SNI (Server Name Indication) hostname sent by the client
    // ResolvesServerCertUsingSni matches DNS hostnames, not IPs, and SNI itself is defined for hostnames (not addresses). 
    // So IP 127.0.0.1 won’t ever hit an entry in that resolver. We need a SniWithDefaultFallbackResolver to provide a default cert for IP connections.
    let mut sni_resolver = ResolvesServerCertUsingSni::new();
    // sni_resolver.add("rqcore.com", rq_certified_key.clone()).expect("Invalid DNS name for rqcore.com");
    // sni_resolver.add("www.rqcore.com", rq_certified_key.clone()).expect("Invalid DNS name for www.rqcore.com");
    sni_resolver.add("thetaconite.com", theta_certified_key.clone()).expect("Invalid DNS name for thetaconite.com");
    sni_resolver.add("localhost", default_certified_key.clone()).expect("Invalid localhost DNS name"); // default cert for localhost and IP e.g. 127.0.0.1

    let cert_resolver = Arc::new(SniWithDefaultFallbackResolver {
        inner: sni_resolver,
        default_ck: Arc::new(default_certified_key.clone()), // use the default (for 'localhost') for IP connections when no domain name sent by client
    });

    let tls_config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);

    // Curl Test
    // curl -v --resolve thetaconite.com:8080:127.0.0.1 --cookie "session=PASTE_YOUR_COOKIE_HERE" --insecure https://thetaconite.com:8080/UserAccount/userinfo
    // curl -v --resolve localhost:8080:127.0.0.1 --cookie "session=PASTE_YOUR_COOKIE_HERE" --insecure https://localhost:8080/UserAccount/userinfo
    HttpServer::new(move || {App::new()
        .wrap(IdentityMiddleware::default()) // Enables Identity API; identity is stored inside the session.
        .wrap(SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone()) // Uses an encrypted cookie to store the entire session.
        .session_lifecycle(PersistentSession::default() // Makes the cookie persistent (not deleted when browser closes).
        .session_ttl(actix_web::cookie::time::Duration::days(365))) // Session validity duration (365 days).
        .cookie_secure(true) // Cookie is only sent over HTTPS (required for SameSite=None).
        .cookie_http_only(true) // Cookie is not accessible from JavaScript (XSS protection).
        .cookie_name("session".to_string()) // Name of the session cookie.
        .cookie_same_site(actix_web::cookie::SameSite::None) // Required for Google OAuth redirects; allows cross-site cookies.
        .cookie_domain(None)
        .build())
        .service(login)
        .service(google_callback)
        .service(logout)
        .service(user_infor)
        .service(authorized_sample)
        .service(root_index)
        // .service(Files::new("/", "./static").index_file("index.html"))
        .service(Files::new("/", "./static").show_files_listing().use_last_modified(true))
    })
    .bind_rustls_0_23(format!("0.0.0.0:{}", 8080), tls_config)?
    .run()
    .await
}
