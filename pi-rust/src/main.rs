use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use log::{error, info};

use axum::{
    extract::State,
    http::Uri,
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use tokio::net::TcpListener;

type HmacSha1 = Hmac<Sha1>;

#[derive(Deserialize)]
struct Config {
    /// Hex-encoded HMAC key bytes (e.g. "deadbeef...")
    hmac_key_hex: String,
    /// Number of OTP digits (typically 6 or 8)
    otp_digits: u32,
    /// Display name shown in the web UI header
    otp_header: String,
    /// Path to the TLS certificate chain PEM file
    cert_path: String,
    /// Path to the TLS private key PEM file
    key_path: String,
    /// IP address to bind to (default: 0.0.0.0)
    bind_address: Option<String>,
    /// HTTPS port (default: 443)
    port: Option<u16>,
    /// HTTP port for redirect to HTTPS (default: 80; set to 0 to disable)
    http_port: Option<u16>,
    /// Directory for log files (default: /var/log/nakotp)
    log_dir: Option<String>,
}

struct AppState {
    hmac_key: Vec<u8>,
    otp_digits: u32,
    otp_header: String,
}

#[derive(Serialize)]
struct OtpResponse {
    code: String,
    expires_at: u64,
    header: String,
    digits: u32,
}

/// Compute the current TOTP code and the Unix timestamp at which it expires.
fn compute_totp(key: &[u8], digits: u32) -> (String, u64) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_secs();

    let time_step = now / 30;
    let expires_at = (time_step + 1) * 30;

    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&time_step.to_be_bytes());
    let hash = mac.finalize().into_bytes();

    // RFC 6238 dynamic truncation
    let offset = (hash[19] & 0x0f) as usize;
    let otp = ((hash[offset] & 0x7f) as u32) << 24
        | (hash[offset + 1] as u32) << 16
        | (hash[offset + 2] as u32) << 8
        | hash[offset + 3] as u32;

    let code = format!("{:0>width$}", otp % 10u32.pow(digits), width = digits as usize);
    (code, expires_at)
}

async fn handle_api_code(State(state): State<Arc<AppState>>) -> Json<OtpResponse> {
    let (code, expires_at) = compute_totp(&state.hmac_key, state.otp_digits);
    info!("GET /api/code → {}", code);
    Json(OtpResponse {
        code,
        expires_at,
        header: state.otp_header.clone(),
        digits: state.otp_digits,
    })
}

async fn handle_index(State(state): State<Arc<AppState>>) -> Html<String> {
    let (code, expires_at) = compute_totp(&state.hmac_key, state.otp_digits);
    info!("GET / → {}", code);
    Html(render_html(&state.otp_header, &code, expires_at))
}

fn render_html(header: &str, code: &str, expires_at: u64) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NakOTP</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: #0d1117;
      color: #e6edf3;
      font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
    }}
    .card {{
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 12px;
      padding: 2rem 3rem;
      text-align: center;
      min-width: 320px;
    }}
    .header {{
      font-size: 0.8rem;
      color: #8b949e;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      margin-bottom: 1.5rem;
    }}
    .code {{
      font-size: 3.5rem;
      font-weight: 700;
      letter-spacing: 0.3em;
      color: #58a6ff;
      margin-bottom: 1.5rem;
      transition: opacity 0.2s ease;
    }}
    .code.fading {{ opacity: 0.25; }}
    .progress-track {{
      background: #21262d;
      border-radius: 4px;
      height: 6px;
      margin-bottom: 0.5rem;
      overflow: hidden;
    }}
    .progress-fill {{
      height: 100%;
      background: #238636;
      border-radius: 4px;
      transition: width 1s linear, background 0.3s;
    }}
    .progress-fill.urgent {{ background: #da3633; }}
    .countdown {{
      font-size: 0.75rem;
      color: #8b949e;
    }}
  </style>
</head>
<body>
  <div class="card">
    <div class="header" id="header">{header}</div>
    <div class="code" id="code">{code}</div>
    <div class="progress-track">
      <div class="progress-fill" id="progress"></div>
    </div>
    <div class="countdown"><span id="seconds">--</span>s remaining</div>
  </div>
  <script>
    let expiresAt = {expires_at};
    let currentCode = document.getElementById('code').textContent;

    function updateDisplay() {{
      const now = Math.floor(Date.now() / 1000);
      const remaining = Math.max(0, expiresAt - now);
      const pct = (remaining / 30) * 100;

      document.getElementById('seconds').textContent = remaining;
      const fill = document.getElementById('progress');
      fill.style.width = pct + '%';
      fill.className = 'progress-fill' + (remaining <= 5 ? ' urgent' : '');

      if (remaining <= 1) {{
        fetchCode();
      }}
    }}

    async function fetchCode() {{
      try {{
        const resp = await fetch('/api/code');
        const data = await resp.json();
        const codeEl = document.getElementById('code');
        if (data.code !== currentCode) {{
          codeEl.classList.add('fading');
          await new Promise(r => setTimeout(r, 200));
          codeEl.textContent = data.code;
          currentCode = data.code;
          codeEl.classList.remove('fading');
        }}
        expiresAt = data.expires_at;
      }} catch (e) {{
        console.error('Failed to fetch code:', e);
      }}
    }}

    updateDisplay();
    setInterval(updateDisplay, 1000);
  </script>
</body>
</html>"#,
        header = header,
        code = code,
        expires_at = expires_at,
    )
}

fn init_logging(log_dir: &str) -> anyhow::Result<()> {
    use log::LevelFilter;
    use log4rs::{
        append::{
            console::ConsoleAppender,
            rolling_file::{
                policy::compound::{
                    roll::fixed_window::FixedWindowRoller, trigger::size::SizeTrigger,
                    CompoundPolicy,
                },
                RollingFileAppender,
            },
        },
        config::{Appender, Config, Root},
        encode::pattern::PatternEncoder,
    };

    let pattern = "{d(%Y-%m-%d %H:%M:%S %Z)} [{l:<5}] {t} — {m}{n}";

    let console = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(pattern)))
        .build();

    let log_file = format!("{log_dir}/nakotp.log");
    let archive_pattern = format!("{log_dir}/nakotp.log.{{}}.gz");

    let roller = FixedWindowRoller::builder().build(&archive_pattern, 4)?;
    let trigger = SizeTrigger::new(10 * 1024 * 1024); // 10 MB per file, 4 archives kept
    let policy = CompoundPolicy::new(Box::new(trigger), Box::new(roller));
    let file = RollingFileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(pattern)))
        .build(&log_file, Box::new(policy))?;

    let config = Config::builder()
        .appender(Appender::builder().build("console", Box::new(console)))
        .appender(Appender::builder().build("file", Box::new(file)))
        .build(
            Root::builder()
                .appender("console")
                .appender("file")
                .build(LevelFilter::Info),
        )?;

    log4rs::init_config(config)?;

    // Route axum's tracing events into the log crate so they appear in log4rs
    tracing_log::LogTracer::init()?;

    Ok(())
}

async fn handle_http_redirect(uri: Uri) -> impl IntoResponse {
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    Redirect::permanent(&format!("https://nakotp.nasbox.nakomis.com{path}"))
}

fn parse_hex_key(hex: &str) -> anyhow::Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        anyhow::bail!("hmac_key_hex must have an even number of hex characters");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("invalid hex at position {i}: {e}"))
        })
        .collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config_path = std::env::args()
        .skip_while(|a| a != "--config")
        .nth(1)
        .map(PathBuf::from)
        .or_else(|| {
            let local = PathBuf::from("config.toml");
            local.exists().then_some(local)
        })
        .unwrap_or_else(|| PathBuf::from("/etc/nakotp/config.toml"));

    let config_str = std::fs::read_to_string(&config_path)
        .map_err(|e| anyhow::anyhow!("could not read config {:?}: {e}", config_path))?;
    let config: Config = toml::from_str(&config_str)?;

    let log_dir = config.log_dir.as_deref().unwrap_or("/var/log/nakotp");
    if let Err(e) = init_logging(log_dir) {
        eprintln!("Warning: could not initialise file logging ({e}); falling back to stderr only");
        // Ensure we at least get output on stderr
        env_logger_fallback();
    }

    info!("nakotp starting (config: {})", config_path.display());

    let hmac_key = parse_hex_key(&config.hmac_key_hex)?;

    let state = Arc::new(AppState {
        hmac_key,
        otp_digits: config.otp_digits,
        otp_header: config.otp_header.clone(),
    });

    let bind_addr = config.bind_address.as_deref().unwrap_or("0.0.0.0");
    let https_port = config.port.unwrap_or(443);
    let http_port = config.http_port.unwrap_or(80);

    let app = Router::new()
        .route("/", get(handle_index))
        .route("/api/code", get(handle_api_code))
        .with_state(state);

    // Optional HTTP → HTTPS redirect server
    if http_port > 0 {
        let http_addr: SocketAddr = format!("{bind_addr}:{http_port}").parse()?;
        tokio::spawn(async move {
            let redirect_app = Router::new().fallback(handle_http_redirect);
            let listener = TcpListener::bind(http_addr).await.unwrap();
            info!("HTTP redirect listening on http://{http_addr}");
            axum::serve(listener, redirect_app).await.unwrap();
        });
    }

    let tls_config = RustlsConfig::from_pem_file(&config.cert_path, &config.key_path)
        .await
        .map_err(|e| {
            error!("Failed to load TLS certificates: {e}");
            e
        })?;

    let https_addr: SocketAddr = format!("{bind_addr}:{https_port}").parse()?;
    info!("HTTPS server listening on https://{https_addr}");

    axum_server::bind_rustls(https_addr, tls_config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

/// Minimal stderr-only logger used when log4rs fails to initialise (e.g. log
/// directory doesn't exist yet on a dev machine).
fn env_logger_fallback() {
    use log::LevelFilter;
    use log4rs::{
        append::console::ConsoleAppender,
        config::{Appender, Config, Root},
        encode::pattern::PatternEncoder,
    };
    let console = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{d(%H:%M:%S)} [{l:<5}] {m}{n}",
        )))
        .build();
    if let Ok(config) = Config::builder()
        .appender(Appender::builder().build("console", Box::new(console)))
        .build(Root::builder().appender("console").build(LevelFilter::Info))
    {
        let _ = log4rs::init_config(config);
    }
    let _ = tracing_log::LogTracer::init();
}
