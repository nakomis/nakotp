use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use log::{error, info};

use axum::{
    extract::{Query, State},
    response::Html,
    routing::get,
    Json, Router,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use tokio::net::TcpListener;

type HmacSha1 = Hmac<Sha1>;

// ---------------------------------------------------------------------------
// Configuration (read from /etc/nakotp/config.toml)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AccountConfig {
    hmac_key_hex: String,
    otp_header: String,
    /// Number of OTP digits (typically 6 or 8; defaults to 6)
    #[serde(default = "default_digits")]
    otp_digits: u32,
}

fn default_digits() -> u32 {
    6
}

#[derive(Deserialize)]
struct Config {
    #[serde(rename = "account")]
    accounts: Vec<AccountConfig>,
    /// IP address to bind to (default: 127.0.0.1 — nginx proxies to us)
    bind_address: Option<String>,
    /// Port to listen on (default: 8766)
    port: Option<u16>,
    /// Directory for log files (default: /var/log/nakotp)
    log_dir: Option<String>,
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

struct Account {
    hmac_key: Vec<u8>,
    otp_header: String,
    otp_digits: u32,
}

struct AppState {
    accounts: Vec<Account>,
}

// ---------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct OtpResponse {
    header: String,
    code: String,
    expires_at: u64,
    digits: u32,
}

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

fn all_codes(state: &AppState) -> Vec<OtpResponse> {
    state
        .accounts
        .iter()
        .map(|acc| {
            let (code, expires_at) = compute_totp(&acc.hmac_key, acc.otp_digits);
            OtpResponse {
                header: acc.otp_header.clone(),
                code,
                expires_at,
                digits: acc.otp_digits,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn handle_bare(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<Vec<OtpResponse>> {
    let filter = params.get("account").map(|s| s.to_lowercase());
    let codes: Vec<OtpResponse> = all_codes(&state)
        .into_iter()
        .filter(|r| {
            filter
                .as_deref()
                .map(|f| r.header.to_lowercase().starts_with(f))
                .unwrap_or(true)
        })
        .collect();
    info!(
        "GET /bare{} → {} account(s)",
        filter.as_deref().map(|f| format!("?account={f}")).unwrap_or_default(),
        codes.len()
    );
    Json(codes)
}

async fn handle_index(State(state): State<Arc<AppState>>) -> Html<String> {
    let codes = all_codes(&state);
    info!("GET / → {} account(s)", codes.len());
    Html(render_html(&codes))
}

fn render_html(accounts: &[OtpResponse]) -> String {
    let cards: String = accounts
        .iter()
        .map(|acc| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let remaining = acc.expires_at.saturating_sub(now);
            let pct = (remaining as f64 / 30.0 * 100.0) as u64;
            let urgent = if remaining <= 5 { " urgent" } else { "" };
            format!(
                r#"<div class="card" data-header="{header}">
  <div class="acct-header">{header}</div>
  <div class="code">{code}</div>
  <div class="progress-track"><div class="progress-fill{urgent}" style="width:{pct}%"></div></div>
  <div class="countdown"><span class="seconds">{remaining}</span>s remaining</div>
</div>"#,
                header = acc.header,
                code = acc.code,
                urgent = urgent,
                pct = pct,
                remaining = remaining,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let init_data = serde_json::to_string(accounts).unwrap_or_else(|_| "[]".into());

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
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 2rem;
    }}
    .accounts {{
      display: flex;
      flex-wrap: wrap;
      gap: 1.5rem;
      justify-content: center;
      max-width: 900px;
      width: 100%;
    }}
    .card {{
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 12px;
      padding: 1.5rem 2rem;
      text-align: center;
      flex: 1 1 260px;
      max-width: 340px;
    }}
    .acct-header {{
      font-size: 0.8rem;
      color: #8b949e;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      margin-bottom: 1rem;
    }}
    .code {{
      font-size: 3rem;
      font-weight: 700;
      letter-spacing: 0.3em;
      color: #58a6ff;
      margin-bottom: 1rem;
      transition: opacity 0.2s ease;
    }}
    .code.fading {{ opacity: 0.25; }}
    .progress-track {{
      background: #21262d;
      border-radius: 4px;
      height: 6px;
      margin-bottom: 0.4rem;
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
      font-size: 0.7rem;
      color: #8b949e;
    }}
  </style>
</head>
<body>
  <div class="accounts" id="accounts">
    {cards}
  </div>
  <script>
    let accounts = {init_data};

    function cardEl(header) {{
      return document.querySelector(`.card[data-header="${{header}}"]`);
    }}

    function updateDisplay() {{
      const now = Math.floor(Date.now() / 1000);
      accounts.forEach(acc => {{
        const card = cardEl(acc.header);
        if (!card) return;
        const remaining = Math.max(0, acc.expires_at - now);
        const pct = (remaining / 30) * 100;
        card.querySelector('.seconds').textContent = remaining;
        const fill = card.querySelector('.progress-fill');
        fill.style.width = pct + '%';
        fill.className = 'progress-fill' + (remaining <= 5 ? ' urgent' : '');
        if (remaining <= 1) fetchCodes();
      }});
    }}

    async function fetchCodes() {{
      try {{
        const resp = await fetch('/bare');
        const data = await resp.json();
        data.forEach(acc => {{
          const existing = accounts.find(a => a.header === acc.header);
          if (existing && existing.code !== acc.code) {{
            const codeEl = cardEl(acc.header)?.querySelector('.code');
            if (codeEl) {{
              codeEl.classList.add('fading');
              setTimeout(() => {{
                codeEl.textContent = acc.code;
                codeEl.classList.remove('fading');
              }}, 200);
            }}
          }}
        }});
        accounts = data;
      }} catch (e) {{
        console.error('Failed to fetch codes:', e);
      }}
    }}

    updateDisplay();
    setInterval(updateDisplay, 1000);
  </script>
</body>
</html>"#,
        cards = cards,
        init_data = init_data,
    )
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

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
    let trigger = SizeTrigger::new(10 * 1024 * 1024);
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
    tracing_log::LogTracer::init()?;
    Ok(())
}

fn env_logger_fallback() {
    use log::LevelFilter;
    use log4rs::{
        append::console::ConsoleAppender,
        config::{Appender, Config, Root},
        encode::pattern::PatternEncoder,
    };
    let console = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{d(%H:%M:%S)} [{l:<5}] {m}{n}")))
        .build();
    if let Ok(config) = Config::builder()
        .appender(Appender::builder().build("console", Box::new(console)))
        .build(Root::builder().appender("console").build(LevelFilter::Info))
    {
        let _ = log4rs::init_config(config);
    }
    let _ = tracing_log::LogTracer::init();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

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
        env_logger_fallback();
    }

    info!(
        "nakotp starting — {} account(s) (config: {})",
        config.accounts.len(),
        config_path.display()
    );

    let accounts: Vec<Account> = config
        .accounts
        .iter()
        .map(|ac| {
            let hmac_key = parse_hex_key(&ac.hmac_key_hex)?;
            Ok(Account {
                hmac_key,
                otp_header: ac.otp_header.clone(),
                otp_digits: ac.otp_digits,
            })
        })
        .collect::<anyhow::Result<_>>()?;

    let state = Arc::new(AppState { accounts });

    let app = Router::new()
        .route("/", get(handle_index))
        .route("/bare", get(handle_bare))
        .with_state(state);

    // Bind to localhost by default — nginx is the public-facing TLS endpoint
    let bind_addr = config.bind_address.as_deref().unwrap_or("127.0.0.1");
    let port = config.port.unwrap_or(8766);
    let addr: SocketAddr = format!("{bind_addr}:{port}").parse()?;

    info!("Listening on http://{addr} (nginx proxies https://nakotp.nasbox.nakomis.com → here)");

    let listener = TcpListener::bind(addr).await.map_err(|e| {
        error!("Failed to bind to {addr}: {e}");
        e
    })?;

    axum::serve(listener, app).await?;

    Ok(())
}
