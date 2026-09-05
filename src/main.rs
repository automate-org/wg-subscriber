use std::collections::{HashMap, HashSet, VecDeque};
use std::env;
use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use blake3;
use if_addrs::get_if_addrs;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use log::{debug, error, info, warn};
use rand::Rng;
use rumqttc::{
    Client, ConnectReturnCode, Connection, Event, Incoming, MqttOptions, QoS, RecvTimeoutError,
    TlsConfiguration, Transport,
};
use rustls::ClientConfig;
use serde::Deserialize;
use serde_json::Value;
use signal_hook::consts::TERM_SIGNALS;
use signal_hook::iterator::Signals;
use tempfile::NamedTempFile;
use zstd::decode_all;

// ---------- 常量 ----------
const MAX_RETRY_QUEUE_SIZE: usize = 500;
const DEFAULT_MAX_RETRY_ATTEMPTS: u32 = 5;
const DEFAULT_LISTEN_PORT: u16 = 51822;
const DEFAULT_KEEPALIVE: u16 = 25;

const HANDSHAKE_MAX_AGE_SECS: u64 = 20;
const MIN_LAN_RETRY_INTERVAL: Duration = Duration::from_secs(120);

const NETWORK_CHECK_INTERVAL: Duration = Duration::from_secs(60);
const NO_HANDSHAKE_THRESHOLD: u64 = 180;
const PORT_CHANGE_LIMIT_WINDOW: Duration = Duration::from_secs(3600);
const MAX_PORT_CHANGES_PER_WINDOW: usize = 3;

const RELAY_FAIL_THRESHOLD: u64 = 180;
const RELAY_FAIL_COUNT_MAX: u32 = 2;

const TRAFFIC_REPORT_INTERVAL: Duration = Duration::from_secs(30);
const REGISTER_RETRY_INTERVAL: Duration = Duration::from_secs(5);
const REGISTER_MAX_RETRIES: u32 = 5;

const LAN_CHECK_INTERVAL: Duration = Duration::from_secs(1);

// ---------- 后端类型 ----------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backend {
    Kernel,
    Gotatun,
    AmneziaWG,
}

fn parse_backend() -> Result<Backend> {
    let s = env::var("WG_BACKEND")
        .map(|s| s.to_lowercase())
        .unwrap_or_else(|_| "kernel".to_string());
    match s.as_str() {
        "kernel" => Ok(Backend::Kernel),
        "gotatun" => Ok(Backend::Gotatun),
        "amneziawg" => Ok(Backend::AmneziaWG),
        other => bail!("Unsupported WG_BACKEND value '{}'", other),
    }
}

fn wg_cmd() -> &'static str {
    if env::var("WG_USE_AWG")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false)
    {
        "awg"
    } else {
        "wg"
    }
}

fn wg_interface_type() -> &'static str {
    if env::var("WG_USE_AWG")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false)
    {
        "amneziawg"
    } else {
        "wireguard"
    }
}

fn get_port_range() -> (u16, u16) {
    static PORT_RANGE: LazyLock<(u16, u16)> = LazyLock::new(|| {
        let min = env::var("WG_PORT_MIN")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1024);
        let max = env::var("WG_PORT_MAX")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(65535);
        if min > max {
            (max, min)
        } else {
            (min, max)
        }
    });
    *PORT_RANGE
}

// ---------- 全局状态 ----------
static LAST_LAN_ATTEMPT: LazyLock<Mutex<HashMap<String, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static PORT_CHANGE_HISTORY: LazyLock<Mutex<VecDeque<Instant>>> =
    LazyLock::new(|| Mutex::new(VecDeque::new()));
static USERSPACE_PROCESS: LazyLock<Mutex<Option<Child>>> = LazyLock::new(|| Mutex::new(None));
static LAST_APPLIED_ROUTES: LazyLock<Mutex<(HashSet<String>, HashSet<String>)>> =
    LazyLock::new(|| Mutex::new((HashSet::new(), HashSet::new())));
static RELAY_POOL: LazyLock<Mutex<Vec<String>>> = LazyLock::new(|| Mutex::new(Vec::new()));
static RELAY_LOAD: LazyLock<Mutex<HashMap<String, u32>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static PEER_TO_RELAY: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static PEER_FAIL_COUNT: LazyLock<Mutex<HashMap<String, u32>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static LAST_SNAPSHOT_PEERS: LazyLock<Mutex<HashMap<String, PeerInfo>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static RELAY_CIDR_V4: LazyLock<String> =
    LazyLock::new(|| env::var("RELAY_CIDR_V4").unwrap_or_else(|_| "10.254.1.0/24".to_string()));
static RELAY_CIDR_V6: LazyLock<String> =
    LazyLock::new(|| env::var("RELAY_CIDR_V6").unwrap_or_else(|_| "fd00:1:1::/64".to_string()));
static TRAFFIC_SNAPSHOT: LazyLock<Mutex<HashMap<String, (u64, u64)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static MISSING_SELF_COUNT: LazyLock<Mutex<u32>> = LazyLock::new(|| Mutex::new(0));
static REGISTRATION_STATE: LazyLock<Mutex<RegistrationState>> =
    LazyLock::new(|| Mutex::new(RegistrationState::NotRegistered));
static LAN_HANDSHAKE_WAIT_SECS: LazyLock<u64> = LazyLock::new(|| {
    env::var("LAN_HANDSHAKE_WAIT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8)
});

// LAN 验证任务队列
#[derive(Debug, Clone)]
struct LanVerificationTask {
    interface: String,
    pubkey: String,
    new_endpoint: String,
    fallback: Option<String>,
    start: Instant,
    timeout: Duration,
}

static LAN_VERIFICATION_TASKS: LazyLock<Mutex<Vec<LanVerificationTask>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

enum RegistrationState {
    NotRegistered,
    InProgress,
    Registered,
}

// ---------- 数据结构和配置 ----------
#[derive(Debug, Clone)]
struct RetryTask {
    pubkey: String,
    endpoint: Option<String>,
    allowed_ips: Option<Vec<String>>,
    persistent_keepalive: Option<u16>,
    preshared_key: Option<String>,
    retry_count: u32,
    last_attempt: Instant,
}

impl RetryTask {
    fn new(
        pubkey: String,
        endpoint: Option<String>,
        allowed_ips: Option<Vec<String>>,
        persistent_keepalive: Option<u16>,
        preshared_key: Option<String>,
    ) -> Self {
        Self {
            pubkey,
            endpoint,
            allowed_ips,
            persistent_keepalive,
            preshared_key,
            retry_count: 0,
            last_attempt: Instant::now(),
        }
    }
    fn next_interval(&self) -> Duration {
        Duration::from_secs(1u64 << self.retry_count.min(4))
    }
}

#[derive(Debug, Deserialize, Clone)]
struct AdvertisedRoutes {
    ipv4: Vec<String>,
    ipv6: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct FullSnapshot {
    peers: HashMap<String, PeerInfo>,
    routes: AdvertisedRoutes,
    #[serde(default)]
    amnezia: Option<AmneziaConfig>,
}

#[derive(Debug, Deserialize, Clone)]
struct PeerInfo {
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    allowed_ips: Option<Vec<String>>,
    #[serde(default)]
    persistent_keepalive: Option<u16>,
    #[serde(deserialize_with = "deserialize_psk")]
    preshared_key: Option<String>,
    #[serde(default)]
    local_ips: Option<Vec<String>>,
}

#[derive(Debug, Default, Clone)]
struct WgState {
    pub listen_port: u16,
    pub peers: HashMap<String, PeerState>,
}

#[derive(Debug, Default, Clone)]
struct PeerState {
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub latest_handshake: Option<u64>,
    pub transfer_rx: u64,
    pub transfer_tx: u64,
}

#[derive(Debug, Deserialize, Clone)]
struct AmneziaConfig {
    #[serde(default)]
    pub jc: u32,
    #[serde(default)]
    pub jmin: u32,
    #[serde(default)]
    pub jmax: u32,
    #[serde(default)]
    pub s1: u32,
    #[serde(default)]
    pub s2: u32,
    #[serde(default)]
    pub h1: u32,
    #[serde(default)]
    pub h2: u32,
    #[serde(default)]
    pub h3: u32,
    #[serde(default)]
    pub h4: u32,
    #[serde(default)]
    pub i1: Option<String>,
    #[serde(default)]
    pub i2: Option<String>,
    #[serde(default)]
    pub i3: Option<String>,
    #[serde(default)]
    pub i4: Option<String>,
    #[serde(default)]
    pub i5: Option<String>,
}

static WG_STATE_CACHE: LazyLock<Mutex<Option<(Instant, WgState)>>> =
    LazyLock::new(|| Mutex::new(None));

fn get_latest_hash() -> &'static Mutex<Option<blake3::Hash>> {
    static HASH: LazyLock<Mutex<Option<blake3::Hash>>> = LazyLock::new(|| Mutex::new(None));
    &HASH
}

/// 将 JSON 的 null 转为 Some("")（表示主动清除），字段缺失转为 None（表示保留现状）
fn deserialize_psk<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct PskVisitor;
    impl<'de> Visitor<'de> for PskVisitor {
        type Value = Option<String>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a string or null")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(Some(v.to_string()))
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            // null → Some("")  表示主动清除
            Ok(Some(String::new()))
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            // 字段缺失 → None  表示保留现状
            Ok(None)
        }

        fn visit_some<D2: serde::Deserializer<'de>>(
            self,
            deserializer: D2,
        ) -> Result<Self::Value, D2::Error> {
            deserializer.deserialize_any(self)
        }
    }

    deserializer.deserialize_option(PskVisitor)
}

// ---------- 工具: LAN 功能开关 ----------
fn is_lan_switching_enabled() -> bool {
    static ENABLED: LazyLock<bool> = LazyLock::new(|| {
        env::var("ENABLE_LAN_SWITCHING")
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false)
    });
    *ENABLED
}

// ---------- 工具: 指数退避计算 ----------
fn exponential_backoff(failures: u32) -> Duration {
    if failures == 0 {
        return Duration::from_secs(0);
    }
    let seconds = (1u64 << failures.min(6)).min(60);
    Duration::from_secs(seconds)
}

// ---------- TLS 传输 ----------
fn build_transport(_host: &str, _port: u16) -> Result<Transport> {
    let tls_enabled = env::var("MQTT_TLS_ENABLE")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    if !tls_enabled {
        return Ok(Transport::Tcp);
    }
    let mut root_store = rustls::RootCertStore::empty();
    if let Ok(ca_path) = env::var("MQTT_TLS_CA_CERT") {
        let ca_pem = fs::read_to_string(&ca_path)?;
        let mut reader = std::io::BufReader::new(ca_pem.as_bytes());
        let certs =
            rustls_pemfile::certs(&mut reader).context("Failed to parse PEM certificates")?;
        for cert_bytes in certs {
            let cert = rustls::pki_types::CertificateDer::from(cert_bytes);
            root_store
                .add(cert)
                .context("Failed to add CA certificate")?;
        }
    } else {
        let native_certs = rustls_native_certs::load_native_certs()
            .context("Failed to load native certificates")?;
        for cert in native_certs {
            let cert_der = rustls::pki_types::CertificateDer::from(cert.0);
            root_store
                .add(cert_der)
                .context("Failed to add native certificate")?;
        }
    }
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let tls_config = TlsConfiguration::Rustls(Arc::new(config));
    Ok(Transport::Tls(tls_config))
}

fn create_mqtt_connection(
    mqtt_host: String,
    mqtt_port: u16,
    mqtt_user: Option<String>,
    mqtt_pass: Option<String>,
    client_id: String,
) -> Result<(Client, Connection)> {
    let transport = build_transport(&mqtt_host, mqtt_port)?;
    let mut mqtt_options = MqttOptions::new(client_id, mqtt_host, mqtt_port);
    mqtt_options.set_keep_alive(Duration::from_secs(30));
    mqtt_options.set_transport(transport);
    mqtt_options.set_clean_session(false);
    if let (Some(user), Some(pass)) = (mqtt_user, mqtt_pass) {
        mqtt_options.set_credentials(user, pass);
    }
    let (client, connection) = Client::new(mqtt_options, 500);
    Ok((client, connection))
}

// ---------- 命令执行 ----------
fn run_cmd_with_timeout(cmd: &mut Command, timeout: Duration) -> Result<String> {
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let start = Instant::now();
    loop {
        match child.try_wait()? {
            Some(status) => {
                let output = child.wait_with_output()?;
                if status.success() {
                    return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
                } else {
                    bail!(
                        "Command failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
            None if start.elapsed() >= timeout => {
                child.kill()?;
                bail!("Command timed out after {:?}", timeout);
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn get_wg_state(interface: &str) -> Result<WgState> {
    let output = Command::new(wg_cmd())
        .args(["show", interface, "dump"])
        .output()
        .context("Failed to execute wg show dump")?;
    if !output.status.success() {
        bail!(
            "wg show dump failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8(output.stdout).context("Dump output is not valid UTF-8")?;
    let mut state = WgState::default();
    let mut lines = stdout.lines();
    if let Some(iface_line) = lines.next() {
        let parts: Vec<&str> = iface_line.split('\t').collect();
        if parts.len() >= 3 {
            state.listen_port = parts[2].parse().unwrap_or(DEFAULT_LISTEN_PORT);
        }
    }
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 8 {
            continue;
        }
        let pubkey = parts[0].to_string();
        let endpoint = if parts[2] == "(none)" || parts[2].is_empty() {
            None
        } else {
            Some(parts[2].to_string())
        };
        let allowed_ips: Vec<String> = parts[3]
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        let latest_handshake = if parts[4] == "0" {
            None
        } else {
            parts[4].parse::<u64>().ok()
        };
        let transfer_rx = parts[5].parse::<u64>().unwrap_or(0);
        let transfer_tx = parts[6].parse::<u64>().unwrap_or(0);
        state.peers.insert(
            pubkey,
            PeerState {
                endpoint,
                allowed_ips,
                latest_handshake,
                transfer_rx,
                transfer_tx,
            },
        );
    }
    Ok(state)
}

fn get_latest_wg_state(interface: &str, cache: &mut Option<(Instant, WgState)>) -> Result<WgState> {
    let ttl = Duration::from_secs(
        env::var("WG_STATE_CACHE_TTL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2),
    );
    if let Some((ref ts, ref state)) = cache {
        if ts.elapsed() < ttl {
            return Ok(state.clone());
        }
    }
    let state = get_wg_state(interface)?;
    *cache = Some((Instant::now(), state.clone()));
    Ok(state)
}

// ---------- WG 接口管理 ----------
fn interface_exists(interface: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", interface])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn get_userspace_backend_command(backend: Backend) -> Result<Vec<String>> {
    if let Ok(cmd) = env::var("WG_USERSPACE_CMD") {
        let parts = shlex::split(&cmd).unwrap_or_else(|| vec![cmd]);
        if parts.is_empty() {
            bail!("WG_USERSPACE_CMD is set but empty");
        }
        Ok(parts)
    } else {
        let backend_name = match backend {
            Backend::Gotatun => "gotatun",
            Backend::AmneziaWG => "amneziawg",
            _ => unreachable!(),
        };
        bail!(
            "WG_BACKEND is set to '{}' but WG_USERSPACE_CMD is not defined.\n\
Please set WG_USERSPACE_CMD to the full command line of your userspace backend.",
            backend_name
        );
    }
}

fn create_kernel_interface(interface: &str) -> Result<()> {
    let status = Command::new("ip")
        .args(["link", "add", interface, "type", wg_interface_type()])
        .status()
        .context("Failed to create kernel WireGuard interface")?;
    if !status.success() {
        bail!("ip link add failed");
    }
    thread::sleep(Duration::from_millis(50));
    info!("Created kernel interface {}", interface);
    Ok(())
}

fn start_userspace_backend(interface: &str, backend: Backend) -> Result<()> {
    let mut cmd_parts = get_userspace_backend_command(backend)?;
    cmd_parts.push(interface.to_string());
    let (prog, args) = cmd_parts.split_first().unwrap();
    let mut cmd = Command::new(prog);
    cmd.args(args);
    let rust_log = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    cmd.env(
        "WG_LOG_LEVEL",
        &rust_log
            .split(&[',', ';'][..])
            .next()
            .unwrap_or("info")
            .to_lowercase(),
    );
    let child = cmd
        .spawn()
        .with_context(|| format!("Failed to start userspace backend '{}'", prog))?;
    *USERSPACE_PROCESS.lock().unwrap() = Some(child);
    let start = Instant::now();
    while !interface_exists(interface) && start.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(200));
    }
    if !interface_exists(interface) {
        bail!("Userspace backend did not create interface in time");
    }
    for attempt in 1..=10 {
        let output = Command::new(wg_cmd()).arg("show").arg(interface).output();
        if let Ok(out) = output {
            if out.status.success() {
                info!("wg show {} succeeded after {} attempts", interface, attempt);
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(200 * (1 << attempt.min(4))));
    }
    bail!("wg show {} still failing", interface);
}

fn cleanup_userspace_backend(backend: Backend) {
    let interface = env::var("WG_INTERFACE").unwrap_or_else(|_| "wg0".to_string());

    if matches!(backend, Backend::Gotatun | Backend::AmneziaWG) {
        if let Ok(state) = get_wg_state(&interface) {
            for pubkey in state.peers.keys() {
                let _ = Command::new(wg_cmd())
                    .args(["set", &interface, "peer", pubkey, "remove"])
                    .status();
            }
            info!("Removed all peers from {} before cleanup", interface);
        }

        if let Some(mut child) = USERSPACE_PROCESS.lock().unwrap().take() {
            let _ = child.kill();
            let _ = child.wait();
            thread::sleep(Duration::from_millis(100));
        }

        if interface_exists(&interface) {
            let status = Command::new("ip")
                .args(["link", "delete", &interface])
                .status();
            match status {
                Ok(s) if s.success() => info!("Deleted interface {}", interface),
                Ok(s) => warn!(
                    "Failed to delete interface {}, exit code: {:?}",
                    interface,
                    s.code()
                ),
                Err(e) => error!("Failed to run ip link delete: {}", e),
            }
        }
    }
}

fn generate_and_save_private_key(key_path: &str) -> Result<String> {
    let privkey_output = Command::new(wg_cmd())
        .arg("genkey")
        .output()
        .context("Failed to generate WireGuard private key")?;
    let privkey = String::from_utf8(privkey_output.stdout)
        .context("Invalid UTF-8")?
        .trim()
        .to_string();
    if let Some(parent) = Path::new(key_path).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(key_path, &privkey)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(key_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(key_path, perms)?;
    }
    info!("Generated and saved new private key to {}", key_path);
    Ok(privkey)
}

fn ensure_wireguard_interface(interface: &str, backend: Backend) -> Result<()> {
    if interface_exists(interface) {
        debug!("WireGuard interface {} already exists", interface);
        let listen_port = env::var("WG_LISTEN_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_LISTEN_PORT);
        let _ = Command::new(wg_cmd())
            .args(["set", interface, "listen-port", &listen_port.to_string()])
            .status();
        return Ok(());
    }
    info!("WireGuard interface {} not found, creating...", interface);
    let key_dir = "/etc/wireguard";
    let key_path = format!("{}/{}.key", key_dir, interface);
    let _privkey = if Path::new(&key_path).exists() {
        let existing = fs::read_to_string(&key_path)?;
        let key = existing.trim().to_string();
        if key.is_empty() {
            generate_and_save_private_key(&key_path)?
        } else {
            info!("Using existing private key from {}", key_path);
            key
        }
    } else {
        generate_and_save_private_key(&key_path)?
    };

    match backend {
        Backend::Kernel => create_kernel_interface(interface)?,
        Backend::Gotatun | Backend::AmneziaWG => start_userspace_backend(interface, backend)?,
    }

    Command::new(wg_cmd())
        .args(["set", interface, "private-key", &key_path])
        .status()
        .context("Failed to set private key")?;
    let listen_port = env::var("WG_LISTEN_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_LISTEN_PORT);
    let status = Command::new(wg_cmd())
        .args(["set", interface, "listen-port", &listen_port.to_string()])
        .status()
        .context("Failed to set listen port")?;
    if !status.success() {
        bail!("wg set listen-port failed");
    }
    Command::new("ip")
        .args(["link", "set", "up", interface])
        .status()
        .context("Failed to bring up interface")?;
    info!("WireGuard interface {} initialized", interface);
    Ok(())
}

fn get_local_public_key(interface: &str) -> Result<String> {
    let output = Command::new(wg_cmd())
        .arg("show")
        .arg(interface)
        .arg("public-key")
        .output()
        .context("Failed to execute wg show public-key")?;
    if !output.status.success() {
        bail!(
            "wg show public-key failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let pubkey = String::from_utf8(output.stdout)
        .context("Invalid UTF-8")?
        .trim()
        .to_string();
    if pubkey.is_empty() {
        bail!("Empty public key");
    }
    Ok(pubkey)
}

// ---------- 工具函数 ----------
fn get_current_peers(state: &WgState) -> HashSet<String> {
    state.peers.keys().cloned().collect()
}
fn get_current_endpoint(state: &WgState, pubkey: &str) -> Option<String> {
    state.peers.get(pubkey).and_then(|p| p.endpoint.clone())
}
fn has_recent_handshake(state: &WgState, pubkey: &str, max_age_secs: u64) -> bool {
    if let Some(ts) = state.peers.get(pubkey).and_then(|p| p.latest_handshake) {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        return now_secs.saturating_sub(ts) <= max_age_secs;
    }
    false
}
fn is_lan_active(state: &WgState, pubkey: &str, endpoint: &str) -> bool {
    if !is_lan_switching_enabled() {
        return false;
    }
    if let Some((ip, _)) = parse_endpoint(endpoint) {
        let my_nets = get_local_lan_networks();
        let is_lan = my_nets.iter().any(|net| net.contains(&ip));
        let has_recent = has_recent_handshake(state, pubkey, HANDSHAKE_MAX_AGE_SECS);
        return is_lan && has_recent;
    }
    false
}
fn get_wg_latest_handshakes(state: &WgState) -> HashMap<String, Option<u64>> {
    state
        .peers
        .iter()
        .map(|(k, v)| (k.clone(), v.latest_handshake))
        .collect()
}
fn get_current_allowed_ips(state: &WgState, pubkey: &str) -> Result<Vec<String>> {
    state
        .peers
        .get(pubkey)
        .map(|p| p.allowed_ips.clone())
        .ok_or_else(|| anyhow::anyhow!("Peer {} not found in state", pubkey))
}
fn first_tunnel_ip(allowed_ips: &[String]) -> Option<String> {
    allowed_ips
        .first()
        .and_then(|cidr| cidr.split('/').next())
        .map(|s| s.to_string())
}

/// 获取接口上所有 scope global 的 IPv4 和 IPv6 地址（CIDR 格式）
fn get_interface_cidrs(interface: &str) -> Result<(Vec<String>, Vec<String>)> {
    let output = Command::new("ip")
        .args(["-o", "addr", "show", "dev", interface, "scope", "global"])
        .output()
        .context("Failed to get interface addresses")?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut v4 = Vec::new();
    let mut v6 = Vec::new();

    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        if parts[2] == "inet" {
            v4.push(parts[3].to_string());
        } else if parts[2] == "inet6" {
            v6.push(parts[3].to_string());
        }
    }
    Ok((v4, v6))
}

fn configure_self_ip(interface: &str, ipv4: &str, ipv6: &str) {
    let current = match get_interface_cidrs(interface) {
        Ok(c) => c,
        Err(e) => {
            warn!(
                "Cannot read interface addresses: {}, falling back to add only",
                e
            );
            if !ipv4.is_empty() {
                let _ = Command::new("ip")
                    .args(["addr", "add", ipv4, "dev", interface])
                    .status();
            }
            if !ipv6.is_empty() {
                let _ = Command::new("ip")
                    .args(["-6", "addr", "add", ipv6, "dev", interface])
                    .status();
            }
            return;
        }
    };
    let (current_v4, current_v6) = current;

    // IPv4
    if ipv4.is_empty() {
        for cidr in &current_v4 {
            let _ = Command::new("ip")
                .args(["addr", "del", cidr.as_str(), "dev", interface])
                .status();
            info!("Removed IPv4 address {} from {}", cidr, interface);
        }
    } else {
        let target_ip = ipv4.split('/').next().unwrap_or(ipv4);
        let target_cidr = format!("{}/32", target_ip);
        let mut found = false;

        for cidr in &current_v4 {
            let existing_ip = cidr.split('/').next().unwrap_or(cidr);
            if existing_ip == target_ip {
                found = true;
                if cidr.as_str() != target_cidr {
                    let _ = Command::new("ip")
                        .args(["addr", "del", cidr.as_str(), "dev", interface])
                        .status();
                    let _ = Command::new("ip")
                        .args(["addr", "add", &target_cidr, "dev", interface])
                        .status();
                    info!(
                        "Corrected IPv4 prefix on {} from {} to {}",
                        interface, cidr, target_cidr
                    );
                } else {
                    debug!("IPv4 address {} already correct, keeping", cidr);
                }
            } else {
                let _ = Command::new("ip")
                    .args(["addr", "del", cidr.as_str(), "dev", interface])
                    .status();
                info!("Removed stray IPv4 address {} from {}", cidr, interface);
            }
        }

        if !found {
            let _ = Command::new("ip")
                .args(["addr", "add", &target_cidr, "dev", interface])
                .status();
            info!("Added IPv4 address {} to {}", target_cidr, interface);
        }
    }

    // IPv6
    if ipv6.is_empty() {
        for cidr in &current_v6 {
            let _ = Command::new("ip")
                .args(["-6", "addr", "del", cidr.as_str(), "dev", interface])
                .status();
            info!("Removed IPv6 address {} from {}", cidr, interface);
        }
    } else {
        let target_ip = ipv6.split('/').next().unwrap_or(ipv6);
        let target_cidr = format!("{}/128", target_ip);
        let mut found = false;

        for cidr in &current_v6 {
            let existing_ip = cidr.split('/').next().unwrap_or(cidr);
            if existing_ip == target_ip {
                found = true;
                if cidr.as_str() != target_cidr {
                    let _ = Command::new("ip")
                        .args(["-6", "addr", "del", cidr.as_str(), "dev", interface])
                        .status();
                    let _ = Command::new("ip")
                        .args(["-6", "addr", "add", &target_cidr, "dev", interface])
                        .status();
                    info!(
                        "Corrected IPv6 prefix on {} from {} to {}",
                        interface, cidr, target_cidr
                    );
                } else {
                    debug!("IPv6 address {} already correct, keeping", cidr);
                }
            } else {
                let _ = Command::new("ip")
                    .args(["-6", "addr", "del", cidr.as_str(), "dev", interface])
                    .status();
                info!("Removed stray IPv6 address {} from {}", cidr, interface);
            }
        }

        if !found {
            let _ = Command::new("ip")
                .args(["-6", "addr", "add", &target_cidr, "dev", interface])
                .status();
            info!("Added IPv6 address {} to {}", target_cidr, interface);
        }
    }
}

fn extract_self_ips(allowed_ips: &[String]) -> (String, String) {
    let mut ipv4 = String::new();
    let mut ipv6 = String::new();
    for cidr in allowed_ips {
        let (ip_str, prefix) = match cidr.split_once('/') {
            Some((ip, p)) => (ip, p.parse::<u8>().unwrap_or(0)),
            None => (cidr.as_str(), 32),
        };
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(_) if prefix == 32 && ipv4.is_empty() => ipv4 = cidr.clone(),
                IpAddr::V6(_) if prefix == 128 && ipv6.is_empty() => ipv6 = cidr.clone(),
                _ => {}
            }
        }
    }
    (ipv4, ipv6)
}

fn trigger_handshake_udp(peer_tunnel_ip: &str) {
    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        let _ = sock.send_to(&[], format!("{}:1", peer_tunnel_ip));
        debug!("Sent UDP handshake trigger to {}", peer_tunnel_ip);
    }
}

// ---------- 对等体管理 ----------
fn add_or_update_peer(
    interface: &str,
    pubkey: &str,
    endpoint: Option<&str>,
    allowed_ips: Option<&[String]>,
    keepalive_opt: Option<u16>,
    preshared_key: Option<&str>,
    state: &WgState,
) -> Result<()> {
    let mut is_new = !state.peers.contains_key(pubkey);
    if !is_new && preshared_key == Some("") {
        remove_peer(interface, pubkey)?;
        is_new = true;
    }
    let final_allowed_ips = if is_new {
        match allowed_ips {
            Some(ips) if !ips.is_empty() => ips.to_vec(),
            _ => state
                .peers
                .get(pubkey)
                .map(|p| p.allowed_ips.clone())
                .unwrap_or_default(),
        }
    } else {
        allowed_ips.map(|v| v.to_vec()).unwrap_or_default()
    };
    if final_allowed_ips.is_empty() {
        bail!("Cannot add peer {} without allowed_ips", pubkey);
    }
    let final_keepalive = if is_new {
        Some(keepalive_opt.unwrap_or(DEFAULT_KEEPALIVE))
    } else {
        keepalive_opt
    };
    let mut args = vec![
        "set".to_string(),
        interface.to_string(),
        "peer".to_string(),
        pubkey.to_string(),
    ];
    let _temp_file = if let Some(psk) = preshared_key {
        if psk.is_empty() {
            None
        } else {
            let mut temp_file = NamedTempFile::new()?;
            temp_file.write_all(psk.as_bytes())?;
            temp_file.flush()?;
            args.push("preshared-key".to_string());
            args.push(temp_file.path().to_string_lossy().to_string());
            Some(temp_file)
        }
    } else {
        None
    };
    if let Some(ka) = final_keepalive {
        args.push("persistent-keepalive".to_string());
        args.push(ka.to_string());
    }
    if let Some(ep) = endpoint {
        args.push("endpoint".to_string());
        args.push(ep.to_string());
    }
    args.push("allowed-ips".to_string());
    args.push(final_allowed_ips.join(","));
    let mut cmd = Command::new(wg_cmd());
    cmd.args(&args).stdin(Stdio::null());
    run_cmd_with_timeout(&mut cmd, Duration::from_secs(10)).context("Failed to execute wg set")?;
    info!(
        "Applied peer {}: endpoint={:?}, allowed_ips={:?}, keepalive={:?}, psk={}, new={}",
        pubkey,
        endpoint,
        Some(&final_allowed_ips),
        final_keepalive,
        preshared_key.is_some(),
        is_new
    );
    if is_new {
        if let Some(ip) = first_tunnel_ip(&final_allowed_ips) {
            trigger_handshake_udp(&ip);
        }
    }
    Ok(())
}

fn remove_peer(interface: &str, pubkey: &str) -> Result<()> {
    let mut cmd = Command::new(wg_cmd());
    cmd.args(["set", interface, "peer", pubkey, "remove"])
        .stdin(Stdio::null());
    run_cmd_with_timeout(&mut cmd, Duration::from_secs(10)).context("Failed to remove peer")?;
    info!("Removed peer {}", pubkey);
    Ok(())
}

fn batch_restore_peers(
    interface: &str,
    config: &[(&String, &PeerInfo)],
    local_pubkey: &str,
) -> Result<Vec<String>> {
    if config.is_empty() {
        return Ok(vec![]);
    }

    let mut conf_lines = vec!["[Interface]".to_string(), "".to_string()];
    let mut clear_psk_peers = Vec::new();

    for (pubkey, peer) in config {
        if *pubkey == local_pubkey {
            continue;
        }
        conf_lines.push("[Peer]".to_string());
        conf_lines.push(format!("PublicKey = {}", pubkey));

        match &peer.preshared_key {
            Some(psk) if !psk.is_empty() => {
                conf_lines.push(format!("PresharedKey = {}", psk));
            }
            Some(psk) if psk.is_empty() => {
                clear_psk_peers.push((*pubkey).clone());
            }
            _ => {
                // None 或其它：不清除 PSK，保留现状
            }
        }

        if let Some(ka) = peer.persistent_keepalive {
            conf_lines.push(format!("PersistentKeepalive = {}", ka));
        }
        if let Some(ep) = &peer.endpoint {
            conf_lines.push(format!("Endpoint = {}", ep));
        }
        if let Some(ips) = &peer.allowed_ips {
            if !ips.is_empty() {
                conf_lines.push(format!("AllowedIPs = {}", ips.join(", ")));
            }
        }
        conf_lines.push("".to_string());
    }

    let conf_content = conf_lines.join("\n");
    let mut temp_file = NamedTempFile::new()?;
    temp_file.write_all(conf_content.as_bytes())?;
    temp_file.flush()?;

    let mut cmd = Command::new(wg_cmd());
    cmd.args(["addconf", interface, temp_file.path().to_str().unwrap()])
        .stdin(Stdio::null());
    run_cmd_with_timeout(&mut cmd, Duration::from_secs(10))?;
    info!("Batch restored peers via wg addconf");

    Ok(clear_psk_peers)
}

// ---------- 局域网切换与端点监控 ----------
fn should_report_ipv6(ip: &Ipv6Addr) -> bool {
    if ip.is_multicast() || ip.is_loopback() || ip.is_unspecified() || ip.is_unicast_link_local() {
        false
    } else {
        (ip.segments()[0] & 0xfe00) == 0xfc00
    }
}
fn get_local_lan_networks() -> Vec<IpNet> {
    let mut nets = Vec::new();
    if let Ok(ifaces) = get_if_addrs() {
        for iface in ifaces {
            if iface.name.starts_with("wg") {
                continue;
            }
            match iface.addr {
                if_addrs::IfAddr::V4(ifv4) => {
                    let ip = ifv4.ip;
                    if ip.is_private() && !ip.is_loopback() {
                        if let Ok(net) = Ipv4Net::with_netmask(ip, ifv4.netmask) {
                            nets.push(IpNet::V4(net.trunc()));
                        }
                    }
                }
                if_addrs::IfAddr::V6(ifv6) => {
                    let ip = ifv6.ip;
                    if should_report_ipv6(&ip) {
                        if let Ok(net) = Ipv6Net::with_netmask(ip, ifv6.netmask) {
                            nets.push(IpNet::V6(net.trunc()));
                        }
                    }
                }
            }
        }
    }
    nets
}
fn parse_endpoint(ep: &str) -> Option<(IpAddr, u16)> {
    if let Ok(socket) = ep.parse::<std::net::SocketAddr>() {
        return Some((socket.ip(), socket.port()));
    }
    if let Some((ip_str, port_str)) = ep.rsplit_once(':') {
        if let (Ok(ip), Ok(port)) = (ip_str.parse::<IpAddr>(), port_str.parse::<u16>()) {
            return Some((ip, port));
        }
    }
    None
}
fn find_same_lan_endpoint(
    peer_local_endpoints: &[String],
    my_nets: &[IpNet],
) -> Option<(String, u16)> {
    for ep_str in peer_local_endpoints {
        if let Some((ip, port)) = parse_endpoint(ep_str) {
            for net in my_nets {
                if net.contains(&ip) {
                    return Some((ip.to_string(), port));
                }
            }
        }
    }
    None
}
fn update_wg_endpoint(interface: &str, pubkey: &str, new_endpoint: &str) {
    let output = Command::new(wg_cmd())
        .args(["set", interface, "peer", pubkey, "endpoint", new_endpoint])
        .output();
    match output {
        Ok(o) if o.status.success() => {
            info!("Updated peer {} endpoint to {}", pubkey, new_endpoint)
        }
        Ok(o) => warn!(
            "Failed to update peer {} endpoint: {}",
            pubkey,
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => error!("Failed to execute wg set endpoint: {}", e),
    }
}

fn try_switch_to_lan_endpoint(interface: String, pubkey: String, local_endpoints: Vec<String>) {
    if !is_lan_switching_enabled() {
        return;
    }

    {
        let last_attempts = LAST_LAN_ATTEMPT.lock().unwrap();
        if let Some(last) = last_attempts.get(&pubkey) {
            if last.elapsed() < MIN_LAN_RETRY_INTERVAL {
                return;
            }
        }
    }
    let my_nets = get_local_lan_networks();
    if let Some((lan_ip, lan_port)) = find_same_lan_endpoint(&local_endpoints, &my_nets) {
        LAST_LAN_ATTEMPT
            .lock()
            .unwrap()
            .insert(pubkey.clone(), Instant::now());
        let new_endpoint = format!("{}:{}", lan_ip, lan_port);
        let state = get_latest_wg_state(&interface, &mut None).unwrap_or_default();
        let current_ep = get_current_endpoint(&state, &pubkey);
        if current_ep.as_ref() == Some(&new_endpoint) {
            return;
        }
        let fallback = current_ep.clone();
        update_wg_endpoint(&interface, &pubkey, &new_endpoint);
        if let Some(ip) = first_tunnel_ip(
            &state
                .peers
                .get(&pubkey)
                .map(|p| p.allowed_ips.as_slice())
                .unwrap_or(&[]),
        ) {
            trigger_handshake_udp(&ip);
        }

        LAN_VERIFICATION_TASKS
            .lock()
            .unwrap()
            .push(LanVerificationTask {
                interface: interface.clone(),
                pubkey: pubkey.clone(),
                new_endpoint,
                fallback,
                start: Instant::now(),
                timeout: Duration::from_secs(*LAN_HANDSHAKE_WAIT_SECS),
            });
    }
}

fn process_lan_verification_tasks() {
    let mut tasks = LAN_VERIFICATION_TASKS.lock().unwrap();
    if tasks.is_empty() {
        return;
    }

    let interface = env::var("WG_INTERFACE").unwrap_or_else(|_| "wg0".to_string());
    let wg_state = match get_wg_state(&interface) {
        Ok(s) => s,
        Err(e) => {
            warn!("LAN verification: failed to get wg state: {}", e);
            return;
        }
    };

    tasks.retain(|task| {
        if !get_current_peers(&wg_state).contains(&task.pubkey) {
            return false;
        }
        let current_ep = get_current_endpoint(&wg_state, &task.pubkey);
        if current_ep.as_ref() != Some(&task.new_endpoint) {
            return false;
        }
        if has_recent_handshake(&wg_state, &task.pubkey, HANDSHAKE_MAX_AGE_SECS) {
            info!(
                "LAN endpoint verified for peer {} (elapsed {:.1}s)",
                task.pubkey,
                task.start.elapsed().as_secs_f64()
            );
            return false;
        }
        if task.start.elapsed() >= task.timeout {
            warn!("LAN endpoint timeout for peer {}, reverting", task.pubkey);
            if let Some(ref fallback) = task.fallback {
                update_wg_endpoint(&task.interface, &task.pubkey, fallback);
            }
            return false;
        }
        true
    });
}

fn update_endpoint_with_fallback(
    interface: String,
    pubkey: String,
    new_endpoint: String,
    _fallback: Option<String>,
) {
    update_wg_endpoint(&interface, &pubkey, &new_endpoint);
    info!(
        "WAN endpoint updated to {} for peer {}, fallback disabled",
        new_endpoint, pubkey
    );
}

fn collect_my_local_endpoints(listen_port: u16) -> Vec<String> {
    let mut endpoints = Vec::new();
    if let Ok(interfaces) = get_if_addrs() {
        for iface in interfaces {
            if iface.name.starts_with("wg") {
                continue;
            }
            match iface.addr {
                if_addrs::IfAddr::V4(ifv4) => {
                    let ip = ifv4.ip;
                    if ip.is_private() && !ip.is_loopback() {
                        endpoints.push(format!("{}:{}", ip, listen_port));
                    }
                }
                if_addrs::IfAddr::V6(ifv6) => {
                    let ip = ifv6.ip;
                    if should_report_ipv6(&ip) {
                        endpoints.push(format!("[{}]:{}", ip, listen_port));
                    }
                }
            }
        }
    }
    endpoints
}

// ---------- 端口更换 ----------
fn has_lan_peer(state: &WgState) -> bool {
    if !is_lan_switching_enabled() {
        return false;
    }
    let my_nets = get_local_lan_networks();
    if my_nets.is_empty() {
        return false;
    }
    for pubkey in state.peers.keys() {
        if let Some(ep_str) = &state.peers[pubkey].endpoint {
            if let Some((ip, _)) = parse_endpoint(ep_str) {
                for net in &my_nets {
                    if net.contains(&ip) {
                        return true;
                    }
                }
            }
        }
    }
    false
}
fn try_change_port(interface: &str, force: bool, state: &WgState) {
    let peers = get_current_peers(state);
    if peers.is_empty() {
        return;
    }
    if !force {
        let any_recent = peers
            .iter()
            .any(|pubkey| has_recent_handshake(state, pubkey, NO_HANDSHAKE_THRESHOLD));
        if any_recent {
            return;
        }
        if has_lan_peer(state) {
            return;
        }
    }
    let now = Instant::now();
    let mut history = PORT_CHANGE_HISTORY.lock().unwrap();
    while history
        .front()
        .map_or(false, |t| now.duration_since(*t) > PORT_CHANGE_LIMIT_WINDOW)
    {
        history.pop_front();
    }
    if history.len() >= MAX_PORT_CHANGES_PER_WINDOW {
        return;
    }
    if let Some(last) = history.back() {
        if now.duration_since(*last) < PORT_CHANGE_LIMIT_WINDOW / MAX_PORT_CHANGES_PER_WINDOW as u32
        {
            return;
        }
    }
    let (min, max) = get_port_range();
    let new_port = rand::thread_rng().gen_range(min..=max);
    info!("Changing listen port to {} (force={})", new_port, force);
    let output = Command::new(wg_cmd())
        .args(["set", interface, "listen-port", &new_port.to_string()])
        .output();
    match output {
        Ok(o) if o.status.success() => {
            info!("Successfully changed listen port to {}", new_port);
            history.push_back(now);
            *WG_STATE_CACHE.lock().unwrap() = None;
        }
        Ok(o) => error!(
            "wg set listen-port failed: {}",
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => error!("Failed to execute wg set listen-port: {}", e),
    }
}
fn check_and_maybe_change_listen_port(interface: &str, state: &WgState) {
    try_change_port(interface, false, state);
}

// ---------- 路由辅助函数 ----------
/// 检查内核路由表中是否已存在某个 IPv4 前缀
fn route_exists_v4(prefix: &str) -> bool {
    if let Ok(output) = Command::new("ip").args(["route", "show", prefix]).output() {
        !String::from_utf8_lossy(&output.stdout).trim().is_empty()
    } else {
        false
    }
}

/// 检查内核路由表中是否已存在某个 IPv6 前缀
fn route_exists_v6(prefix: &str) -> bool {
    if let Ok(output) = Command::new("ip")
        .args(["-6", "route", "show", prefix])
        .output()
    {
        !String::from_utf8_lossy(&output.stdout).trim().is_empty()
    } else {
        false
    }
}

fn is_valid_cidr(s: &str) -> bool {
    s.parse::<ipnet::IpNet>().is_ok()
}

// ---------- 应用通告路由 ----------
fn apply_advertised_routes(interface: &str, routes: &AdvertisedRoutes) -> Result<()> {
    let new_ipv4: HashSet<String> = routes.ipv4.iter().cloned().collect();
    let new_ipv6: HashSet<String> = routes.ipv6.iter().cloned().collect();
    let mut last = LAST_APPLIED_ROUTES.lock().unwrap();

    // --- 删除不再需要的 IPv4 路由 ---
    for cidr in last.0.iter() {
        if !new_ipv4.contains(cidr) {
            let _ = Command::new("ip")
                .args(["route", "del", cidr, "dev", interface])
                .status();
            info!("Deleted old IPv4 route: {} dev {}", cidr, interface);
        }
    }

    // --- 删除不再需要的 IPv6 路由 ---
    for cidr in last.1.iter() {
        if !new_ipv6.contains(cidr) {
            let _ = Command::new("ip")
                .args(["-6", "route", "del", cidr, "dev", interface])
                .status();
            info!("Deleted old IPv6 route: {} dev {}", cidr, interface);
        }
    }

    // --- 添加新的 IPv4 路由 ---
    for cidr in &new_ipv4 {
        if !last.0.contains(cidr) {
            // 校验格式
            if !is_valid_cidr(cidr) {
                error!("Invalid CIDR format, skipping: {}", cidr);
                continue;
            }
            // 检查是否已存在
            if route_exists_v4(cidr) {
                warn!("Skipping route {} because it already exists", cidr);
                continue;
            }
            let _ = Command::new("ip")
                .args(["route", "replace", cidr, "dev", interface])
                .status();
            info!("Added/Replaced IPv4 route: {} dev {}", cidr, interface);
        }
    }

    // --- 添加新的 IPv6 路由 ---
    for cidr in &new_ipv6 {
        if !last.1.contains(cidr) {
            // 1. 校验 CIDR 格式
            if !is_valid_cidr(cidr) {
                error!("Invalid IPv6 CIDR format, skipping: {}", cidr);
                continue;
            }
            // 2. 检查内核中是否已存在该路由
            if route_exists_v6(cidr) {
                warn!("Skipping IPv6 route {} because it already exists", cidr);
                continue;
            }
            // 3. 不存在则安全添加（replace 保证幂等）
            let _ = Command::new("ip")
                .args(["-6", "route", "replace", cidr, "dev", interface])
                .status();
            info!("Added/Replaced IPv6 route: {} dev {}", cidr, interface);
        }
    }

    *last = (new_ipv4, new_ipv6);
    Ok(())
}

// ---------- 中继功能 ----------
fn get_original_ips_from_snapshot(pubkey: &str) -> Vec<String> {
    LAST_SNAPSHOT_PEERS
        .lock()
        .unwrap()
        .get(pubkey)
        .and_then(|p| p.allowed_ips.clone())
        .unwrap_or_default()
}
fn get_last_snapshot() -> Option<FullSnapshot> {
    let peers = LAST_SNAPSHOT_PEERS.lock().unwrap();
    if peers.is_empty() {
        None
    } else {
        Some(FullSnapshot {
            peers: peers.clone(),
            routes: AdvertisedRoutes {
                ipv4: vec![],
                ipv6: vec![],
            },
            amnezia: None,
        })
    }
}
fn discover_relay(snapshot: &FullSnapshot, state: &WgState) {
    let target_v4 = &*RELAY_CIDR_V4;
    let target_v6 = &*RELAY_CIDR_V6;
    let mut candidates = Vec::new();
    for (pubkey, peer) in &snapshot.peers {
        if let Some(ips) = &peer.allowed_ips {
            if ips.contains(target_v4) || ips.contains(target_v6) {
                if has_recent_handshake(state, pubkey, RELAY_FAIL_THRESHOLD) {
                    candidates.push(pubkey.clone());
                }
            }
        }
    }
    candidates.sort();
    let count = candidates.len();
    *RELAY_POOL.lock().unwrap() = candidates;
    info!("Relay pool updated: {} candidates", count);
}
fn add_ips_to_peer(interface: &str, pubkey: &str, ips: &[String]) -> Result<()> {
    let state = get_latest_wg_state(interface, &mut None)?;
    let current = get_current_allowed_ips(&state, pubkey)?;
    let mut new_set: HashSet<String> = current.into_iter().collect();
    for ip in ips {
        new_set.insert(ip.clone());
    }
    set_allowed_ips(interface, pubkey, &new_set.into_iter().collect::<Vec<_>>())
}
fn remove_ips_from_peer(interface: &str, pubkey: &str, ips: &[String]) -> Result<()> {
    let state = get_latest_wg_state(interface, &mut None)?;
    let current = get_current_allowed_ips(&state, pubkey)?;
    let remove_set: HashSet<&str> = ips.iter().map(|s| s.as_str()).collect();
    let new_ips: Vec<String> = current
        .into_iter()
        .filter(|ip| !remove_set.contains(ip.as_str()))
        .collect();
    set_allowed_ips(interface, pubkey, &new_ips)
}
fn set_allowed_ips(interface: &str, pubkey: &str, ips: &[String]) -> Result<()> {
    let output = Command::new(wg_cmd())
        .args(&[
            "set",
            interface,
            "peer",
            pubkey,
            "allowed-ips",
            &ips.join(","),
        ])
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        bail!(
            "Failed to set allowed-ips for {}: {}",
            pubkey,
            String::from_utf8_lossy(&output.stderr)
        )
    }
}
fn check_and_apply_relay(interface: &str, local_pubkey: &str, state: &WgState) {
    if let Some(ref snapshot) = get_last_snapshot() {
        discover_relay(snapshot, state);
    }
    let pool = RELAY_POOL.lock().unwrap().clone();
    if pool.is_empty() {
        return;
    }
    let handshakes = get_wg_latest_handshakes(state);
    for pubkey in handshakes.keys() {
        if pool.contains(pubkey) || pubkey == local_pubkey {
            continue;
        }
        let is_alive = has_recent_handshake(state, pubkey, RELAY_FAIL_THRESHOLD);
        if !is_alive {
            let action = {
                let mut fail_counts = PEER_FAIL_COUNT.lock().unwrap();
                let relay_load = RELAY_LOAD.lock().unwrap();
                let peer_to_relay = PEER_TO_RELAY.lock().unwrap();
                let count = fail_counts.entry(pubkey.to_string()).or_insert(0);
                *count += 1;
                if *count >= RELAY_FAIL_COUNT_MAX && !peer_to_relay.contains_key(pubkey) {
                    let best_relay = pool
                        .iter()
                        .filter(|pk| has_recent_handshake(state, pk, RELAY_FAIL_THRESHOLD))
                        .min_by_key(|pk| relay_load.get(*pk).copied().unwrap_or(0))
                        .cloned();
                    if let Some(relay) = best_relay {
                        let original_ips = get_original_ips_from_snapshot(pubkey);
                        if !original_ips.is_empty() {
                            Some((relay, pubkey.clone(), original_ips))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            };
            if let Some((relay, peer, original_ips)) = action {
                if add_ips_to_peer(interface, &relay, &original_ips).is_ok() {
                    let should_commit = {
                        let pt = PEER_TO_RELAY.lock().unwrap();
                        !pt.contains_key(&peer)
                            && has_recent_handshake(state, &relay, RELAY_FAIL_THRESHOLD)
                    };
                    if should_commit {
                        if remove_peer(interface, &peer).is_ok() {
                            let mut relay_load = RELAY_LOAD.lock().unwrap();
                            let mut peer_to_relay = PEER_TO_RELAY.lock().unwrap();
                            *relay_load.entry(relay.clone()).or_insert(0) += 1;
                            peer_to_relay.insert(peer.clone(), relay.clone());
                            PEER_FAIL_COUNT
                                .lock()
                                .unwrap()
                                .get_mut(&peer)
                                .map(|c| *c = 0);
                            info!(
                                "Peer {} -> relay {} (load: {})",
                                peer, relay, relay_load[&relay]
                            );
                        } else {
                            let _ = remove_ips_from_peer(interface, &relay, &original_ips);
                        }
                    } else {
                        let _ = remove_ips_from_peer(interface, &relay, &original_ips);
                    }
                }
            }
        } else {
            let action = {
                let mut peer_to_relay = PEER_TO_RELAY.lock().unwrap();
                if let Some(relay) = peer_to_relay.remove(pubkey) {
                    Some((
                        relay,
                        pubkey.clone(),
                        get_original_ips_from_snapshot(pubkey),
                    ))
                } else {
                    None
                }
            };
            if let Some((relay, peer, original_ips)) = action {
                let _ = remove_ips_from_peer(interface, &relay, &original_ips);
                let pt = PEER_TO_RELAY.lock().unwrap();
                if pt.get(&peer) != Some(&relay) {
                    return;
                }
                if let Some(info) = LAST_SNAPSHOT_PEERS.lock().unwrap().get(&peer).cloned() {
                    if add_or_update_peer(
                        interface,
                        &peer,
                        info.endpoint.as_deref(),
                        info.allowed_ips.as_deref(),
                        info.persistent_keepalive,
                        info.preshared_key.as_deref(),
                        state,
                    )
                    .is_ok()
                    {
                        if let Some(ld) = RELAY_LOAD.lock().unwrap().get_mut(&relay) {
                            *ld = ld.saturating_sub(1);
                        }
                        PEER_FAIL_COUNT.lock().unwrap().remove(&peer);
                        info!(
                            "Peer {} restored to direct, released from relay {}",
                            peer, relay
                        );
                    }
                }
            }
            PEER_FAIL_COUNT
                .lock()
                .unwrap()
                .entry(pubkey.to_string())
                .and_modify(|c| *c = 0);
        }
    }
    for relay in pool.iter() {
        if !has_recent_handshake(state, relay, RELAY_FAIL_THRESHOLD) {
            let peers_to_migrate = {
                let peer_to_relay = PEER_TO_RELAY.lock().unwrap();
                let mut peers = Vec::new();
                for (peer, assigned) in peer_to_relay.iter() {
                    if assigned == relay {
                        peers.push((peer.clone(), get_original_ips_from_snapshot(peer)));
                    }
                }
                peers
            };
            if peers_to_migrate.is_empty() {
                RELAY_LOAD.lock().unwrap().remove(relay);
                continue;
            }
            warn!(
                "Relay {} failed, migrating {} peers",
                relay,
                peers_to_migrate.len()
            );
            for (peer, original_ips) in peers_to_migrate {
                let _ = remove_ips_from_peer(interface, relay, &original_ips);
                let new_relay = pool
                    .iter()
                    .filter(|pk| {
                        *pk != relay && has_recent_handshake(state, pk, RELAY_FAIL_THRESHOLD)
                    })
                    .min_by_key(|pk| RELAY_LOAD.lock().unwrap().get(*pk).copied().unwrap_or(0))
                    .cloned();
                if let Some(target_relay) = new_relay {
                    if add_ips_to_peer(interface, &target_relay, &original_ips).is_ok() {
                        let bind_ok = {
                            let pt = PEER_TO_RELAY.lock().unwrap();
                            !pt.contains_key(&peer)
                                && has_recent_handshake(state, &target_relay, RELAY_FAIL_THRESHOLD)
                        };
                        if bind_ok {
                            let mut relay_load = RELAY_LOAD.lock().unwrap();
                            *relay_load.entry(target_relay.clone()).or_insert(0) += 1;
                            PEER_TO_RELAY
                                .lock()
                                .unwrap()
                                .insert(peer.clone(), target_relay.clone());
                            info!(
                                "Migrated peer {} from relay {} to {}",
                                peer, relay, target_relay
                            );
                        } else {
                            let _ = remove_ips_from_peer(interface, &target_relay, &original_ips);
                        }
                    }
                } else {
                    warn!(
                        "No healthy relay available for peer {} after relay {} failed",
                        peer, relay
                    );
                }
            }
            RELAY_LOAD.lock().unwrap().remove(relay);
        }
    }
}

// ---------- Amnezia 配置 ----------
fn apply_amnezia_config(interface: &str, config: &AmneziaConfig) -> Result<()> {
    let mut args = vec![
        "set".to_string(),
        interface.to_string(),
        format!("jc={}", config.jc),
        format!("jmin={}", config.jmin),
        format!("jmax={}", config.jmax),
        format!("s1={}", config.s1),
        format!("s2={}", config.s2),
        format!("h1={}", config.h1),
        format!("h2={}", config.h2),
        format!("h3={}", config.h3),
        format!("h4={}", config.h4),
    ];

    if let Some(ref v) = config.i1 {
        if !v.is_empty() {
            args.push(format!("i1={}", v));
        }
    }
    if let Some(ref v) = config.i2 {
        if !v.is_empty() {
            args.push(format!("i2={}", v));
        }
    }
    if let Some(ref v) = config.i3 {
        if !v.is_empty() {
            args.push(format!("i3={}", v));
        }
    }
    if let Some(ref v) = config.i4 {
        if !v.is_empty() {
            args.push(format!("i4={}", v));
        }
    }
    if let Some(ref v) = config.i5 {
        if !v.is_empty() {
            args.push(format!("i5={}", v));
        }
    }

    let status = Command::new(wg_cmd())
        .args(&args)
        .status()
        .context("Failed to apply Amnezia config")?;
    if !status.success() {
        bail!("awg set Amnezia config failed");
    }
    info!("Applied Amnezia config to {}", interface);
    Ok(())
}

// ---------- 无psk跳过清除 ----------
fn get_peers_with_psk(interface: &str) -> Result<HashSet<String>> {
    let output = Command::new(wg_cmd())
        .args(["show", interface, "preshared-keys"])
        .output()
        .context("Failed to execute wg show preshared-keys")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut set = HashSet::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // 格式: <pubkey>  <psk>
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        let pubkey = parts[0].to_string();
        // 如果有 PSK，parts[1] 存在且不为 "(none)"；无 PSK 的 peer 通常不在此列表中
        // 保险起见，检查第二个字段是否存在且不为 "(none)"
        if parts.len() >= 2 && parts[1] == "(none)" {
            continue; // 极少数情况若出现 (none)，应跳过
        }
        set.insert(pubkey);
    }
    Ok(set)
}

// ---------- 全量快照处理 ----------
fn handle_full_snapshot(
    interface: &str,
    local_pubkey: &str,
    payload: &[u8],
    retry_queue: &Arc<Mutex<VecDeque<RetryTask>>>,
    client: &Client,
    _request_topic: &str,
    wg_state_cache: &mut Option<(Instant, WgState)>,
    do_register: &dyn Fn(&Client),
) {
    let new_hash = blake3::hash(payload);
    let mut last = get_latest_hash().lock().unwrap();
    if let Some(last_hash) = last.as_ref() {
        if *last_hash == new_hash {
            warn!("Duplicate full snapshot ignored");
            return;
        }
    }
    *last = Some(new_hash);

    let decompressed = match decode_all(payload) {
        Ok(data) => data,
        Err(e) => {
            warn!("Zstd decompression failed: {}, trying raw JSON", e);
            payload.to_vec()
        }
    };

    let snapshot: FullSnapshot = match serde_json::from_slice(&decompressed) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to parse full snapshot JSON: {}", e);
            return;
        }
    };
    info!(
        "Received full state snapshot: {} peers",
        snapshot.peers.len()
    );

    let self_in_snapshot = snapshot.peers.contains_key(local_pubkey);
    let min_peers = 2;
    let snapshot_ok = self_in_snapshot && snapshot.peers.len() >= min_peers;

    if !snapshot_ok {
        warn!(
            "Incomplete snapshot (peers: {}, self_present: {}), refusing to apply. Requesting fresh full state.",
              snapshot.peers.len(),
              self_in_snapshot
        );
        *REGISTRATION_STATE.lock().unwrap() = RegistrationState::NotRegistered;
        *LAST_SNAPSHOT_PEERS.lock().unwrap() = snapshot.peers.clone();
        *wg_state_cache = None;
        return;
    }

    if let Err(e) = apply_advertised_routes(interface, &snapshot.routes) {
        error!("Failed to apply routes: {}", e);
    }

    if wg_cmd() == "awg" {
        if let Some(ref amnezia) = snapshot.amnezia {
            let _ = apply_amnezia_config(interface, amnezia);
        }
    }

    if let Some(self_peer) = snapshot.peers.get(local_pubkey) {
        if let Some(allowed_ips) = &self_peer.allowed_ips {
            let (ipv4, ipv6) = extract_self_ips(allowed_ips);
            if !ipv4.is_empty() || !ipv6.is_empty() {
                configure_self_ip(interface, &ipv4, &ipv6);
            }
        }
        *MISSING_SELF_COUNT.lock().unwrap() = 0;
        *REGISTRATION_STATE.lock().unwrap() = RegistrationState::Registered;
    } else {
        warn!("Self public key not found in full snapshot");
        let mut count = MISSING_SELF_COUNT.lock().unwrap();
        *count += 1;
        if *count >= 3 {
            warn!("Re-registering after {} missing snapshots", count);
            do_register(client);
            *count = 0;
        }
    }

    let peer_to_relay = PEER_TO_RELAY.lock().unwrap();
    let relay_peers: HashSet<String> = peer_to_relay.keys().cloned().collect();
    drop(peer_to_relay);

    // ---- LAN 活跃保护 + 单次遍历构建 config_entries ----
    let state_for_lan = get_latest_wg_state(interface, wg_state_cache).unwrap_or_default();
    let mut cloned_entries: Vec<(String, PeerInfo)> = Vec::new();

    for (pubkey, peer) in snapshot
        .peers
        .iter()
        .filter(|(k, _)| *k != local_pubkey && !relay_peers.contains(*k))
    {
        let mut peer_clone = peer.clone();
        if is_lan_switching_enabled() {
            if let Some(ref current_ep) = get_current_endpoint(&state_for_lan, pubkey) {
                if is_lan_active(&state_for_lan, pubkey, current_ep) {
                    peer_clone.endpoint = Some(current_ep.clone());
                    info!(
                        "LAN active for peer {}, preserving LAN endpoint {} over snapshot endpoint {:?}",
                        pubkey, current_ep, peer.endpoint
                    );
                }
            }
        }
        cloned_entries.push((pubkey.clone(), peer_clone));
    }

    let config_entries: Vec<(&String, &PeerInfo)> =
        cloned_entries.iter().map(|(k, v)| (k, v)).collect();
    // ---- 保护结束 ----

    match batch_restore_peers(interface, &config_entries, local_pubkey) {
        Ok(clear_psk_peers) => {
            // 获取当前已配置 PSK 的 peer 集合，若查询失败则强制清除所有请求的 peer
            let (peers_with_psk, force_clear) = match get_peers_with_psk(interface) {
                Ok(set) => (set, false),
                Err(e) => {
                    warn!(
                        "Failed to query PSK status, will clear all requested peers: {}",
                        e
                    );
                    (HashSet::new(), true) // 查询失败时不跳过任何 peer，确保清除
                }
            };

            for pubkey in &clear_psk_peers {
                // 若查询成功且 peer 当前无 PSK，则跳过（避免无意义的删除/添加）
                if !force_clear && !peers_with_psk.contains(pubkey.as_str()) {
                    debug!("Skipping PSK clear for peer {}: no PSK present", pubkey);
                    continue;
                }

                if let Some(peer) = snapshot.peers.get(pubkey) {
                    // 仅当快照明确要求清除 PSK (preshared_key == Some("")) 时才执行
                    if peer.preshared_key.as_deref() != Some("") {
                        debug!(
                            "Skipping PSK clear for peer {}: preshared_key is {:?}",
                            pubkey, peer.preshared_key
                        );
                        continue;
                    }
                    // 保护：若 allowed_ips 为空，跳过（避免添加失败并重试）
                    let allowed_ips = match &peer.allowed_ips {
                        Some(ips) if !ips.is_empty() => ips.as_slice(),
                        _ => {
                            warn!(
                                "Peer {} has empty allowed_ips in snapshot, skipping PSK clear",
                                pubkey
                            );
                            continue;
                        }
                    };

                    // 获取最新状态
                    let current_state = get_wg_state(interface).unwrap_or_default();

                    // LAN 端点保护
                    let final_endpoint = match get_current_endpoint(&current_state, pubkey) {
                        Some(ref current_ep)
                            if is_lan_active(&current_state, pubkey, current_ep) =>
                        {
                            Some(current_ep.clone())
                        }
                        _ => peer.endpoint.clone(),
                    };

                    // 强制清除 PSK
                    if let Err(e) = add_or_update_peer(
                        interface,
                        pubkey,
                        final_endpoint.as_deref(),
                        Some(allowed_ips),
                        peer.persistent_keepalive,
                        Some(""),
                        &current_state,
                    ) {
                        error!("Failed to handle PSK for peer {}: {}", pubkey, e);
                    } else {
                        info!("PSK cleared for peer {}", pubkey);
                    }
                }
            }
        }
        Err(e) => {
            error!(
                "Batch restore failed: {}, falling back to individual peers",
                e
            );
            let state = get_latest_wg_state(interface, wg_state_cache).unwrap_or_default();
            for (pubkey, peer) in &config_entries {
                if let Err(e) = add_or_update_peer(
                    interface,
                    pubkey,
                    peer.endpoint.as_deref(),
                    peer.allowed_ips.as_deref(),
                    peer.persistent_keepalive,
                    peer.preshared_key.as_deref(),
                    &state,
                ) {
                    error!(
                        "Failed to add peer {}: {}, adding to retry queue",
                        pubkey, e
                    );
                    if retry_queue.lock().unwrap().len() < MAX_RETRY_QUEUE_SIZE {
                        retry_queue.lock().unwrap().push_back(RetryTask::new(
                            (*pubkey).clone(),
                            peer.endpoint.clone(),
                            peer.allowed_ips.clone(),
                            peer.persistent_keepalive,
                            peer.preshared_key.clone(),
                        ));
                    }
                }
            }
        }
    }

    for (pubkey, peer) in &snapshot.peers {
        if pubkey == local_pubkey {
            continue;
        }
        if let Some(local_ips) = &peer.local_ips {
            if !local_ips.is_empty() {
                try_switch_to_lan_endpoint(
                    interface.to_string(),
                    pubkey.clone(),
                    local_ips.clone(),
                );
            }
        }
    }

    let current_peers = get_current_peers(&get_wg_state(interface).unwrap_or_default());
    for pubkey in current_peers {
        if pubkey == local_pubkey || snapshot.peers.contains_key(&pubkey) {
            continue;
        }
        let _ = remove_peer(interface, &pubkey);
        let mut peer_to_relay = PEER_TO_RELAY.lock().unwrap();
        if let Some(relay) = peer_to_relay.remove(&pubkey) {
            PEER_FAIL_COUNT.lock().unwrap().remove(&pubkey);
            if let Some(load) = RELAY_LOAD.lock().unwrap().get_mut(&relay) {
                *load = load.saturating_sub(1);
            }
        }
    }

    *LAST_SNAPSHOT_PEERS.lock().unwrap() = snapshot.peers.clone();
    *wg_state_cache = None;
}

// ---------- 增量消息处理 ----------
fn handle_delta_message(
    interface: &str,
    local_pubkey: &str,
    payload: &[u8],
    retry_queue: &Arc<Mutex<VecDeque<RetryTask>>>,
    client: &Client,
    request_topic: &str,
    wg_state_cache: &mut Option<(Instant, WgState)>,
) {
    let json: Value = match serde_json::from_slice(payload) {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to parse delta JSON: {}", e);
            return;
        }
    };
    let action = json.get("action").and_then(|v| v.as_str()).unwrap_or("");
    let pubkey = json.get("pubkey").and_then(|v| v.as_str()).unwrap_or("");
    if pubkey.is_empty() || pubkey == local_pubkey {
        return;
    }
    match action {
        "add" | "update" => {
            let endpoint = json.get("endpoint").and_then(|v| {
                if v.is_null() {
                    None
                } else {
                    v.as_str().map(String::from)
                }
            });
            let allowed_ips: Option<Vec<String>> = json
                .get("allowed_ips")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                });
            if action == "update" {
                let state = get_latest_wg_state(interface, wg_state_cache).unwrap_or_default();
                if !get_current_peers(&state).contains(pubkey) {
                    warn!(
                        "Received update for unknown peer {}, requesting full state",
                        pubkey
                    );
                    let _ = client.publish(request_topic, QoS::AtLeastOnce, false, "1");
                    return;
                }
            }
            if action == "add" && allowed_ips.is_none() {
                return;
            }
            let keepalive = json
                .get("persistent_keepalive")
                .and_then(|v| v.as_u64())
                .map(|v| v as u16);
            let psk = json
                .get("preshared_key")
                .and_then(|v| v.as_str())
                .map(String::from);
            let state = get_latest_wg_state(interface, wg_state_cache).unwrap_or_default();
            if let Err(e) = add_or_update_peer(
                interface,
                pubkey,
                endpoint.as_deref(),
                allowed_ips.as_deref(),
                keepalive,
                psk.as_deref(),
                &state,
            ) {
                error!(
                    "Failed to update peer {}: {}, adding to retry queue",
                    pubkey, e
                );
                if retry_queue.lock().unwrap().len() < MAX_RETRY_QUEUE_SIZE {
                    retry_queue.lock().unwrap().push_back(RetryTask::new(
                        pubkey.to_string(),
                        endpoint,
                        allowed_ips,
                        keepalive,
                        psk,
                    ));
                }
            } else if let Some(ref new_ep) = endpoint {
                let current_ep = get_current_endpoint(&state, pubkey);
                if current_ep.as_ref() != Some(new_ep) {
                    if is_lan_switching_enabled() {
                        let lan_is_active = if let Some(current_ep_str) = &current_ep {
                            if let Some((ip, _)) = parse_endpoint(current_ep_str) {
                                let my_nets = get_local_lan_networks();
                                let is_lan_ip = my_nets.iter().any(|net| net.contains(&ip));
                                let has_recent =
                                    has_recent_handshake(&state, pubkey, HANDSHAKE_MAX_AGE_SECS);
                                is_lan_ip && has_recent
                            } else {
                                false
                            }
                        } else {
                            false
                        };
                        if lan_is_active {
                            info!(
                                "LAN switching enabled: peer {} is using LAN endpoint {}, ignoring WAN endpoint update {}",
                                pubkey,
                                current_ep.as_ref().unwrap(),
                                new_ep
                            );
                        } else {
                            update_endpoint_with_fallback(
                                interface.to_string(),
                                pubkey.to_string(),
                                new_ep.clone(),
                                current_ep,
                            );
                        }
                    } else {
                        update_endpoint_with_fallback(
                            interface.to_string(),
                            pubkey.to_string(),
                            new_ep.clone(),
                            current_ep,
                        );
                    }
                }
            }
            if let Some(local_ips) = json.get("local_ips").and_then(|v| v.as_array()) {
                let ips: Vec<String> = local_ips
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                if !ips.is_empty() {
                    try_switch_to_lan_endpoint(interface.to_string(), pubkey.to_string(), ips);
                }
            }
        }
        "remove" => {
            let _ = remove_peer(interface, pubkey);
            let mut peer_to_relay = PEER_TO_RELAY.lock().unwrap();
            if let Some(relay) = peer_to_relay.remove(pubkey) {
                PEER_FAIL_COUNT.lock().unwrap().remove(pubkey);
                if let Some(load) = RELAY_LOAD.lock().unwrap().get_mut(&relay) {
                    *load = load.saturating_sub(1);
                }
            }
            *wg_state_cache = None;
        }
        "set_routes" => {
            if let Some(routes_val) = json.get("routes") {
                match serde_json::from_value::<AdvertisedRoutes>(routes_val.clone()) {
                    Ok(routes) => {
                        if let Err(e) = apply_advertised_routes(interface, &routes) {
                            error!("Failed to apply routes from delta: {}", e);
                        } else {
                            info!("Routes updated via delta set_routes");
                        }
                    }
                    Err(e) => warn!("Invalid routes in delta 'set_routes': {}", e),
                }
            }
        }
        _ => {}
    }
}

// ---------- 重试队列 ----------
fn process_retry_queue(
    interface: &str,
    retry_queue: &Arc<Mutex<VecDeque<RetryTask>>>,
    state: &WgState,
) {
    let pending: Vec<RetryTask> = {
        let mut queue = retry_queue.lock().unwrap();
        let now = Instant::now();
        let mut collected = Vec::new();
        while let Some(mut task) = queue.pop_front() {
            if now.duration_since(task.last_attempt) >= task.next_interval() {
                task.last_attempt = now;
                task.retry_count += 1;
                collected.push(task);
            } else {
                queue.push_front(task);
                break;
            }
        }
        collected
    };

    for task in pending {
        let effective_endpoint = if task.endpoint.is_some() {
            if let Some(current_ep) = get_current_endpoint(state, &task.pubkey) {
                if is_lan_active(state, &task.pubkey, &current_ep) {
                    info!(
                        "Retry queue: preserving LAN endpoint {} for peer {}",
                        current_ep, task.pubkey
                    );
                    Some(current_ep)
                } else {
                    task.endpoint.clone()
                }
            } else {
                task.endpoint.clone()
            }
        } else {
            None
        };

        if let Err(e) = add_or_update_peer(
            interface,
            &task.pubkey,
            effective_endpoint.as_deref(),
            task.allowed_ips.as_deref(),
            task.persistent_keepalive,
            task.preshared_key.as_deref(),
            state,
        ) {
            error!(
                "Retry {} failed for peer {}: {}",
                task.retry_count, task.pubkey, e
            );
            if task.retry_count < DEFAULT_MAX_RETRY_ATTEMPTS {
                retry_queue.lock().unwrap().push_back(task);
            }
        } else {
            info!("Retry succeeded for peer {}", task.pubkey);
        }
    }
}

// ---------- 流量上报 ----------
fn try_report_traffic(client: &Client, interface: &str, local_pubkey: &str, state: &WgState) {
    let increments = {
        let mut snapshot = TRAFFIC_SNAPSHOT.lock().unwrap();
        let mut increments = HashMap::new();
        for (pubkey, peer) in &state.peers {
            let cur_rx = peer.transfer_rx;
            let cur_tx = peer.transfer_tx;
            let (delta_rx, delta_tx) = if let Some(&(last_rx, last_tx)) = snapshot.get(pubkey) {
                (
                    if cur_rx >= last_rx {
                        cur_rx - last_rx
                    } else {
                        cur_rx
                    },
                    if cur_tx >= last_tx {
                        cur_tx - last_tx
                    } else {
                        cur_tx
                    },
                )
            } else {
                (cur_rx, cur_tx)
            };
            snapshot.insert(pubkey.clone(), (cur_rx, cur_tx));
            if delta_rx > 0 || delta_tx > 0 {
                increments.insert(pubkey.clone(), (delta_rx, delta_tx));
            }
        }
        snapshot.retain(|pk, _| state.peers.contains_key(pk));
        increments
    };
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let peers: Vec<serde_json::Value> = state
        .peers
        .iter()
        .filter_map(|(pubkey, peer)| {
            let (delta_rx, delta_tx) = increments.get(pubkey).copied().unwrap_or((0, 0));
            if peer.transfer_rx == 0 && peer.transfer_tx == 0 && delta_rx == 0 && delta_tx == 0 {
                return None;
            }
            Some(serde_json::json!({
                "pubkey": pubkey,
                "rx_bytes": delta_rx,
                "tx_bytes": delta_tx,
                "rx_total": peer.transfer_rx,
                "tx_total": peer.transfer_tx,
            }))
        })
        .collect();
    if peers.is_empty() {
        return;
    }
    let payload = serde_json::json!({
        "timestamp": now_secs,
        "node": local_pubkey,
        "peers": peers,
    });
    let topic = format!("wg/{}/traffic", interface);
    let _ = client.publish(
        &topic,
        QoS::AtLeastOnce,
        false,
        payload.to_string().as_bytes(),
    );
    info!(
        "Traffic report published to {} ({} peers)",
        topic,
        peers.len()
    );
}

// ---------- 注册管理 ----------
fn start_registration(
    client: &Client,
    register_topic: &str,
    _request_topic: &str,
    register_payload: &serde_json::Value,
) {
    let payload_str = register_payload.to_string();
    info!("Sending registration request to {}", register_topic);
    for attempt in 1..=REGISTER_MAX_RETRIES {
        match client.publish(
            register_topic,
            QoS::AtLeastOnce,
            false,
            payload_str.as_bytes(),
        ) {
            Ok(_) => {
                info!("Register message published (attempt {})", attempt);
                *REGISTRATION_STATE.lock().unwrap() = RegistrationState::InProgress;
                return;
            }
            Err(e) => {
                error!("Failed to publish register (attempt {}): {}", attempt, e);
                if attempt < REGISTER_MAX_RETRIES {
                    thread::sleep(REGISTER_RETRY_INTERVAL);
                }
            }
        }
    }
    error!("All registration attempts failed");
}

// ---------- 主函数 ----------
fn main() -> Result<()> {
    env_logger::init();
    let wg_interface = env::var("WG_INTERFACE").unwrap_or_else(|_| "wg0".to_string());
    let backend = parse_backend()?;
    info!("Using backend: {:?}", backend);
    let mqtt_host = env::var("MQTT_HOST").context("MQTT_HOST must be set")?;
    let mqtt_port = env::var("MQTT_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1883);
    let mqtt_user = env::var("MQTT_USER").ok();
    let mqtt_pass = env::var("MQTT_PASS").ok();
    let enable_port_change = env::var("ENABLE_PORT_CHANGE_ON_NETWORK_LOSS")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    let enable_scheduled = env::var("ENABLE_SCHEDULED_PORT_CHANGE")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    let scheduled_interval = Duration::from_secs(
        env::var("SCHEDULED_PORT_CHANGE_INTERVAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(7200),
    );
    let enable_traffic_report = env::var("ENABLE_TRAFFIC_REPORT")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    info!(
        "Port change on network loss: {}",
        if enable_port_change {
            "ENABLED"
        } else {
            "DISABLED"
        }
    );
    info!(
        "Scheduled port change: {}",
        if enable_scheduled {
            "ENABLED"
        } else {
            "DISABLED"
        }
    );
    info!(
        "Traffic report: {}",
        if enable_traffic_report {
            "ENABLED"
        } else {
            "DISABLED"
        }
    );

    ensure_wireguard_interface(&wg_interface, backend)?;
    let local_pubkey = get_local_public_key(&wg_interface)?;
    info!("Local public key: {}", local_pubkey);

    let initial_state = get_wg_state(&wg_interface).unwrap_or_default();
    let my_local_endpoints = if is_lan_switching_enabled() {
        collect_my_local_endpoints(initial_state.listen_port)
    } else {
        Vec::new()
    };
    let client_id = format!(
        "wg-{}",
        &blake3::hash(local_pubkey.as_bytes()).to_hex()[..20]
    );
    let hostname = String::from_utf8(Command::new("hostname").output()?.stdout)?
        .trim()
        .to_string();
    let register_payload = serde_json::json!({
        "pubkey": local_pubkey,
        "hostname": hostname,
        "local_ips": my_local_endpoints,
    });

    let full_topic = format!("wg/{}/full", wg_interface);
    let delta_topic = format!("wg/{}/delta", wg_interface);
    let response_topic = format!("wg/{}/full/response/{}", wg_interface, client_id);
    let register_topic = format!("wg/{}/register", wg_interface);
    let request_topic = format!("wg/{}/full/request/{}", wg_interface, client_id);

    let (client, connection) = create_mqtt_connection(
        mqtt_host.clone(),
        mqtt_port,
        mqtt_user.clone(),
        mqtt_pass.clone(),
        client_id.clone(),
    )?;
    let mut mqtt_conn: Option<(Client, Connection)> = Some((client, connection));

    if let Some((ref client, _)) = mqtt_conn {
        let _ = client.subscribe(&full_topic, QoS::AtLeastOnce);
        let _ = client.subscribe(&delta_topic, QoS::AtLeastOnce);
        let _ = client.subscribe(&response_topic, QoS::AtLeastOnce);
    }

    let retry_queue = Arc::new(Mutex::new(VecDeque::new()));
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    let mut signals = Signals::new(TERM_SIGNALS)?;
    std::thread::spawn(move || {
        for _ in signals.forever() {
            info!("Received termination signal, shutting down...");
            r.store(false, Ordering::Relaxed);
            break;
        }
    });

    let mut wg_state_cache: Option<(Instant, WgState)> = Some((Instant::now(), initial_state));
    let mut last_retry_process = Instant::now();
    let mut last_network_check = Instant::now();
    let mut last_scheduled_change = Instant::now();
    let mut last_traffic_report = if enable_traffic_report {
        Some(Instant::now())
    } else {
        None
    };
    let mut last_lan_check = Instant::now();

    const RETRY_PROCESS_INTERVAL: Duration = Duration::from_secs(2);

    let mut reconnect_failures: u32 = 0;

    let re_register_interval = Duration::from_secs(
        env::var("RE_REGISTER_INTERVAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(600),
    );
    let mut last_re_register = Instant::now();

    while running.load(Ordering::Relaxed) {
        if last_retry_process.elapsed() >= RETRY_PROCESS_INTERVAL {
            if let Ok(state) = get_latest_wg_state(&wg_interface, &mut wg_state_cache) {
                process_retry_queue(&wg_interface, &retry_queue, &state);
            }
            last_retry_process = Instant::now();
        }
        if last_network_check.elapsed() >= NETWORK_CHECK_INTERVAL {
            if let Ok(state) = get_latest_wg_state(&wg_interface, &mut wg_state_cache) {
                if enable_port_change {
                    check_and_maybe_change_listen_port(&wg_interface, &state);
                }
                check_and_apply_relay(&wg_interface, &local_pubkey, &state);
            }
            last_network_check = Instant::now();
        }
        if enable_scheduled && last_scheduled_change.elapsed() >= scheduled_interval {
            if let Ok(state) = get_latest_wg_state(&wg_interface, &mut wg_state_cache) {
                try_change_port(&wg_interface, true, &state);
            }
            last_scheduled_change = Instant::now();
        }
        if enable_traffic_report {
            if let Some((ref client, _)) = mqtt_conn {
                if let Some(ref mut last) = last_traffic_report {
                    if last.elapsed() >= TRAFFIC_REPORT_INTERVAL {
                        if let Ok(state) = get_latest_wg_state(&wg_interface, &mut wg_state_cache) {
                            try_report_traffic(client, &wg_interface, &local_pubkey, &state);
                        }
                        *last = Instant::now();
                    }
                }
            }
        }

        if last_lan_check.elapsed() >= LAN_CHECK_INTERVAL {
            process_lan_verification_tasks();
            last_lan_check = Instant::now();
        }

        if last_re_register.elapsed() >= re_register_interval {
            let need = {
                let state = REGISTRATION_STATE.lock().unwrap();
                !matches!(*state, RegistrationState::Registered)
            };
            if need {
                if let Some((ref client, _)) = mqtt_conn {
                    info!("Periodic re‑registration triggered (not yet registered)");
                    start_registration(client, &register_topic, &request_topic, &register_payload);
                }
            }
            last_re_register = Instant::now();
        }

        if let Some((ref mut client, ref mut connection)) = mqtt_conn {
            match connection.recv_timeout(Duration::from_secs(1)) {
                Ok(notification) => match notification {
                    Ok(Event::Incoming(Incoming::ConnAck(ack))) => match ack.code {
                        ConnectReturnCode::Success => {
                            reconnect_failures = 0;
                            info!("MQTT connected");
                            start_registration(
                                client,
                                &register_topic,
                                &request_topic,
                                &register_payload,
                            );
                        }
                        other => {
                            warn!(
                                "MQTT connection refused with code {:?}, will retry...",
                                other
                            );
                            reconnect_failures += 1;
                            let wait = exponential_backoff(reconnect_failures);
                            error!("Backing off for {:?} before next reconnect attempt", wait);
                            mqtt_conn = None;
                            thread::sleep(wait);
                        }
                    },
                    Ok(Event::Incoming(Incoming::Publish(publish))) => {
                        let topic = publish.topic;
                        if topic == full_topic || topic == response_topic {
                            handle_full_snapshot(
                                &wg_interface,
                                &local_pubkey,
                                &publish.payload,
                                &retry_queue,
                                client,
                                &request_topic,
                                &mut wg_state_cache,
                                &|c: &Client| {
                                    start_registration(
                                        c,
                                        &register_topic,
                                        &request_topic,
                                        &register_payload,
                                    )
                                },
                            );
                            if topic == response_topic {
                                let _ = client.unsubscribe(&response_topic);
                            }
                        } else if topic == delta_topic {
                            handle_delta_message(
                                &wg_interface,
                                &local_pubkey,
                                &publish.payload,
                                &retry_queue,
                                client,
                                &request_topic,
                                &mut wg_state_cache,
                            );
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        error!("MQTT connection error: {:?}", e);
                    }
                },
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    reconnect_failures += 1;
                    let wait = exponential_backoff(reconnect_failures);
                    warn!(
                        "MQTT connection lost, backing off for {:?} (failures: {})",
                        wait, reconnect_failures
                    );
                    mqtt_conn = None;
                    *REGISTRATION_STATE.lock().unwrap() = RegistrationState::NotRegistered;
                    thread::sleep(wait);
                }
            }
        } else {
            match create_mqtt_connection(
                mqtt_host.clone(),
                mqtt_port,
                mqtt_user.clone(),
                mqtt_pass.clone(),
                client_id.clone(),
            ) {
                Ok((new_client, new_connection)) => {
                    info!("MQTT reconnected successfully");
                    let _ = new_client.subscribe(&full_topic, QoS::AtLeastOnce);
                    let _ = new_client.subscribe(&delta_topic, QoS::AtLeastOnce);
                    let _ = new_client.subscribe(&response_topic, QoS::AtLeastOnce);
                    mqtt_conn = Some((new_client, new_connection));
                    if enable_traffic_report {
                        last_traffic_report = Some(Instant::now());
                    }
                }
                Err(e) => {
                    reconnect_failures += 1;
                    let wait = exponential_backoff(reconnect_failures);
                    error!(
                        "Reconnect failed (attempt {}): {}. Backing off for {:?}",
                        reconnect_failures, e, wait
                    );
                    thread::sleep(wait);
                }
            }
        }
    }
    cleanup_userspace_backend(backend);
    info!("Goodbye");
    Ok(())
}
