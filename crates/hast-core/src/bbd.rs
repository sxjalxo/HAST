//! BlackBerry Dynamics mock.
//!
//! The real SDK (React Native, native modules) cannot run here, so this mirrors its public shapes:
//! `ApplicationConfig` is copied from `BlackBerry-Dynamics-for-React-Native-Application`
//! (`getApplicationConfig()`), and `getApplicationPolicy()` is a free-form JSON object.
//! `BlackBerryDynamics` stands in for the GD runtime (init plus container-key message sealing).
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AppServer {
    pub port: Option<u16>,
    pub priority: Option<u32>,
    pub server: Option<String>,
}

/// Field-for-field the SDK's `ApplicationConfig` type.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationConfig {
    pub app_host: Option<String>,
    pub app_port: Option<u16>,
    pub app_servers: Option<Vec<AppServer>>,
    pub communication_protocols: Option<BTreeMap<String, bool>>,
    pub container_id: Option<String>,
    pub copy_paste_on: Option<bool>,
    pub detailed_logs_on: Option<bool>,
    pub enterprise_id: Option<String>,
    pub enterprise_id_activated: Option<bool>,
    pub enterprise_id_features: Option<Vec<String>>,
    pub extra_info: Option<BTreeMap<String, String>>,
    pub keyboard_restricted_mode: Option<bool>,
    pub prevent_android_dictation: Option<bool>,
    pub prevent_dictation: Option<bool>,
    pub prevent_keyboard_extensions: Option<bool>,
    #[serde(rename = "preventPasteFromNonGDApps")]
    pub prevent_paste_from_non_gd_apps: Option<bool>,
    pub prevent_screen_capture: Option<bool>,
    pub prevent_user_detailed_logs: Option<bool>,
    pub prevent_custom_keyboards: Option<bool>,
    pub prevent_screen_recording: Option<bool>,
    pub protected_by_password: Option<bool>,
    pub upn: Option<String>,
    pub user_id: Option<String>,
}

/// What the original settings panel edits (its state shape, unchanged).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    // Data Leakage Prevention
    pub copy_paste_restriction: bool,
    pub screenshot_blocking: bool,
    pub watermarking: bool,
    // File Security
    pub secure_wipe_timer: i32, // hours
    pub allowed_file_types: Vec<String>,
    pub max_file_size: i32, // MB
    // Network Security
    pub vpn_passthrough: bool,
    pub allowed_domains: Vec<String>,
    pub blocked_domains: Vec<String>,
    // Authentication
    pub biometric_required: bool,
    pub pin_complexity: String,
    pub session_timeout: i32, // minutes
    // Encryption
    pub encryption_level: String,
    pub key_rotation_interval: i32, // hours
    pub quantum_safe_enabled: bool,
}

impl Default for Settings {
    fn default() -> Self {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect();
        Settings {
            copy_paste_restriction: true,
            screenshot_blocking: true,
            watermarking: false,
            secure_wipe_timer: 24,
            allowed_file_types: s(&["pdf", "docx", "xlsx", "jpg", "png"]),
            max_file_size: 50,
            vpn_passthrough: false,
            allowed_domains: s(&["cyberdyne.corp", "defense.mil", "justice.gov"]),
            blocked_domains: s(&["consumer-email.com", "social-media.com"]),
            biometric_required: true,
            pin_complexity: "high".into(),
            session_timeout: 30,
            encryption_level: "AES-256-GCM".into(),
            key_rotation_interval: 24,
            quantum_safe_enabled: true,
        }
    }
}

impl ApplicationConfig {
    /// Console-provided values a real app would receive from UEM.
    pub fn mock() -> Self {
        ApplicationConfig {
            app_host: Some("gd.cyberdyne.corp".into()),
            app_port: Some(443),
            app_servers: Some(vec![AppServer {
                server: Some("gw1.cyberdyne.corp".into()),
                port: Some(443),
                priority: Some(1),
            }]),
            communication_protocols: Some(BTreeMap::from([("TLSv1.2".into(), true), ("TLSv1.3".into(), true)])),
            container_id: Some("hast-container-01".into()),
            copy_paste_on: Some(true),
            detailed_logs_on: Some(false),
            enterprise_id: Some("com.hast.messaging".into()),
            enterprise_id_activated: Some(true),
            enterprise_id_features: Some(vec!["messaging".into()]),
            extra_info: Some(BTreeMap::new()),
            keyboard_restricted_mode: Some(false),
            prevent_android_dictation: Some(false),
            prevent_dictation: Some(false),
            prevent_keyboard_extensions: Some(false),
            prevent_paste_from_non_gd_apps: Some(false),
            prevent_screen_capture: Some(false),
            prevent_user_detailed_logs: Some(false),
            prevent_custom_keyboards: Some(false),
            prevent_screen_recording: Some(false),
            protected_by_password: Some(true),
            upn: Some("s.connor@cyberdyne.corp".into()),
            user_id: Some("sconnor".into()),
        }
    }

    /// DLP toggles of the settings panel mapped onto the real config flags.
    pub fn with_settings(mut self, s: &Settings) -> Self {
        self.copy_paste_on = Some(!s.copy_paste_restriction);
        self.prevent_paste_from_non_gd_apps = Some(s.copy_paste_restriction);
        self.prevent_screen_capture = Some(s.screenshot_blocking);
        self.prevent_screen_recording = Some(s.screenshot_blocking);
        self
    }
}

impl Settings {
    /// Everything that has no `ApplicationConfig` field travels as application policy
    /// (what `getApplicationPolicy()` would return).
    pub fn to_policy(&self) -> Value {
        json!({
            "watermarking": self.watermarking,
            "files": { "secureWipeTimerHours": self.secure_wipe_timer, "allowedFileTypes": self.allowed_file_types, "maxFileSizeMB": self.max_file_size },
            "network": { "vpnPassthrough": self.vpn_passthrough, "allowedDomains": self.allowed_domains, "blockedDomains": self.blocked_domains },
            "authentication": { "biometricRequired": self.biometric_required, "pinComplexity": self.pin_complexity, "sessionTimeoutMinutes": self.session_timeout },
            "encryption": { "algorithm": self.encryption_level, "keyRotationIntervalHours": self.key_rotation_interval, "quantumSafe": self.quantum_safe_enabled },
        })
    }
}

// ---- BlackBerryDynamicsService mock ----

/// Stands in for the GD runtime: `initialize` creates a random container key, and messages are sealed with
/// XChaCha20-Poly1305 under it (the real SDK keeps such a key inside its secure container).
#[derive(Default)]
pub struct BlackBerryDynamics {
    container_key: Option<[u8; 32]>,
}

impl BlackBerryDynamics {
    pub fn initialize(&mut self) {
        let mut k = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut k);
        self.container_key = Some(k);
    }

    pub fn encrypt_message(&self, message: &str) -> Result<String, &'static str> {
        let key = self.container_key.as_ref().ok_or("SDK not initialized")?;
        Ok(crate::pq::encrypt_local(key, message))
    }

    pub fn decrypt_message(&self, encrypted: &str) -> Result<String, &'static str> {
        let key = self.container_key.as_ref().ok_or("SDK not initialized")?;
        crate::pq::decrypt_local(key, encrypted).ok_or("Decryption failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_serializes_with_sdk_field_names() {
        let v = serde_json::to_value(ApplicationConfig::mock()).unwrap();
        for k in ["appHost", "preventScreenCapture", "enterpriseIdActivated", "preventPasteFromNonGDApps"] {
            assert!(v.get(k).is_some(), "missing {k}");
        }
    }

    #[test]
    fn dlp_toggles_map_to_flags() {
        let off = Settings {
            copy_paste_restriction: false,
            screenshot_blocking: false,
            ..Default::default()
        };
        let c = ApplicationConfig::mock().with_settings(&off);
        assert_eq!(
            (c.copy_paste_on, c.prevent_screen_capture, c.prevent_screen_recording),
            (Some(true), Some(false), Some(false))
        );
        let c = ApplicationConfig::mock().with_settings(&Settings::default());
        assert_eq!(
            (c.copy_paste_on, c.prevent_paste_from_non_gd_apps, c.prevent_screen_capture),
            (Some(false), Some(true), Some(true))
        );
    }

    #[test]
    fn mock_crypto_needs_init_and_roundtrips() {
        let mut sdk = BlackBerryDynamics::default();
        assert!(sdk.encrypt_message("hi").is_err());
        sdk.initialize();
        let enc = sdk.encrypt_message("hi: there").unwrap();
        assert!(!enc.contains("hi"));
        assert_eq!(sdk.decrypt_message(&enc).unwrap(), "hi: there");
        let mut other = BlackBerryDynamics::default();
        other.initialize();
        assert!(other.decrypt_message(&enc).is_err(), "another container cannot read it");
    }
}
