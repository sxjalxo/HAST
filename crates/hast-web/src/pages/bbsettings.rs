//! Port of components/BlackBerrySettingsPanel.tsx. The DLP switches drive the real SDK `ApplicationConfig`
//! flags; everything else is carried as application policy. A sixth "SDK Config" tab shows what
//! `getApplicationConfig()` / `getApplicationPolicy()` would return.
use crate::ui::*;
use crate::util::*;
use gloo_timers::future::TimeoutFuture;
use hast_core::bbd::{ApplicationConfig, Settings};
use leptos::prelude::*;
use leptos::task::spawn_local;

const STORE_KEY: &str = "gd:bbd-settings"; // AsyncStorage-style key, same `gd:` prefix as the other mock storage

fn load() -> Settings {
    ls_get(STORE_KEY).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn config_json(s: &Settings) -> String {
    serde_json::to_string_pretty(&ApplicationConfig::mock().with_settings(s)).unwrap_or_default()
}

fn policy_json(s: &Settings) -> String {
    serde_json::to_string_pretty(&s.to_policy()).unwrap_or_default()
}

#[component]
pub fn BlackBerrySettingsPanel() -> impl IntoView {
    let settings = RwSignal::new(load());
    let tab = RwSignal::new("security");
    let flash = RwSignal::new("");
    let say = move |msg: &'static str| {
        flash.set(msg);
        spawn_local(async move {
            TimeoutFuture::new(2000).await;
            flash.try_set("");
        });
    };
    let set = move |f: Box<dyn FnOnce(&mut Settings)>| settings.update(f);
    let num = move |e: leptos::ev::Event, f: fn(&mut Settings, i32)| {
        if let Ok(v) = event_target_value(&e).parse::<i32>() {
            settings.update(|s| f(s, v));
        }
    };

    let toggle_row = move |title: &'static str, desc: &'static str, get: fn(&Settings) -> bool, put: fn(&mut Settings, bool)| {
        view! {
            <div class="flex items-center justify-between">
                <div><h4 class="font-medium">{title}</h4><p class="text-sm text-hast-muted">{desc}</p></div>
                <Switch checked=Signal::derive(move || get(&settings.get())) on_change=Callback::new(move |v| settings.update(|s| put(s, v))) />
            </div>
        }
    };
    let tab_btn = move |id: &'static str, label: &'static str| {
        view! {
            <button class=move || format!("{TAB_SM} {}", if tab.get() == id { TAB_ACTIVE } else { "" }) on:click=move |_| tab.set(id)>{label}</button>
        }
    };
    let domain_list =
        move |blocked: bool| {
            move || {
                let s = settings.get();
                let (list, bg, text) = if blocked {
                    (s.blocked_domains, "bg-hast-danger/10 border-hast-danger/20", "text-hast-danger")
                } else {
                    (s.allowed_domains, "bg-hast-verified/10 border-hast-verified/20", "text-hast-verified")
                };
                list.into_iter().map(|d| {
                let dd = d.clone();
                view! {
                    <div class=format!("flex items-center justify-between p-2 rounded border {bg}")>
                        <span class=format!("text-sm font-mono {text}")>{d}</span>
                        <button class=format!("{BTN_BASE} {BTN_GHOST} {SZ_SM} text-hast-danger hover:text-hast-danger")
                            on:click=move |_| settings.update(|s| { let l = if blocked { &mut s.blocked_domains } else { &mut s.allowed_domains }; l.retain(|x| x != &dd); })>
                            <Icon name="trash-2" class="w-3 h-3" />
                        </button>
                    </div>
                }
            }).collect_view()
            }
        };
    let card = format!("{CARD} hast-panel p-6");

    view! {
        <div>
            <PageHeader icon="sliders" title="BB Dynamics" demo=true subtitle="Enterprise security policy configuration">
                <span class="text-xs text-hast-verified font-mono">{move || flash.get()}</span>
                        <button class=format!("{BTN_BASE} {BTN_OUTLINE} {SZ_SM}")
                            on:click=move |_| { let s = settings.get_untracked(); copy_text(&format!("{}\n{}", config_json(&s), policy_json(&s))); say("Config copied"); }>
                            <Icon name="download" class="w-4 h-4" />"Export Config"
                        </button>
                        <button class=format!("{BTN_BASE} {BTN_DEFAULT} {SZ_SM}")
                            on:click=move |_| { if let Ok(j) = serde_json::to_string(&settings.get_untracked()) { ls_set(STORE_KEY, &j); } say("Changes applied"); }>
                            <Icon name="upload" class="w-4 h-4" />"Apply Changes"
                        </button>
            </PageHeader>
            <div class="max-w-4xl mx-auto p-6 space-y-6">
                <div class="space-y-6">
                    <div class=format!("{TABS_LIST_MUTED} grid w-full grid-cols-6 bg-hast-surface")>
                        {tab_btn("security", "Security")}{tab_btn("files", "Files")}{tab_btn("network", "Network")}
                        {tab_btn("auth", "Authentication")}{tab_btn("encryption", "Encryption")}{tab_btn("sdk", "SDK Config")}
                    </div>

                    <div class="space-y-6" class:hidden=move || tab.get() != "security">
                        <div class=card.clone()>
                            <h3 class="text-lg font-semibold mb-4 flex items-center"><Icon name="lock" class="w-5 h-5 mr-2 text-hast-link" />"Data Leakage Prevention"</h3>
                            <div class="space-y-4">
                                {toggle_row("Copy/Paste Restriction", "Prevent copying sensitive data outside the app", |s| s.copy_paste_restriction, |s, v| s.copy_paste_restriction = v)}
                                {toggle_row("Screenshot Blocking", "Block screenshots and screen recording", |s| s.screenshot_blocking, |s, v| s.screenshot_blocking = v)}
                                {toggle_row("Dynamic Watermarking", "Add user identification to displayed content", |s| s.watermarking, |s, v| s.watermarking = v)}
                            </div>
                        </div>
                        <div class=card.clone()>
                            <h3 class="text-lg font-semibold mb-4 flex items-center"><Icon name="alert-triangle" class="w-5 h-5 mr-2 text-hast-warning" />"Security Status"</h3>
                            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                                <div class="text-center p-4 bg-hast-verified/10 rounded-lg border border-hast-verified/20"><Icon name="check-circle" class="w-8 h-8 text-hast-verified mx-auto mb-2" /><p class="text-sm font-medium text-hast-verified">"Policies Active"</p><p class="text-xs text-hast-muted">"All security policies enforced"</p></div>
                                <div class="text-center p-4 bg-hast-elevated rounded-lg border border-hast-border"><Icon name="shield" class="w-8 h-8 text-hast-muted mx-auto mb-2" /><p class="text-sm font-medium text-hast-secondary">"Compliance Score"</p><p class="text-lg font-mono font-semibold">"98.7%"</p></div>
                                <div class="text-center p-4 bg-hast-elevated rounded-lg border border-hast-border"><Icon name="clock" class="w-8 h-8 text-hast-muted mx-auto mb-2" /><p class="text-sm font-medium text-hast-secondary">"Last Audit"</p><p class="text-xs text-hast-muted">"2 hours ago"</p></div>
                            </div>
                        </div>
                    </div>

                    <div class="space-y-6" class:hidden=move || tab.get() != "files">
                        <div class=card.clone()>
                            <h3 class="text-lg font-semibold mb-4 flex items-center"><Icon name="file-x" class="w-5 h-5 mr-2 text-hast-danger" />"Secure File Management"</h3>
                            <div class="space-y-4">
                                <div>
                                    <label class="text-sm font-medium mb-2 block">"Secure Wipe Timer (hours)"</label>
                                    <input type="number" min="1" max="168" class=format!("{INPUT} hast-input w-32") prop:value=move || settings.get().secure_wipe_timer.to_string() on:input=move |e| num(e, |s, v| s.secure_wipe_timer = v) />
                                    <p class="text-xs text-hast-muted mt-1">"Files will be securely deleted after this period"</p>
                                </div>
                                <div>
                                    <label class="text-sm font-medium mb-2 block">"Maximum File Size (MB)"</label>
                                    <input type="number" min="1" max="500" class=format!("{INPUT} hast-input w-32") prop:value=move || settings.get().max_file_size.to_string() on:input=move |e| num(e, |s, v| s.max_file_size = v) />
                                </div>
                                <div>
                                    <label class="text-sm font-medium mb-2 block">"Allowed File Types"</label>
                                    <div class="flex flex-wrap gap-2">
                                        {move || settings.get().allowed_file_types.into_iter().map(|t| { let tt = t.clone(); view! {
                                            <span class=format!("{BADGE_OUTLINE} border-hast-verified text-hast-verified")>
                                                {format!(".{t}")}
                                                <button class="ml-1 hover:text-hast-danger" on:click=move |_| set(Box::new({ let tt = tt.clone(); move |s| s.allowed_file_types.retain(|x| x != &tt) }))>"×"</button>
                                            </span>
                                        } }).collect_view()}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="space-y-6" class:hidden=move || tab.get() != "network">
                        <div class=card.clone()>
                            <h3 class="text-lg font-semibold mb-4 flex items-center"><Icon name="globe" class="w-5 h-5 mr-2 text-hast-verified" />"Network Access Control"</h3>
                            <div class="space-y-6">
                                {toggle_row("VPN Passthrough", "Allow traffic through enterprise VPN", |s| s.vpn_passthrough, |s, v| s.vpn_passthrough = v)}
                                <div><h4 class="font-medium mb-3">"Allowed Domains"</h4><div class="space-y-2">{domain_list(false)}</div></div>
                                <div><h4 class="font-medium mb-3">"Blocked Domains"</h4><div class="space-y-2">{domain_list(true)}</div></div>
                            </div>
                        </div>
                    </div>

                    <div class="space-y-6" class:hidden=move || tab.get() != "auth">
                        <div class=card.clone()>
                            <h3 class="text-lg font-semibold mb-4 flex items-center"><Icon name="users" class="w-5 h-5 mr-2 text-hast-primary" />"Authentication & Access"</h3>
                            <div class="space-y-4">
                                {toggle_row("Biometric Authentication Required", "Enforce fingerprint/face recognition", |s| s.biometric_required, |s, v| s.biometric_required = v)}
                                <div>
                                    <label class="text-sm font-medium mb-2 block">"Session Timeout (minutes)"</label>
                                    <input type="number" min="5" max="480" class=format!("{INPUT} hast-input w-32") prop:value=move || settings.get().session_timeout.to_string() on:input=move |e| num(e, |s, v| s.session_timeout = v) />
                                </div>
                                <div>
                                    <label class="text-sm font-medium mb-2 block">"PIN Complexity"</label>
                                    <select class="hast-input w-48" prop:value=move || settings.get().pin_complexity on:change=move |e| { let v = event_target_value(&e); settings.update(|s| s.pin_complexity = v) }>
                                        <option value="low">"Low (4 digits)"</option>
                                        <option value="medium">"Medium (6 alphanumeric)"</option>
                                        <option value="high">"High (8+ mixed characters)"</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="space-y-6" class:hidden=move || tab.get() != "encryption">
                        <div class=card.clone()>
                            <h3 class="text-lg font-semibold mb-4 flex items-center"><Icon name="lock" class="w-5 h-5 mr-2 text-hast-link" />"Encryption Configuration"</h3>
                            <div class="space-y-4">
                                <div>
                                    <label class="text-sm font-medium mb-2 block">"Encryption Algorithm"</label>
                                    <select class="hast-input w-64" prop:value=move || settings.get().encryption_level on:change=move |e| { let v = event_target_value(&e); settings.update(|s| s.encryption_level = v) }>
                                        <option value="AES-256-GCM">"AES-256-GCM (Military Grade)"</option>
                                        <option value="ChaCha20-Poly1305">"ChaCha20-Poly1305 (High Performance)"</option>
                                        <option value="CRYSTALS-Kyber">"CRYSTALS-Kyber (Quantum Safe)"</option>
                                    </select>
                                </div>
                                <div>
                                    <label class="text-sm font-medium mb-2 block">"Key Rotation Interval (hours)"</label>
                                    <input type="number" min="1" max="168" class=format!("{INPUT} hast-input w-32") prop:value=move || settings.get().key_rotation_interval.to_string() on:input=move |e| num(e, |s, v| s.key_rotation_interval = v) />
                                </div>
                                {toggle_row("Quantum-Safe Cryptography", "Enable post-quantum encryption algorithms", |s| s.quantum_safe_enabled, |s, v| s.quantum_safe_enabled = v)}
                                <div class="mt-6 p-4 bg-hast-link/10 rounded-lg border border-hast-link/20">
                                    <div class="flex items-center space-x-2 mb-2"><Icon name="lock" class="w-5 h-5 text-hast-link" /><h4 class="font-medium text-hast-link">"Current Encryption Status"</h4></div>
                                    <div class="grid grid-cols-2 gap-4 text-sm">
                                        <div><span class="text-hast-muted">"Algorithm:"</span><span class="ml-2 font-mono">{move || settings.get().encryption_level}</span></div>
                                        <div><span class="text-hast-muted">"Key Strength:"</span><span class="ml-2 font-mono text-hast-verified">"256-bit"</span></div>
                                        <div><span class="text-hast-muted">"Last Rotation:"</span><span class="ml-2 font-mono">"2 hours ago"</span></div>
                                        <div><span class="text-hast-muted">"Quantum Safe:"</span>
                                            <span class=move || format!("ml-2 font-mono {}", if settings.get().quantum_safe_enabled { "text-hast-verified" } else { "text-hast-warning" })>{move || if settings.get().quantum_safe_enabled { "Active" } else { "Disabled" }}</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="space-y-6" class:hidden=move || tab.get() != "sdk">
                        <div class=card.clone()>
                            <h3 class="text-lg font-semibold mb-1 flex items-center"><Icon name="settings-2" class="w-5 h-5 mr-2 text-hast-link" />"getApplicationConfig()"</h3>
                            <p class="text-xs text-hast-muted mb-3">"BlackBerry-Dynamics-for-React-Native-Application · DLP switches map to copyPasteOn, preventPasteFromNonGDApps, preventScreenCapture, preventScreenRecording. Mocked: no UEM console here."</p>
                            <pre class="hast-input p-3 font-mono text-xs overflow-x-auto whitespace-pre">{move || config_json(&settings.get())}</pre>
                        </div>
                        <div class=card.clone()>
                            <h3 class="text-lg font-semibold mb-1 flex items-center"><Icon name="settings-2" class="w-5 h-5 mr-2 text-hast-link" />"getApplicationPolicy()"</h3>
                            <p class="text-xs text-hast-muted mb-3">"Free-form policy object: the settings that have no ApplicationConfig field."</p>
                            <pre class="hast-input p-3 font-mono text-xs overflow-x-auto whitespace-pre">{move || policy_json(&settings.get())}</pre>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    }
}
