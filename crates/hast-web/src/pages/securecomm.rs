//! Ports of components/SecureMessenger.tsx, CryptoStrengthIndicator.tsx and BlackBerryDynamicsPanel.tsx
use crate::ui::*;
use crate::util::*;
use gloo_timers::future::TimeoutFuture;
use leptos::prelude::*;
use leptos::task::spawn_local;

#[derive(Clone)]
struct Msg {
    #[allow(dead_code)]
    id: String,
    sender: &'static str,
    sender_hash: &'static str,
    content: String,
    timestamp: String,
    ttl: &'static str,
    status: &'static str, // sending | sent | delivered | read
    message_key: String,
    quantum_safe: bool,
}

const LEVELS: [(&str, &str); 3] = [("AES-256-GCM", "AES-256"), ("ChaCha20-Poly1305", "ChaCha20"), ("CRYSTALS-Kyber", "Quantum-Safe")];

fn enc_color(level: &str) -> &'static str {
    match level {
        "AES-256-GCM" => "chip-verified",
        "ChaCha20-Poly1305" => "chip-warning",
        _ => "chip-verified",
    }
}

#[component]
pub fn SecureMessenger() -> impl IntoView {
    let messages = RwSignal::new(vec![
        Msg {
            id: "1".into(),
            sender: "Agent Alpha",
            sender_hash: "a7f3c9d2",
            content: "Secure channel established. All communications encrypted with AES-256-GCM.".into(),
            timestamp: "14:23:45".into(),
            ttl: "23h 36m",
            status: "read",
            message_key: "k1_9f8e7d6c".into(),
            quantum_safe: false,
        },
        Msg {
            id: "2".into(),
            sender: "Control",
            sender_hash: "b8e4d1f5",
            content: "Mission parameters updated. Switching to quantum-safe protocols.".into(),
            timestamp: "14:24:12".into(),
            ttl: "23h 35m",
            status: "delivered",
            message_key: "k2_3a2b1c9d".into(),
            quantum_safe: true,
        },
    ]);
    let input = RwSignal::new(String::new());
    let level = RwSignal::new("AES-256-GCM");
    let gd_connected = RwSignal::new(false);
    let show_enc = RwSignal::new(false);
    let channel = RwSignal::new("command");
    let alive = alive_flag();

    // simulated delivery receipts
    spawn_local(async move {
        while is_alive(&alive) {
            TimeoutFuture::new(2000).await;
            if !is_alive(&alive) {
                break;
            }
            messages.update(|m| {
                for x in m.iter_mut() {
                    x.status = match x.status {
                        "sending" => "sent",
                        "sent" if random() > 0.7 => "delivered",
                        "delivered" if random() > 0.8 => "read",
                        s => s,
                    };
                }
            });
        }
    });

    let send = move || {
        let text = input.get_untracked();
        if text.trim().is_empty() {
            return;
        }
        let lv = level.get_untracked();
        messages.update(|m| {
            m.push(Msg {
                id: (now_ms() as u64).to_string(),
                sender: "You",
                sender_hash: "f9a8b7c6",
                content: text,
                timestamp: time_hms(now_ms()),
                ttl: "24h 00m",
                status: "sending",
                message_key: format!("k{}_{}", now_ms() as u64, rand_id(8)),
                quantum_safe: lv == "CRYSTALS-Kyber",
            })
        });
        input.set(String::new());
        spawn_local(async {
            TimeoutFuture::new(100).await;
            scroll_to_bottom("sc-msgs");
        });
    };

    let channels: [(&str, &str, u32); 3] = [("command", "Command", 3), ("ops", "Operations", 7), ("intel", "Intelligence", 2)];

    view! {
        <div class="min-h-full bg-hast-bg">
            <PageHeader icon="shield-check" title="SecureComm" demo=true subtitle="End-to-end encrypted channels over BlackBerry Dynamics">
                <span class=format!("{BADGE} chip-neutral")><Icon name="lock" class="w-3 h-3 mr-1" />"E2EE"</span>
                <span class=move || format!("{BADGE} font-mono {}", if gd_connected.get() { "chip-verified" } else { "chip-neutral" })>
                                <Icon name="smartphone" class="w-3 h-3" />{move || format!("GD {}", if gd_connected.get() { "Connected" } else { "Offline" })}
                            </span>
                            <button class=format!("{BTN_BASE} {BTN_GHOST} {SZ_SM}")><Icon name="settings" class="w-4 h-4" /></button>
            </PageHeader>

            <div class="container mx-auto px-4 py-6">
                <div class="grid grid-cols-1 lg:grid-cols-4 gap-6">
                    <div class="lg:col-span-1 space-y-4">
                        <div class=format!("{CARD} hast-panel p-4")>
                            <h3 class="hast-title text-sm mb-3 flex items-center"><Icon name="users" class="w-4 h-4 mr-2" />"Secure Channels"</h3>
                            <div class="space-y-2">
                                {channels.iter().map(|&(id, name, n)| view! {
                                    <button on:click=move |_| channel.set(id)
                                        class=move || format!("w-full p-2 rounded-lg text-left transition-all {}", if channel.get() == id { "bg-hast-primary/10 border border-hast-primary/40" } else { "border border-transparent" })>
                                        <div class="flex items-center justify-between">
                                            <span class="font-mono text-sm">{format!("# {name}")}</span>
                                            <div class="flex items-center space-x-1"><span class="text-xs text-hast-muted">{n}</span><Icon name="lock" class="w-3 h-3 text-hast-verified" /></div>
                                        </div>
                                    </button>
                                }).collect_view()}
                            </div>
                        </div>
                        <CryptoStrengthIndicator algorithm=Signal::derive(move || level.get().to_string()) key_length=256
                            quantum_resistant=Signal::derive(move || level.get() == "CRYSTALS-Kyber") is_blackberry=Signal::derive(move || gd_connected.get()) />
                        <BlackBerryDynamicsPanel is_connected=Signal::derive(move || gd_connected.get()) on_toggle=Callback::new(move |_| gd_connected.update(|c| *c = !*c)) />
                    </div>

                    <div class="lg:col-span-3">
                        <div class=format!("{CARD} hast-panel h-[calc(100vh-200px)] flex flex-col")>
                            <div class="p-4 border-b border-hast-border">
                                <div class="flex items-center justify-between">
                                    <div class="flex items-center space-x-3">
                                        <span class="relative flex h-8 w-8 shrink-0 overflow-hidden rounded-full w-8 h-8">
                                            <span class="flex h-full w-full items-center justify-center rounded-md border border-hast-border bg-hast-elevated text-hast-text text-xs">{move || channel.get().chars().next().unwrap_or(' ').to_uppercase().to_string()}</span>
                                        </span>
                                        <div>
                                            <h2 class="font-semibold">{move || format!("#{}", channel.get())}</h2>
                                            <p class="text-xs text-hast-muted font-mono">{move || format!("{} participants • End-to-end encrypted", channels.iter().find(|c| c.0 == channel.get()).map(|c| c.2).unwrap_or(0))}</p>
                                        </div>
                                    </div>
                                    <div class="flex items-center space-x-2">
                                        <button class=format!("{BTN_BASE} {BTN_GHOST} {SZ_SM}") on:click=move |_| show_enc.update(|s| *s = !*s)>
                                            {move || if show_enc.get() { view! { <Icon name="eye-off" class="w-4 h-4" /> }.into_any() } else { view! { <Icon name="eye" class="w-4 h-4" /> }.into_any() }}
                                        </button>
                                        <span class=move || format!("{BADGE_OUTLINE} {}", enc_color(level.get()))><Icon name="key" class="w-3 h-3 mr-1" />{move || level.get()}</span>
                                    </div>
                                </div>
                            </div>

                            <div id="sc-msgs" class="flex-1 p-4 overflow-y-auto">
                                <div class="space-y-4">
                                    {move || messages.get().into_iter().map(|m| {
                                        let me = m.sender == "You";
                                        let shown = if show_enc.get() { format!("🔒 {}...", btoa(&m.content).chars().take(40).collect::<String>()) } else { m.content.clone() };
                                        let status_icon = match m.status {
                                            "sending" => view! { <Icon name="clock" class="w-3 h-3 text-hast-muted animate-spin" /> }.into_any(),
                                            "sent" => view! { <Icon name="check-circle-2" class="w-3 h-3 text-hast-muted" /> }.into_any(),
                                            "delivered" => view! { <Icon name="check" class="w-3 h-3 text-hast-muted" /> }.into_any(),
                                            _ => view! { <Icon name="check-circle-2" class="w-3 h-3 text-hast-secondary" /> }.into_any(),
                                        };
                                        view! {
                                            <div class=format!("flex {}", if me { "justify-end" } else { "justify-start" })>
                                                <div class=format!("max-w-[70%] {}", if me { "order-2" } else { "order-1" })>
                                                    <div class=format!("rounded-lg p-3 {}", if me { "bg-hast-elevated text-hast-text border border-hast-border border-r-2 border-r-hast-primary" } else { "bg-hast-surface border border-hast-border" })>
                                                        <div class="flex items-center justify-between mb-1">
                                                            <div class="flex items-center space-x-2">
                                                                <span class="text-xs font-mono opacity-70">{format!("{} • {}", m.sender, m.sender_hash)}</span>
                                                                {m.quantum_safe.then(|| view! {
                                                                    <span class=format!("{BADGE} chip-verified text-xs")><Icon name="zap" class="w-3 h-3 mr-1" />"QS"</span>
                                                                })}
                                                            </div>
                                                            <span class="text-xs opacity-70">{m.timestamp.clone()}</span>
                                                        </div>
                                                        <p class="text-sm">{shown}</p>
                                                        <div class="flex items-center justify-between mt-2 text-xs opacity-70">
                                                            <div class="flex items-center space-x-2">
                                                                <span class="font-mono">{format!("TTL: {}", m.ttl)}</span>
                                                                <span class="font-mono">{format!("Key: {}", m.message_key)}</span>
                                                            </div>
                                                            <div class="flex items-center space-x-1">
                                                                <Icon name="shield" class="w-3 h-3 text-hast-verified" />
                                                                {status_icon}
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        }
                                    }).collect_view()}
                                </div>
                            </div>

                            <div class="p-4 border-t border-hast-border">
                                <div class=format!("{TABS_LIST_MUTED} grid w-full grid-cols-3 mb-3")>
                                    {LEVELS.iter().map(|&(v, label)| view! {
                                        <button class=move || format!("{TAB_SM} text-xs {}", if level.get() == v { TAB_ACTIVE } else { "" }) on:click=move |_| level.set(v)>{label}</button>
                                    }).collect_view()}
                                </div>
                                <div class="flex space-x-2">
                                    <input class=format!("{INPUT} hast-input flex-1") placeholder="Type secure message..." prop:value=move || input.get()
                                        on:input=move |e| input.set(event_target_value(&e)) on:keypress=move |e| if e.key() == "Enter" { send() } />
                                    <button class=format!("{BTN_BASE} {BTN_DEFAULT} {SZ_MD}") disabled=move || input.get().trim().is_empty() on:click=move |_| send()><Icon name="send" class="w-4 h-4" /></button>
                                </div>
                                <div class="flex items-center justify-between mt-2 text-xs text-hast-muted">
                                    <div class="flex items-center space-x-2"><Icon name="lock" class="w-3 h-3" /><span>{move || format!("Messages are end-to-end encrypted with {}", level.get())}</span></div>
                                    <div class="flex items-center space-x-1"><Icon name="globe" class="w-3 h-3" /><span>"Via BlackBerry Infrastructure"</span></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    }
}

#[component]
fn CryptoStrengthIndicator(
    #[prop(into)] algorithm: Signal<String>,
    key_length: u32,
    #[prop(into)] quantum_resistant: Signal<bool>,
    #[prop(into)] is_blackberry: Signal<bool>,
) -> impl IntoView {
    let entropy = RwSignal::new(0.0f64);
    let cpu = RwSignal::new(0.0f64);
    let alive = alive_flag();
    spawn_local(async move {
        while is_alive(&alive) {
            TimeoutFuture::new(2000).await;
            if is_alive(&alive) {
                entropy.set(random() * 100.0);
                cpu.set(random() * 30.0 + 10.0);
            }
        }
    });
    let strength = Memo::new(move |_| {
        let base = match algorithm.get().as_str() {
            "AES-256" | "ChaCha20" => 85.0,
            "AES-128" => 70.0,
            "RSA-2048" => 75.0,
            "RSA-4096" => 90.0,
            "ECC-P256" => 80.0,
            "CUSTOM" => 60.0,
            _ => 50.0,
        };
        let key_bonus = ((key_length as f64 / 256.0) * 10.0).min(15.0);
        let q = if quantum_resistant.get() { 20.0 } else { 0.0 };
        let bb = if is_blackberry.get() { 15.0 } else { 0.0 };
        (base + key_bonus + q + bb).min(100.0)
    });
    let color = move || {
        let s = strength.get();
        if s >= 90.0 {
            "text-hast-verified border-hast-verified/40"
        } else if s >= 75.0 {
            "text-hast-link border-hast-link/40"
        } else if s >= 60.0 {
            "text-hast-warning border-hast-warning"
        } else {
            "text-hast-danger border-hast-danger"
        }
    };
    let text = move || {
        let s = strength.get();
        if s >= 90.0 {
            "MILITARY GRADE"
        } else if s >= 75.0 {
            "HIGH SECURITY"
        } else if s >= 60.0 {
            "STANDARD"
        } else {
            "WEAK"
        }
    };
    view! {
        <div class=format!("{CARD} hast-panel p-4")>
            <div class="space-y-3">
                <div class="flex items-center justify-between">
                    <div class="flex items-center space-x-2"><Icon name="shield" class="w-4 h-4 text-hast-muted" /><span class="text-sm font-medium hast-title">"Crypto strength"</span></div>
                    <span class=move || format!("{BADGE_OUTLINE} {}", color())>{text}</span>
                </div>
                <div class="flex items-center justify-between text-sm">
                    <span class="text-hast-muted">"Algorithm:"</span>
                    <div class="flex items-center space-x-2">
                        <span class="font-mono">{move || algorithm.get()}</span>
                        {move || quantum_resistant.get().then(|| view! { <span class=format!("{BADGE_OUTLINE} text-hast-text border-hast-primary/60 text-xs")><Icon name="zap" class="w-3 h-3 mr-1" />"QUANTUM"</span> })}
                        {move || is_blackberry.get().then(|| view! { <span class=format!("{BADGE_OUTLINE} text-hast-link border-hast-link/40 text-xs")>"BB"</span> })}
                    </div>
                </div>
                <div class="flex items-center justify-between text-sm"><span class="text-hast-muted">"Key Length:"</span><span class="font-mono">{format!("{key_length} bits")}</span></div>
                <div class="space-y-2">
                    <div class="flex items-center justify-between text-xs">
                        <span class="text-hast-muted">"Encryption Strength"</span>
                        <span class=move || format!("font-medium {}", color().split(' ').next().unwrap_or(""))>{move || format!("{:.0}%", strength.get())}</span>
                    </div>
                    <div class="crypto-strength-indicator">
                        {move || {
                            let active = ((strength.get() / 100.0) * 10.0).ceil() as usize;
                            let q = quantum_resistant.get();
                            (0..10usize).map(|i| {
                                let cls = if i < active { if q && i >= 8 { "quantum" } else { "active" } } else { "" };
                                view! { <div class=format!("strength-bar {cls}") style=format!("animation-delay:{}s", i as f64 * 0.1)></div> }
                            }).collect_view()
                        }}
                    </div>
                </div>
                <div class="grid grid-cols-2 gap-3 pt-2 border-t border-hast-border">
                    <div class="space-y-1">
                        <div class="flex items-center space-x-1 text-xs text-hast-muted"><Icon name="activity" class="w-3 h-3" /><span>"Entropy"</span></div>
                        <div class="text-sm font-mono">{move || format!("{:.1}%", entropy.get())}</div>
                        <div class="w-full bg-hast-elevated rounded-full h-1"><div class="bg-hast-secondary h-1 rounded-full transition-all duration-500" style=move || format!("width:{}%", entropy.get())></div></div>
                    </div>
                    <div class="space-y-1">
                        <div class="flex items-center space-x-1 text-xs text-hast-muted"><Icon name="cpu" class="w-3 h-3" /><span>"CPU Usage"</span></div>
                        <div class="text-sm font-mono">{move || format!("{:.1}%", cpu.get())}</div>
                        <div class="w-full bg-hast-elevated rounded-full h-1"><div class="bg-hast-warning h-1 rounded-full transition-all duration-500" style=move || format!("width:{}%", cpu.get())></div></div>
                    </div>
                </div>
                <div class="flex flex-wrap gap-1 pt-2 border-t border-hast-border">
                    <span class=format!("{BADGE_OUTLINE} text-xs")><Icon name="lock" class="w-3 h-3 mr-1" />"E2E Encrypted"</span>
                    <span class=format!("{BADGE_OUTLINE} text-xs")><Icon name="eye" class="w-3 h-3 mr-1" />"Forward Secrecy"</span>
                    {move || is_blackberry.get().then(|| view! { <span class=format!("{BADGE_OUTLINE} text-hast-link border-hast-link/40 text-xs")><Icon name="hard-drive" class="w-3 h-3 mr-1" />"Containerized"</span> })}
                </div>
            </div>
        </div>
    }
}

#[component]
fn BlackBerryDynamicsPanel(#[prop(into)] is_connected: Signal<bool>, on_toggle: Callback<()>) -> impl IntoView {
    let status = RwSignal::new("disconnected"); // connecting | connected | disconnected
    let container = RwSignal::new("secured"); // secured | initializing | error
    let latency = RwSignal::new(0.0f64);
    let throughput = RwSignal::new(0.0f64);
    let epoch = RwSignal::new(0u32);
    let alive = alive_flag();

    Effect::new(move |_| {
        epoch.update(|e| *e += 1);
        let my = epoch.get_untracked();
        if is_connected.get() {
            status.set("connecting");
            let (alive, alive2) = (alive.clone(), alive.clone());
            spawn_local(async move {
                TimeoutFuture::new(2000).await;
                if is_alive(&alive) && epoch.get_untracked() == my {
                    status.set("connected");
                    latency.set(random() * 50.0 + 10.0);
                    throughput.set(random() * 500.0 + 200.0);
                }
            });
            spawn_local(async move {
                let alive = alive2;
                while is_alive(&alive) && epoch.get_untracked() == my {
                    TimeoutFuture::new(3000).await;
                    if is_alive(&alive) && epoch.get_untracked() == my {
                        latency.update(|l| *l += (random() - 0.5) * 10.0);
                        throughput.update(|t| *t += (random() - 0.5) * 100.0);
                    }
                }
            });
        } else {
            status.set("disconnected");
        }
    });

    let establish = move || {
        if status.get_untracked() == "disconnected" {
            on_toggle.run(());
            container.set("initializing");
            spawn_local(async move {
                TimeoutFuture::new(1500).await;
                container.try_set("secured");
            });
        } else {
            on_toggle.run(());
            status.set("disconnected");
            container.set("secured");
        }
    };

    let feature = |icon: &'static str, label: &'static str| {
        view! {
            <div class="flex items-center justify-between text-xs">
                <div class="flex items-center space-x-2"><Icon name=icon class="w-3 h-3 text-hast-verified" /><span>{label}</span></div>
                <Icon name="check-circle" class="w-3 h-3 text-hast-verified" />
            </div>
        }
    };

    view! {
        <div class=move || format!("{CARD} hast-panel p-6 {}", if is_connected.get() { "bb-secure-channel" } else { "" })>
            <div class="space-y-4">
                <div class="flex items-center justify-between">
                    <div class="flex items-center space-x-2"><Icon name="smartphone" class="w-5 h-5 text-hast-link" /><h3 class="text-lg font-semibold text-hast-link">"BlackBerry Dynamics"</h3></div>
                    <span class=move || format!("{BADGE_OUTLINE} font-mono text-xs {}", match status.get() { "connected" => "status-blackberry", "connecting" => "status-warning", _ => "status-danger" })>
                        {move || match status.get() { "connected" => "SECURE TUNNEL ACTIVE", "connecting" => "ESTABLISHING CONNECTION", _ => "DISCONNECTED" }}
                    </span>
                </div>
                <div class="space-y-3">
                    <button class=move || format!("{BTN_BASE} {SZ_MD} w-full {}", if is_connected.get() { "border border-hast-danger/50 bg-hast-danger/10 text-hast-danger hover:bg-hast-danger/20" } else { BTN_DEFAULT })
                        disabled=move || status.get() == "connecting" on:click=move |_| establish()>
                        {move || if status.get() == "connecting" { view! { <Icon name="activity" class="w-4 h-4 mr-2 animate-spin" />"Establishing Secure Channel..." }.into_any() }
                            else if is_connected.get() { view! { <Icon name="shield" class="w-4 h-4 mr-2" />"Disconnect Secure Channel" }.into_any() }
                            else { view! { <Icon name="lock" class="w-4 h-4 mr-2" />"Establish Secure Channel" }.into_any() }}
                    </button>
                    {move || (status.get() == "connecting").then(|| view! {
                        <div class="space-y-2">
                            <div class="text-xs text-hast-muted">"Initializing BlackBerry Dynamics SDK..."</div>
                            <div class="w-full bg-hast-elevated rounded-full h-2"><div class="bg-neon-blue h-2 rounded-full animate-data-stream w-1/3"></div></div>
                        </div>
                    })}
                </div>

                {move || (is_connected.get() && status.get() == "connected").then(|| view! {
                    <div class="space-y-4 pt-4 border-t border-hast-link/40/30">
                        <div class="grid grid-cols-2 gap-4">
                            <div class="space-y-1"><div class="flex items-center space-x-1 text-xs text-hast-muted"><Icon name="key" class="w-3 h-3" /><span>"Encryption"</span></div><div class="text-sm font-mono text-hast-link">"AES-256"</div></div>
                            <div class="space-y-1"><div class="flex items-center space-x-1 text-xs text-hast-muted"><Icon name="shield" class="w-3 h-3" /><span>"Key Strength"</span></div><div class="text-sm font-mono text-hast-link">"256 bits"</div></div>
                        </div>
                        <div class="grid grid-cols-2 gap-4">
                            <div class="space-y-1">
                                <div class="flex items-center space-x-1 text-xs text-hast-muted"><Icon name="zap" class="w-3 h-3" /><span>"Latency"</span></div>
                                <div class="text-sm font-mono">{move || format!("{:.1} ms", latency.get())}</div>
                                <div class="w-full bg-hast-elevated rounded-full h-1"><div class="bg-neon-blue h-1 rounded-full transition-all duration-500" style=move || format!("width:{}%", (100.0 - latency.get()).max(0.0))></div></div>
                            </div>
                            <div class="space-y-1">
                                <div class="flex items-center space-x-1 text-xs text-hast-muted"><Icon name="activity" class="w-3 h-3" /><span>"Throughput"</span></div>
                                <div class="text-sm font-mono">{move || format!("{:.0} Mbps", throughput.get())}</div>
                                <div class="w-full bg-hast-elevated rounded-full h-1"><div class="bg-neon-blue h-1 rounded-full transition-all duration-500" style=move || format!("width:{}%", (throughput.get() / 10.0).min(100.0))></div></div>
                            </div>
                        </div>
                        <div class="space-y-3">
                            <h4 class="text-sm font-medium text-hast-link">"Active Security Features"</h4>
                            <div class="grid grid-cols-1 gap-2">
                                {feature("hard-drive", "App Containerization")}
                                {feature("globe", "Secure Gateway")}
                                {feature("eye", "DLP Monitoring")}
                                {feature("server", "Enterprise Policies")}
                            </div>
                        </div>
                        <div class="pt-3 border-t border-hast-link/40/30">
                            <div class="flex items-center justify-between text-sm">
                                <div class="flex items-center space-x-2"><Icon name="hard-drive" class="w-4 h-4 text-hast-link" /><span>"Container Status"</span></div>
                                <span class=move || format!("{BADGE_OUTLINE} text-xs {}", match container.get() { "secured" => "text-hast-verified border-hast-verified/40", "initializing" => "text-hast-warning border-hast-warning", _ => "text-hast-danger border-hast-danger" })>
                                    {move || match container.get() {
                                        "secured" => view! { <Icon name="check-circle" class="w-3 h-3 mr-1" /> }.into_any(),
                                        "initializing" => view! { <Icon name="activity" class="w-3 h-3 mr-1 animate-spin" /> }.into_any(),
                                        _ => view! { <Icon name="alert-triangle" class="w-3 h-3 mr-1" /> }.into_any(),
                                    }}
                                    {move || container.get().to_uppercase()}
                                </span>
                            </div>
                        </div>
                    </div>
                })}

                <div class="pt-3 border-t border-hast-border">
                    <div class="text-xs text-hast-muted space-y-1">
                        <div>"• Enterprise-grade mobile security platform"</div>
                        <div>"• Secure app containerization and VPN tunneling"</div>
                        <div>"• Policy enforcement and remote management"</div>
                        <div>"• FIPS 140-2 Level 1 certified encryption"</div>
                    </div>
                </div>
            </div>
        </div>
    }
}
