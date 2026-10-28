//! Port of components/NetworkSimulatorExtended.tsx
use crate::ui::*;
use crate::util::*;
use gloo_timers::future::TimeoutFuture;
use leptos::prelude::*;
use leptos::task::spawn_local;

#[derive(Clone, PartialEq)]
struct Node {
    id: &'static str,
    kind: &'static str,
    name: &'static str,
    status: &'static str, // online | offline | warning | secure
    x: f64,
    y: f64,
    encrypted: bool,
    protocol: &'static str,
    blackberry: bool,
    tunnel: bool,
}

#[derive(Clone, PartialEq)]
struct Conn {
    id: &'static str,
    from: &'static str,
    to: &'static str,
    kind: &'static str, // standard | encrypted | bb-tunnel | vpn
    status: &'static str,
    throughput: f64,
    latency: f64,
}

#[allow(clippy::too_many_arguments)]
fn node(
    id: &'static str,
    kind: &'static str,
    name: &'static str,
    status: &'static str,
    x: f64,
    y: f64,
    encrypted: bool,
    protocol: &'static str,
    blackberry: bool,
    tunnel: bool,
) -> Node {
    Node {
        id,
        kind,
        name,
        status,
        x,
        y,
        encrypted,
        protocol,
        blackberry,
        tunnel,
    }
}

fn initial() -> (Vec<Node>, Vec<Conn>) {
    let nodes = vec![
        node("mobile1", "device", "Secure Mobile", "secure", 100.0, 300.0, true, "BB-Dynamics", true, true),
        node("bb-gateway", "bb-gateway", "BlackBerry Gateway", "secure", 300.0, 200.0, true, "AppKinetics", true, true),
        node("enterprise-server", "server", "Enterprise Server", "secure", 500.0, 150.0, true, "TLS 1.3", true, false),
        node("vpn-gateway", "vpn", "VPN Gateway", "online", 400.0, 350.0, true, "IPSec", false, false),
        node("internet", "internet", "Internet", "warning", 600.0, 400.0, false, "HTTP/HTTPS", false, false),
        node("threat-source", "device", "Threat Actor", "offline", 700.0, 300.0, false, "Malicious", false, false),
        node("internal-network", "router", "Internal Router", "online", 650.0, 100.0, true, "Internal", false, false),
    ];
    let c = |id, from, to, kind, status, throughput, latency| Conn {
        id,
        from,
        to,
        kind,
        status,
        throughput,
        latency,
    };
    let conns = vec![
        c("conn1", "mobile1", "bb-gateway", "bb-tunnel", "active", 95.0, 12.0),
        c("conn2", "bb-gateway", "enterprise-server", "bb-tunnel", "active", 98.0, 8.0),
        c("conn3", "bb-gateway", "vpn-gateway", "encrypted", "active", 85.0, 15.0),
        c("conn4", "vpn-gateway", "internet", "vpn", "active", 70.0, 25.0),
        c("conn5", "internet", "threat-source", "standard", "inactive", 0.0, 999.0),
        c("conn6", "enterprise-server", "internal-network", "encrypted", "active", 92.0, 5.0),
    ];
    (nodes, conns)
}

fn node_color(status: &str) -> &'static str {
    match status {
        "secure" => "text-hast-verified border-hast-verified bg-hast-verified/10",
        "online" => "text-hast-link border-hast-link/40 bg-hast-link/10",
        "warning" => "text-hast-warning border-hast-warning bg-hast-warning/10",
        "offline" => "text-hast-danger border-hast-danger bg-hast-danger/10",
        _ => "text-hast-muted border-hast-border bg-hast-elevated/10",
    }
}

/// (stroke class, badge class, bar class); the badge only gets border-* like the original's single .replace
fn conn_color(kind: &str) -> (&'static str, &'static str, &'static str) {
    match kind {
        "bb-tunnel" => ("stroke-hast-link", "border-hast-link/40", "bg-hast-link"),
        "encrypted" => ("stroke-hast-verified", "border-hast-verified/40", "bg-hast-verified"),
        "vpn" => ("stroke-hast-text", "border-hast-secondary", "bg-hast-text"),
        "standard" => ("stroke-hast-muted", "border-hast-muted", "bg-hast-muted"),
        _ => ("stroke-hast-border", "border-hast-border", "bg-hast-border"),
    }
}

fn node_icon(kind: &str) -> &'static str {
    match kind {
        "device" => "smartphone",
        "server" => "server",
        "router" => "router",
        "bb-gateway" => "shield",
        "vpn" => "lock",
        "internet" => "globe",
        _ => "network",
    }
}

#[component]
pub fn NetworkSimulatorExtended() -> impl IntoView {
    let (n0, c0) = initial();
    let nodes = RwSignal::new(n0);
    let conns = RwSignal::new(c0);
    let selected = RwSignal::<Option<Node>>::new(None);
    let running = RwSignal::new(false);
    let show_bb = RwSignal::new(true);
    let threat = RwSignal::new(0.0f64);
    let epoch = RwSignal::new(0u32);
    let alive = alive_flag();

    Effect::new(move |_| {
        epoch.update(|e| *e += 1);
        let my = epoch.get_untracked();
        if running.get() {
            let alive = alive.clone();
            spawn_local(async move {
                loop {
                    TimeoutFuture::new(2000).await;
                    if !is_alive(&alive) || epoch.get_untracked() != my {
                        break;
                    }
                    conns.update(|cs| {
                        for c in cs.iter_mut() {
                            c.throughput = (c.throughput + (random() - 0.5) * 10.0).max(0.0);
                            c.latency = (c.latency + (random() - 0.5) * 5.0).max(1.0);
                        }
                    });
                    threat.set(random() * 100.0);
                    nodes.update(|ns| {
                        for n in ns.iter_mut().filter(|n| n.id == "threat-source") {
                            if random() > 0.7 {
                                n.status = "warning";
                            }
                        }
                    });
                }
            });
        }
    });

    let reset = move || {
        running.set(false);
        let (n, c) = initial();
        nodes.set(n);
        conns.set(c);
        threat.set(0.0);
    };

    view! {
        <div>
            <PageHeader icon="network" title="Network Simulator" demo=true subtitle="BlackBerry Dynamics secure tunnels and VPN analysis">
                <button class=move || format!("{BTN_BASE} {BTN_OUTLINE} {SZ_SM} {}", if show_bb.get() { "border-hast-link/40 text-hast-link" } else { "" }) on:click=move |_| show_bb.update(|s| *s = !*s)><Icon name="shield" class="w-4 h-4" />"BB Tunnels"</button>
                        <button class=move || format!("{BTN_BASE} {BTN_OUTLINE} {SZ_SM} {}", if running.get() { "border-hast-verified text-hast-verified" } else { "" }) on:click=move |_| running.update(|r| *r = !*r)>
                            {move || if running.get() { view! { <Icon name="pause" class="w-4 h-4" /> }.into_any() } else { view! { <Icon name="play" class="w-4 h-4" /> }.into_any() }}
                            {move || if running.get() { "Pause Simulation" } else { "Start Simulation" }}
                        </button>
                        <button class=format!("{BTN_BASE} {BTN_OUTLINE} {SZ_SM}") on:click=move |_| reset()><Icon name="rotate-ccw" class="w-4 h-4" />"Reset"</button>
            </PageHeader>
            <div class="max-w-7xl mx-auto p-6 space-y-6">
                <div class="grid grid-cols-1 lg:grid-cols-4 gap-6">
                    <div class="lg:col-span-3">
                        <div class=format!("{CARD} hast-panel p-4 sm:p-6")>
                            <div class="flex flex-wrap items-center justify-between gap-2 mb-4">
                                <h3 class="hast-title text-lg">"Network Topology"</h3>
                                <div class="flex flex-wrap items-center gap-2">
                                    <span class=format!("{BADGE_OUTLINE} border-hast-verified text-hast-verified")><Icon name="activity" class="w-3 h-3 mr-1" />{move || format!("{:.0}% Threat Level", threat.get())}</span>
                                    <span class=format!("{BADGE_OUTLINE} border-hast-link/40 text-hast-link")><Icon name="shield" class="w-3 h-3 mr-1" />"BB-Dynamics Active"</span>
                                </div>
                            </div>
                            <div class="rounded-lg bg-hast-bg/20">
                                // one coordinate space for nodes, links and labels, scaled to the card's width
                                <svg viewBox="0 0 800 480" preserveAspectRatio="xMidYMid meet" class="block w-full h-auto">
                                    {move || {
                                        let ns = nodes.get();
                                        conns.get().into_iter().filter_map(|c| {
                                            let a = ns.iter().find(|n| n.id == c.from)?;
                                            let b = ns.iter().find(|n| n.id == c.to)?;
                                            if !(show_bb.get() || c.kind != "bb-tunnel") { return None; }
                                            let stroke = conn_color(c.kind).0;
                                            let op = if c.status == "active" { "opacity-80" } else { "opacity-30" };
                                            Some(view! {
                                                <g>
                                                    <line x1=a.x y1=a.y x2=b.x y2=b.y stroke-width=if c.kind == "bb-tunnel" { 3 } else { 2 }
                                                        stroke-dasharray=if c.kind == "bb-tunnel" { "5,5" } else { "none" } class=format!("{stroke} {op}") />
                                                    <circle cx=(a.x + b.x) / 2.0 cy=(a.y + b.y) / 2.0 r="3" class=format!("{stroke} fill-current") />
                                                </g>
                                            })
                                        }).collect_view()
                                    }}
                                    {move || nodes.get().into_iter().map(|n| {
                                        let n2 = n.clone();
                                        view! {
                                            <g>
                                                <circle cx=n.x cy=n.y r="30" class=format!("{} fill-hast-elevated stroke-current stroke-2 cursor-pointer", node_color(n.status)) on:click=move |_| selected.set(Some(n2.clone())) />
                                                {n.blackberry.then(|| view! { <circle cx=n.x + 20.0 cy=n.y - 20.0 r="8" class="fill-hast-link stroke-hast-link stroke-2" /> })}
                                                {(n.tunnel && show_bb.get()).then(|| view! { <circle cx=n.x cy=n.y r="35" class="fill-none stroke-hast-link stroke-2 opacity-50" stroke-dasharray="10,5" /> })}
                                            </g>
                                        }
                                    }).collect_view()}
                                    {move || nodes.get().into_iter().map(|n| view! {
                                        <text x=n.x y=n.y + 52.0 text-anchor="middle" class=format!("{} fill-current font-mono text-[12px] pointer-events-none", node_color(n.status))>{n.name}</text>
                                    }).collect_view()}
                                </svg>
                            </div>
                        </div>
                    </div>

                    <div class="space-y-6">
                        {move || selected.get().map(|n| view! {
                            <div class=format!("{CARD} hast-panel p-4")>
                                <h4 class="font-semibold mb-3 flex items-center"><Icon name=node_icon(n.kind) class="w-6 h-6" /><span class="ml-2">{n.name}</span></h4>
                                <div class="space-y-2 text-sm">
                                    <div class="flex justify-between"><span>"Type:"</span><span class="font-mono">{n.kind}</span></div>
                                    <div class="flex justify-between"><span>"Status:"</span><span class=format!("{BADGE_OUTLINE} text-xs {}", node_color(n.status))>{n.status}</span></div>
                                    <div class="flex justify-between"><span>"Protocol:"</span><span class="font-mono">{n.protocol}</span></div>
                                    <div class="flex justify-between"><span>"Encryption:"</span>
                                        <span class=format!("{BADGE_OUTLINE} text-xs {}", if n.encrypted { "border-hast-verified text-hast-verified" } else { "border-hast-danger text-hast-danger" })>{if n.encrypted { "Active" } else { "None" }}</span>
                                    </div>
                                    {n.blackberry.then(|| view! { <div class="flex justify-between"><span>"BB Dynamics:"</span><span class=format!("{BADGE_OUTLINE} border-hast-link/40 text-hast-link text-xs")>"Enabled"</span></div> })}
                                </div>
                            </div>
                        })}

                        <div class=format!("{CARD} hast-panel p-4")>
                            <h4 class="font-semibold mb-3">"Network Performance"</h4>
                            <div class="space-y-3">
                                {move || conns.get().into_iter().filter(|c| c.status == "active").map(|c| {
                                    let (_, badge, bar) = conn_color(c.kind);
                                    view! {
                                        <div class="space-y-1">
                                            <div class="flex justify-between text-xs">
                                                <span class="font-mono">{format!("{} → {}", c.from, c.to)}</span>
                                                <span class=format!("{BADGE_OUTLINE} text-xs {badge}")>{c.kind}</span>
                                            </div>
                                            <div class="flex justify-between text-xs text-hast-muted">
                                                <span>{format!("Throughput: {:.0}%", c.throughput)}</span><span>{format!("Latency: {:.0}ms", c.latency)}</span>
                                            </div>
                                            <div class="w-full bg-hast-elevated/30 rounded-full h-1"><div class=format!("h-1 rounded-full {bar}") style=format!("width:{}%", c.throughput)></div></div>
                                        </div>
                                    }
                                }).collect_view()}
                            </div>
                        </div>

                        <div class=format!("{CARD} hast-panel p-4")>
                            <h4 class="font-semibold mb-3">"Security Overview"</h4>
                            <div class="space-y-2 text-sm">
                                <div class="flex justify-between"><span>"BB Tunnels:"</span><span class="text-hast-link font-mono">{move || format!("{} Active", conns.get().iter().filter(|c| c.kind == "bb-tunnel").count())}</span></div>
                                <div class="flex justify-between"><span>"Encrypted Links:"</span><span class="text-hast-verified font-mono">{move || format!("{} Active", conns.get().iter().filter(|c| c.kind == "encrypted").count())}</span></div>
                                <div class="flex justify-between"><span>"Threat Level:"</span>
                                    <span class=move || format!("font-mono {}", { let t = threat.get(); if t > 70.0 { "text-hast-danger" } else if t > 40.0 { "text-hast-warning" } else { "text-hast-verified" } })>{move || format!("{:.0}%", threat.get())}</span>
                                </div>
                                <div class="flex justify-between"><span>"Quantum Safe:"</span><span class=format!("{BADGE_OUTLINE} border-hast-primary text-hast-text text-xs")>"Active"</span></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    }
}
