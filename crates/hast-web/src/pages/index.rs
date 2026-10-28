//! The overview: this account's real key state at a glance, and every module.
use super::livechat::{DAY_MS, KEM_MAX_AGE_MS, ROTATE_AFTER};
use crate::auth::{self, use_auth};
use crate::contacts::{directory, Dir};
use crate::ui::*;
use crate::util::*;
use leptos::prelude::*;
use leptos::task::spawn_local;
use std::collections::HashMap;

/// One line about each module, by path (the sidebar's `MODULES` gives the name and icon).
fn blurb(href: &str) -> &'static str {
    match href {
        "/chat" => "Encrypted rooms, signed with HBSS and SLH-DSA",
        "/messaging" => "Sealed messages over a noisy channel",
        "/account" => "Passkeys for signing in",
        "/hbss-lab" => "Benchmarks, hashes and the signing flow",
        "/hbss-explained" => "How hash-based signatures work",
        "/quantum-playground" => "Hamming codes and quantum key distribution",
        "/cipher-lab" => "Build and test cipher algorithms",
        "/cipher-chat" => "Legacy cipher messaging",
        "/securecomm" => "End-to-end encrypted messenger",
        "/network" => "Topology and attack simulation",
        "/blackberry" => "Enterprise secure chat",
        "/blackberry/settings" => "Dynamics policy configuration",
        _ => "",
    }
}

#[component]
pub fn Index() -> impl IntoView {
    let me = use_auth().username_untracked().unwrap_or_default();
    let members = RwSignal::new(None::<usize>);
    // this account's chain, verified here like anyone else's: (keys, recoveries), or None if it did not verify
    let chain = RwSignal::new(None::<Option<(usize, usize)>>);
    let uses = auth::key_uses(&me).min(ROTATE_AFTER);
    let kem_age_days = auth::load_lt(&me).filter(|k| k.kem_since > 0.0).map(|k| ((now_ms() - k.kem_since) / DAY_MS).floor() as u32);
    let alive = alive_flag();
    {
        let me = me.clone();
        spawn_local(async move {
            let n = auth::call("GET", "/api/directory", None).await.ok().and_then(|v| v["accounts"].as_array().map(Vec::len));
            if !is_alive(&alive) {
                return;
            }
            members.set(n);
            let d = directory(&me, &me, RwSignal::new(HashMap::new()), false).await;
            if is_alive(&alive) {
                chain.set(Some(match d {
                    Dir::Ok { roots, recoveries, .. } => Some((roots.len(), recoveries.len())),
                    Dir::Bad => None,
                }));
            }
        });
    }

    let stat = |label: &'static str, icon: &'static str, body: AnyView| {
        view! {
            <div class="hast-panel p-4">
                <div class="flex items-center justify-between mb-3"><span class="hast-label">{label}</span><Icon name=icon class="w-4 h-4 text-hast-muted" /></div>
                {body}
            </div>
        }
    };
    let loading = || view! { <div class="h-8 w-12 rounded bg-hast-elevated animate-pulse"></div> };
    let modules = MODULES
        .iter()
        .flat_map(|(_, items)| items.iter())
        .filter(|(href, ..)| *href != "/")
        .map(|&(href, label, icon, demo)| {
            view! {
                <a href=href class="group hast-panel flex items-start gap-3 p-4 hover:border-hast-muted/70 hover:bg-hast-elevated/40">
                    <div class="flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-hast-border bg-hast-elevated">
                        <Icon name=icon class="w-4 h-4 text-hast-secondary group-hover:text-hast-primary transition-colors" />
                    </div>
                    <div class="min-w-0 flex-1">
                        <div class="flex items-center gap-2 text-sm font-medium text-hast-text">{label}{demo.then(|| view! { <DemoTag /> })}</div>
                        <div class="text-xs text-hast-muted">{blurb(href)}</div>
                    </div>
                </a>
            }
        })
        .collect_view();

    view! {
        <div>
            <PageHeader icon="layout-grid" title="Overview" subtitle="Your keys at a glance, and every HAST module">
                <span class=format!("{BADGE} chip-verified")><Icon name="shield-check" class="w-3 h-3 mr-1" />"Keys unlocked"</span>
            </PageHeader>
            <div class="max-w-6xl mx-auto p-6 space-y-6">
                <div class="hast-panel relative overflow-hidden p-6">
                    <div class="absolute inset-y-0 left-0 w-[3px] bg-hast-primary"></div>
                    <div class="flex flex-wrap items-center justify-between gap-6">
                        <div class="flex items-start gap-4">
                            <div class="flex h-12 w-12 shrink-0 items-center justify-center rounded-md border border-hast-border bg-hast-elevated"><Icon name="message-square" class="w-5 h-5 text-hast-text" /></div>
                            <div>
                                <h2 class="hast-title text-xl">"HAST LiveChat"</h2>
                                <p class="text-sm text-hast-secondary">"Post-quantum secure messaging: every message sealed with ML-KEM-768 and signed with HBSS and SLH-DSA."</p>
                                <div class="mt-3 flex flex-wrap gap-2 font-mono text-[11px]">
                                    <span class=format!("{BADGE} chip-neutral")>"ML-KEM-768"</span>
                                    <span class=format!("{BADGE} chip-neutral")>"SLH-DSA-SHAKE-128f"</span>
                                    <span class=format!("{BADGE} chip-neutral")>"HBSS"</span>
                                </div>
                            </div>
                        </div>
                        <a href="/chat" class=format!("{BTN} {BTN_DEFAULT}")>"Open LiveChat"<Icon name="arrow-right" class="w-4 h-4" /></a>
                    </div>
                </div>

                <div class="grid grid-cols-2 lg:grid-cols-4 gap-4">
                    {stat("Members", "users", view! {
                        {move || match members.get() {
                            Some(n) => view! { <div class="text-2xl font-semibold font-mono">{n}</div> }.into_any(),
                            None => loading().into_any(),
                        }}
                        <div class="text-xs text-hast-muted">"Accounts on this server"</div>
                    }.into_any())}
                    {stat("Your key chain", "fingerprint", view! {
                        {move || match chain.get() {
                            None => loading().into_any(),
                            Some(Some((keys, recoveries))) => view! {
                                <div class="text-2xl font-semibold font-mono">{keys}</div>
                                <div class="flex items-center gap-1 text-xs text-hast-verified"><Icon name="check-circle" class="w-3 h-3" />
                                    {format!("Verified here · {keys} key{}", if keys == 1 { "" } else { "s" })}
                                </div>
                                {(recoveries > 0).then(|| view! {
                                    <div class="text-xs text-hast-warning">{format!("{recoveries} recover{} by the server", if recoveries == 1 { "y" } else { "ies" })}</div>
                                })}
                            }.into_any(),
                            Some(None) => view! {
                                <div class="text-2xl font-semibold font-mono text-hast-danger">"!"</div>
                                <div class="text-xs text-hast-danger">"Your chain did not verify"</div>
                            }.into_any(),
                        }}
                    }.into_any())}
                    {stat("Current signing key", "key", view! {
                        <div class="text-2xl font-semibold font-mono">{format!("{uses}/{ROTATE_AFTER}")}</div>
                        <div class="mt-2 h-1 w-full rounded-full bg-hast-elevated"><div class="h-1 rounded-full bg-hast-secondary" style=format!("width:{}%", uses * 100 / ROTATE_AFTER)></div></div>
                        <div class="mt-1 text-xs text-hast-muted">"Signatures before handover"</div>
                    }.into_any())}
                    {stat("Encryption key age", "lock", view! {
                        <div class="text-2xl font-semibold font-mono">{kem_age_days.map(|d| format!("{d} d")).unwrap_or_else(|| "–".into())}</div>
                        <div class="text-xs text-hast-muted">{format!("Replaced at least every {} days", (KEM_MAX_AGE_MS / DAY_MS) as u32)}</div>
                    }.into_any())}
                </div>

                <div>
                    <div class="hast-label mb-3">"Modules"</div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">{modules}</div>
                    <p class="mt-3 text-xs text-hast-muted">"Modules marked Demo run on sample data: they show what an interface could look like, but nothing in them is sent, stored or verified."</p>
                </div>
            </div>
        </div>
    }
}
