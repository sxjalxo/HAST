//! Port of src/pages/QuantumCryptographyPlayground.tsx (the complete first component; the file also had a
//! truncated duplicate glued on that could not compile). The original posted to a placeholder URL
//! (https://example.secure.api/messages) so every send failed; this posts to the local messaging server, sealed end to
//! end like the messaging page.
use crate::contacts::Dir;
use crate::ui::*;
use crate::util::*;
use gloo_net::http::Request;
use gloo_timers::future::TimeoutFuture;
use hast_core::hbss::base64_utf8;
use hast_core::mds;
use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::{json, Value};
use std::collections::HashMap;

const STORAGE_KEY_MODE: &str = "gd:qc-preferred-mode";
const AUTO_SCROLL_THRESHOLD: i32 = 120;

#[derive(Clone)]
struct Item {
    id: String,
    mode: &'static str,
    original: String,
    details: Option<Value>,
    timestamp: f64,
    status: &'static str, // sent | failed | local
}

fn hex_preview(b: &[u8]) -> String {
    b.iter().take(16).map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
}

fn modes(m: &str) -> &'static str {
    match m {
        "AES" => "AES",
        "BlackBerry" => "BlackBerry",
        _ => "Quantum",
    }
}

/// Posts to the messaging channel, sealed and signed like everything else there (`sealed::seal`); "Quantum" uses its
/// Hamming-coded noisy channel.
async fn post(mode: &str, payload: &str, me: &str, chains: RwSignal<HashMap<String, Dir>>) -> Result<(), String> {
    let frame = crate::sealed::seal(me, payload, mode == "Quantum", chains).await?;
    let res = Request::post("/api/messaging/messages")
        .json(&frame)
        .map_err(|e| e.to_string())?
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if res.ok() {
        Ok(())
    } else {
        Err(format!("HTTP {}", res.status()))
    }
}

#[component]
pub fn QuantumCryptographyPlayground() -> impl IntoView {
    let mode = RwSignal::new(modes(&ls_get(STORAGE_KEY_MODE).unwrap_or_else(|| "Quantum".into())));
    let input = RwSignal::new(String::new());
    let history = RwSignal::new(Vec::<Item>::new());
    let near_bottom = RwSignal::new(true);
    let alive = alive_flag();
    let me = StoredValue::new(crate::auth::use_auth().username_untracked().unwrap_or_default());
    let chains = RwSignal::new(HashMap::<String, Dir>::new());

    Effect::new(move |_| ls_set(STORAGE_KEY_MODE, mode.get()));
    Effect::new(move |_| {
        history.with(|h| h.len());
        if near_bottom.get_untracked() {
            spawn_local(async {
                TimeoutFuture::new(40).await;
                scroll_to_bottom("qc-history");
            });
        }
    });

    let patch = move |id: String, f: Box<dyn FnOnce(&mut Item)>| {
        history.try_update(|h| {
            if let Some(x) = h.iter_mut().find(|x| x.id == id) {
                f(x);
            }
        });
    };

    let send = {
        let alive = alive.clone();
        move || {
            let original = input.get_untracked();
            if original.trim().is_empty() {
                return;
            }
            let id = (now_ms() as u64).to_string();
            let m = mode.get_untracked();
            history.update(|h| {
                h.push(Item {
                    id: id.clone(),
                    mode: m,
                    original: original.clone(),
                    details: None,
                    timestamp: now_ms(),
                    status: "local",
                })
            });
            input.set(String::new());
            let alive = alive.clone();
            spawn_local(async move {
                match m {
                    "AES" => {
                        let cipher = base64_utf8(&original);
                        let r = post("AES", &cipher, &me.get_value(), chains).await;
                        if !is_alive(&alive) {
                            return;
                        }
                        match r {
                            Ok(()) => patch(
                                id,
                                Box::new(move |x| {
                                    x.details = Some(json!({ "cipher": cipher }));
                                    x.status = "sent";
                                }),
                            ),
                            Err(e) => patch(
                                id,
                                Box::new(move |x| {
                                    x.details = Some(json!({ "cipher": cipher, "error": e }));
                                    x.status = "failed";
                                }),
                            ),
                        }
                    }
                    "BlackBerry" => {
                        let r = post("BlackBerry", &original, &me.get_value(), chains).await;
                        if !is_alive(&alive) {
                            return;
                        }
                        match r {
                            Ok(()) => patch(
                                id,
                                Box::new(|x| {
                                    x.details = Some(json!({ "via": "GD" }));
                                    x.status = "sent";
                                }),
                            ),
                            Err(e) => patch(
                                id,
                                Box::new(move |x| {
                                    x.details = Some(json!({ "error": e }));
                                    x.status = "failed";
                                }),
                            ),
                        }
                    }
                    _ => {
                        let enc = mds::encode_message(&original);
                        let noisy = mds::simulate_noise(&enc, 0.02);
                        let d = mds::decode_message(&noisy);
                        let ok = post("Quantum", &original, &me.get_value(), chains).await.is_ok();
                        if !is_alive(&alive) {
                            return;
                        }
                        let details = json!({
                            "encodedPreview": hex_preview(&enc),
                            "decoded": { "decoded": d.text, "correctedCount": d.corrected, "uncorrectableCount": d.uncorrectable },
                            "noisyPreview": hex_preview(&noisy),
                        });
                        patch(
                            id,
                            Box::new(move |x| {
                                x.details = Some(details);
                                x.status = if ok { "sent" } else { "failed" };
                            }),
                        );
                    }
                }
            });
        }
    };

    let run_qkd = move || {
        let res = mds::qkd_run(128, if random() < 0.4 { 0.12 } else { 0.0 });
        history.update(|h| {
            h.push(Item {
                id: format!("qkd-{}", now_ms() as u64),
                mode: "Quantum",
                original: "[QKD demo]".into(),
                details: serde_json::to_value(res).ok(),
                timestamp: now_ms(),
                status: "local",
            })
        });
    };

    let on_scroll = move |_| {
        if let Some(el) = web_sys::window().and_then(|w| w.document()).and_then(|d| d.get_element_by_id("qc-history")) {
            near_bottom.set(el.scroll_height() - el.scroll_top() - el.client_height() < AUTO_SCROLL_THRESHOLD);
        }
    };

    let node = |title: &'static str, sub: Box<dyn Fn() -> String + Send + Sync>| {
        view! {
            <div class="min-w-[96px] rounded-md border border-hast-border bg-hast-elevated px-4 py-3 text-center">
                <div class="text-sm font-medium text-hast-text">{title}</div>
                <div class="font-mono text-[11px] text-hast-muted">{move || sub()}</div>
            </div>
        }
    };
    let arrow = || view! { <Icon name="arrow-right" class="w-4 h-4 text-hast-muted" /> };
    // the modes are told apart by label and icon, not by colour
    let mode_icon = |m: &str| match m {
        "AES" => "lock",
        "BlackBerry" => "smartphone",
        _ => "atom",
    };

    view! {
        <div>
            <PageHeader icon="atom" title="Quantum Playground" subtitle="Hamming error correction and quantum key distribution">
                <label class="flex items-center gap-2 rounded-md border border-hast-border bg-hast-elevated px-3 h-9 text-sm">
                    <span class="text-hast-muted">"Mode"</span>
                    <select class="bg-transparent text-hast-text cursor-pointer" prop:value=move || mode.get() on:change=move |e| mode.set(modes(&event_target_value(&e)))>
                        <option value="AES" class="bg-hast-surface">"AES (sim)"</option>
                        <option value="BlackBerry" class="bg-hast-surface">"BlackBerry (GD transport)"</option>
                        <option value="Quantum" class="bg-hast-surface">"Quantum (Hamming demo)"</option>
                    </select>
                </label>
                <button on:click=move |_| run_qkd() class=format!("{BTN_BASE} {BTN_OUTLINE} {SZ_SM}")><Icon name="key" class="w-4 h-4" />"Run QKD"</button>
            </PageHeader>
            <div class="p-6 grid grid-cols-1 xl:grid-cols-[1fr_560px] gap-6">
                <section class="space-y-4">
                    <div class="hast-panel p-5">
                        <div class="hast-label mb-4">"Channel pipeline"</div>
                        <div class="flex flex-wrap items-center gap-2">
                            {node("Sender", Box::new(|| "message".into()))}{arrow()}
                            {node("Encoder", Box::new(move || if mode.get() == "Quantum" { "Hamming(12,8)".into() } else { "AES/GD".into() }))}{arrow()}
                            {node("Channel", Box::new(|| "noise & adversary".into()))}{arrow()}
                            {node("Decoder", Box::new(move || if mode.get() == "Quantum" { "error-correct".into() } else { "decrypt".into() }))}{arrow()}
                            {node("Receiver", Box::new(|| "message".into()))}
                        </div>
                    </div>
                    <div class="flex flex-wrap gap-4 text-sm text-hast-secondary">
                        {["AES", "BlackBerry", "Quantum"].map(|m| view! {
                            <span class=move || format!("flex items-center gap-2 {}", if mode.get() == m { "text-hast-text" } else { "" })>
                                <Icon name=mode_icon(m) class=if m == "Quantum" { "w-4 h-4 text-hast-primary" } else { "w-4 h-4 text-hast-muted" } />
                                {match m { "AES" => "AES", "BlackBerry" => "BlackBerry (GD)", _ => "Quantum MDS" }}
                            </span>
                        })}
                    </div>
                </section>
                <section class="flex flex-col relative">
                    <div class="flex gap-2 mb-3">
                        <input placeholder="Type message..." class=format!("{INPUT} hast-input flex-1")
                            prop:value=move || input.get() on:input=move |e| input.set(event_target_value(&e))
                            on:keydown={ let s = send.clone(); move |e| if e.key() == "Enter" { e.prevent_default(); s() } } />
                        <button on:click={let s = send.clone(); move |_| s()} class=format!("{BTN} {BTN_DEFAULT}")>"Send"</button>
                    </div>
                    <div id="qc-history" on:scroll=on_scroll class="hast-panel p-3 overflow-y-auto max-h-[520px] flex flex-col gap-2.5">
                        {move || history.get().is_empty().then(|| view! { <div class="py-6 text-center text-sm text-hast-muted">"No messages yet"</div> })}
                        {move || history.get().into_iter().map(|h| view! {
                            <article class="rounded-md border border-hast-border bg-hast-elevated/60 p-3">
                                <header class="flex items-center gap-2 mb-1.5 text-xs">
                                    <Icon name=mode_icon(h.mode) class="w-3.5 h-3.5 text-hast-muted" />
                                    <span class="font-medium text-hast-text">{h.mode}</span>
                                    <time class="font-mono text-hast-muted">{time_string(h.timestamp)}</time>
                                    <span class=format!("ml-auto {BADGE} {}", match h.status { "sent" => "chip-verified", "failed" => "chip-danger", _ => "chip-neutral" })>{h.status}</span>
                                </header>
                                <div class="text-sm text-hast-text">{h.original.clone()}</div>
                                {h.details.as_ref().map(|d| view! { <pre class="mt-2 overflow-x-auto rounded border border-hast-border bg-hast-bg/60 p-2 font-mono text-[11px] text-hast-secondary">{serde_json::to_string_pretty(d).unwrap_or_default()}</pre> })}
                            </article>
                        }).collect_view()}
                    </div>
                    {move || (!near_bottom.get()).then(|| view! {
                        <button on:click=move |_| scroll_to_bottom("qc-history") class=format!("{BTN_BASE} {BTN_DEFAULT} {SZ_SM} absolute right-4 bottom-4 shadow-lg")><Icon name="chevron-down" class="w-4 h-4" />"Latest"</button>
                    })}
                </section>
            </div>
        </div>
    }
}
