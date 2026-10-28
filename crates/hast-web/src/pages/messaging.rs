//! The messaging channel: end-to-end encrypted (see `sealed`), with an optional Hamming-coded noisy channel whose
//! error correction runs in the receiving browser.
use crate::contacts::Dir;
use crate::ui::*;
use crate::util::*;
use futures::{channel::mpsc, SinkExt, StreamExt};
use gloo_net::websocket::{futures::WebSocket, Message};
use gloo_timers::future::TimeoutFuture;
use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::Value;
use std::collections::HashMap;

const STORAGE_KEY: &str = "gd:messaging-preferred-mode"; // GdStorage mock prefixes keys with `gd:`
const AUTO_SCROLL_THRESHOLD: i32 = 120;

#[derive(Clone, PartialEq)]
struct LocalMsg {
    id: String,
    sender_id: String,
    text: String,
    ts: f64,
    tampered: bool,
    /// signed with keys the user hasn't confirmed (see `sealed::Opened::unconfirmed`)
    unconfirmed: bool,
    /// the id the sender gave the message, so the broadcast replaces the local copy instead of duplicating it
    client_id: Option<String>,
    note: &'static str,
    /// (bits corrected, bytes uncorrectable) by this browser's Hamming decoding
    hamming: Option<(usize, usize)>,
}

/// Check, open and decode a stored message. `kept`: inner messages this browser decrypted before (by message id); one
/// decrypted now is added there and to local history, since the key that opened it is deleted a week after rotating.
async fn from_remote(m: &Value, me: &str, chains: RwSignal<HashMap<String, Dir>>, kept: &mut HashMap<String, String>) -> Option<LocalMsg> {
    let id = m["id"].as_str()?.to_string();
    let o = crate::sealed::open(m, me, chains, crate::auth::load_lt(me).as_ref(), kept.get(&id).map(String::as_str)).await;
    if let Some(inner) = &o.opened {
        let at = m["sentAt"].as_f64().unwrap_or_else(now_ms);
        crate::history::put(me, &format!("messaging:{id}"), &serde_json::json!({ "inner": inner, "at": at })).await;
        kept.insert(id.clone(), inner.clone());
    }
    Some(LocalMsg {
        id,
        sender_id: match m["senderId"].as_str() {
            Some(t) if t == me => "me".to_string(), // our own message coming back
            Some(other) => other.to_string(),
            None => "remote".to_string(),
        },
        text: o.text,
        ts: m["sentAt"].as_f64().or(m["ts"].as_f64()).unwrap_or_else(now_ms),
        tampered: !o.verified || o.hamming.is_some_and(|(_, bad)| bad > 0),
        unconfirmed: o.verified && o.unconfirmed,
        client_id: m["clientId"].as_str().map(String::from),
        note: o.note,
        hamming: o.hamming,
    })
}

#[component]
pub fn Messaging() -> impl IntoView {
    let mode = RwSignal::new(
        ls_get(STORAGE_KEY)
            .filter(|v| ["AES", "MDS", "Quantum"].contains(&v.as_str()))
            .unwrap_or_else(|| "AES".into()),
    );
    let input = RwSignal::new(String::new());
    let history = RwSignal::new(Vec::<LocalMsg>::new());
    let connected = RwSignal::new(false);
    let near_bottom = RwSignal::new(true);
    let pending = RwSignal::new(0usize);
    let tx = RwSignal::<Option<mpsc::UnboundedSender<String>>>::new(None);
    let alive = alive_flag();
    let alive_sv = StoredValue::new(alive.clone());
    let me = RwSignal::new(crate::auth::use_auth().username_untracked().unwrap_or_default());
    let chains = RwSignal::new(HashMap::<String, Dir>::new());
    let notice = RwSignal::new(String::new());

    Effect::new(move |_| ls_set(STORAGE_KEY, &mode.get()));

    let merge = move |items: Vec<LocalMsg>| {
        history.update(|h| {
            let mut added = 0;
            for m in items {
                // our own message echoed by the server: update the local copy with what the server made of it
                // (`clientId` is unsigned, so only our own echo may replace one of our own unsent copies)
                let target = m.client_id.as_ref().filter(|_| m.sender_id == "me");
                if let Some(local) = target.and_then(|c| h.iter_mut().find(|x| &x.id == c && x.sender_id == "me" && x.client_id.is_none())) {
                    local.text = m.text;
                    local.tampered = m.tampered;
                    local.unconfirmed = m.unconfirmed;
                    local.note = m.note;
                    local.hamming = m.hamming;
                    continue;
                }
                if h.iter().any(|x| x.id == m.id) {
                    continue;
                }
                h.push(m);
                added += 1;
            }
            if added == 0 {
                return;
            }
            if near_bottom.get_untracked() {
                spawn_local(async {
                    TimeoutFuture::new(50).await;
                    scroll_to_bottom("messages");
                });
            } else {
                pending.update(|p| *p += added);
            }
            h.sort_by(|a, b| a.ts.total_cmp(&b.ts));
        });
    };

    // websocket with exponential-ish backoff, like the hook
    spawn_local(async move {
        let mut kept: HashMap<String, String> = crate::history::all(&me.get_untracked())
            .await
            .into_iter()
            .filter_map(|(k, rec)| Some((k.strip_prefix("messaging:")?.to_string(), rec["inner"].as_str()?.to_string())))
            .collect();
        let mut delay = 1000u32;
        while is_alive(&alive) {
            if let Ok(ws) = WebSocket::open(&messaging_ws_url()) {
                let (mut write, mut read) = ws.split();
                let (s, mut r) = mpsc::unbounded::<String>();
                tx.set(Some(s));
                connected.set(true);
                delay = 1000;
                spawn_local(async move {
                    while let Some(m) = r.next().await {
                        if write.send(Message::Text(m)).await.is_err() {
                            break;
                        }
                    }
                });
                while let Some(Ok(Message::Text(t))) = read.next().await {
                    if !is_alive(&alive) {
                        break;
                    }
                    let Ok(p) = serde_json::from_str::<Value>(&t) else { continue };
                    let name = me.get_untracked();
                    let incoming = match p["type"].as_str() {
                        Some("backlog") => p["messages"].as_array().cloned().unwrap_or_default(),
                        Some("message") => vec![p["message"].clone()],
                        Some("error") => {
                            notice.set(format!("Server rejected a message: {}", p["reason"].as_str().unwrap_or("unknown reason")));
                            continue;
                        }
                        _ => continue,
                    };
                    let mut opened = vec![];
                    for m in &incoming {
                        opened.extend(from_remote(m, &name, chains, &mut kept).await);
                    }
                    if !is_alive(&alive) {
                        break;
                    }
                    merge(opened);
                }
                if !is_alive(&alive) {
                    break;
                }
                tx.set(None);
                connected.set(false);
            }
            TimeoutFuture::new(delay).await;
            delay = ((delay as f64 * 1.5) as u32).min(30000);
        }
    });

    let on_send = move || {
        let txt = input.get_untracked().trim().to_string();
        if txt.is_empty() {
            return;
        }
        let hamming = mode.get_untracked() != "AES";
        let local_id = format!("{}-{}", now_ms() as u64, rand_id(6));
        history.update(|h| {
            h.push(LocalMsg {
                id: local_id.clone(),
                sender_id: "me".into(),
                text: txt.clone(),
                ts: now_ms(),
                tampered: false,
                unconfirmed: false,
                client_id: None,
                note: "",
                hamming: None,
            })
        });
        input.set(String::new());
        if near_bottom.get_untracked() {
            spawn_local(async {
                TimeoutFuture::new(50).await;
                scroll_to_bottom("messages");
            });
        }
        let alive = alive_sv.get_value();
        spawn_local(async move {
            // seal and sign first (the SLH-DSA signature runs in the worker), then send
            let frame = crate::sealed::seal(&me.get_untracked(), &txt, hamming, chains).await;
            if !is_alive(&alive) {
                return;
            }
            let sent = match frame {
                Ok(mut f) => {
                    f["type"] = "chat".into();
                    f["clientId"] = local_id.clone().into();
                    tx.get_untracked().is_some_and(|s| s.unbounded_send(f.to_string()).is_ok())
                }
                Err(e) => {
                    notice.set(e);
                    false
                }
            };
            if !sent {
                history.update(|h| {
                    if let Some(x) = h.iter_mut().find(|x| x.id == local_id) {
                        x.text.push_str(" ❌");
                    }
                });
            }
        });
    };

    let jump_to_latest = move |_| {
        scroll_to_bottom("messages");
        pending.set(0);
    };

    let on_scroll = move |_| {
        if let Some(el) = web_sys::window().and_then(|w| w.document()).and_then(|d| d.get_element_by_id("messages")) {
            let delta = el.scroll_height() - el.scroll_top() - el.client_height();
            near_bottom.set(delta < AUTO_SCROLL_THRESHOLD);
            if delta < AUTO_SCROLL_THRESHOLD {
                pending.set(0);
            }
        }
    };

    let icon = move || match mode.get().as_str() {
        "AES" => "lock",
        "MDS" => "shield",
        _ => "atom",
    };

    view! {
        <div class="flex flex-col h-full bg-hast-bg">
            <PageHeader icon="mail" title="Secure Messaging" subtitle="Sealed to every member with ML-KEM-768, signed with SLH-DSA">
                <span class=move || format!("{BADGE} {}", if connected.get() { "chip-verified" } else { "chip-warning" })>
                    <span class="mr-1.5 h-1.5 w-1.5 rounded-full bg-current"></span>
                    {move || if connected.get() { "Connected" } else { "Disconnected" }}
                </span>
                <label class="flex items-center gap-2 rounded-md border border-hast-border bg-hast-elevated px-3 h-9 text-sm">
                    <span class="text-hast-muted">"Channel"</span>
                    <select class="bg-transparent text-hast-text cursor-pointer"
                        prop:value=move || mode.get() on:change=move |e| mode.set(event_target_value(&e))>
                        <option value="AES" class="bg-hast-surface">"Standard"</option>
                        <option value="MDS" class="bg-hast-surface">"MDS (Hamming)"</option>
                        <option value="Quantum" class="bg-hast-surface">"Quantum (Hamming)"</option>
                    </select>
                </label>
            </PageHeader>
            {move || (!notice.get().is_empty()).then(|| view! {
                <div class="px-6 py-2 bg-hast-warning/10 border-b border-hast-warning/30 text-hast-warning text-xs flex items-center justify-between gap-4">
                    <span class="flex items-center gap-2"><Icon name="alert-triangle" class="w-3.5 h-3.5 shrink-0" />{move || notice.get()}</span>
                    <button class="hover:text-hast-text" aria-label="Dismiss" on:click=move |_| notice.set(String::new())><Icon name="x" class="w-3.5 h-3.5" /></button>
                </div>
            })}

            <div class="px-6 py-2 border-b border-hast-border flex flex-wrap items-center justify-between gap-2 text-xs text-hast-secondary">
                <div class="flex items-center gap-4">
                    <span class="flex items-center gap-1.5"><Icon name="lock" class="w-3 h-3 text-hast-muted" />"End-to-end encrypted (ML-KEM-768, signed with SLH-DSA)"</span>
                    <span class="hidden sm:inline text-hast-muted">"·"</span>
                    <span class="hidden sm:inline">"BlackBerry Dynamics: "<span class="text-hast-verified">"Active"</span></span>
                </div>
                <div class="flex items-center gap-1.5">
                    {move || view! { <Icon name=icon() class="w-3 h-3 text-hast-muted" /> }}
                    <span>{move || if mode.get() == "AES" { "No channel noise".to_string() } else { format!("Noisy channel ({}% bit errors), Hamming correction in the receiver", (crate::sealed::NOISE * 100.0) as u32) }}</span>
                </div>
            </div>

            <main class="flex-1 min-h-0 overflow-hidden relative">
                <div id="messages" class="h-full overflow-y-auto px-6 py-4 space-y-4" on:scroll=on_scroll style=format!("scroll-behavior:smooth;{GRID_BG}")>
                    {move || {
                        let h = history.get();
                        h.iter().enumerate().map(|(idx, m)| {
                            let is_me = m.sender_id == "me";
                            let show_avatar = idx == 0 || h[idx - 1].sender_id != m.sender_id;
                            let bubble = if m.tampered { "bg-hast-danger/10 border border-hast-danger/50 text-hast-text" }
                                else if m.unconfirmed { "bg-hast-warning/5 border border-hast-warning/40 text-hast-text rounded-tl-sm" }
                                else if is_me { "bg-hast-elevated text-hast-text border border-hast-border border-r-2 border-r-hast-primary rounded-tr-sm" }
                                else { "bg-hast-surface text-hast-text border border-hast-border rounded-tl-sm" };
                            view! {
                                <div class=format!("flex gap-3 {} {}", if is_me { "flex-row-reverse" } else { "flex-row" }, if show_avatar { "" } else { "ml-11" })>
                                    {(show_avatar && !is_me).then(|| view! {
                                        <div class="w-8 h-8 rounded-md bg-hast-elevated border border-hast-border flex items-center justify-center text-xs font-semibold text-hast-text flex-shrink-0">
                                            {m.sender_id.chars().take(2).collect::<String>().to_uppercase()}
                                        </div>
                                    })}
                                    {(show_avatar && is_me).then(|| view! { <div class="w-8"></div> })}
                                    <div class=format!("flex flex-col {} max-w-[75%]", if is_me { "items-end" } else { "items-start" })>
                                        {show_avatar.then(|| view! {
                                            <div class="flex items-center gap-2 mb-1 px-1">
                                                <span class="text-xs font-medium text-hast-secondary">{if is_me { "You".to_string() } else { m.sender_id.clone() }}</span>
                                                <span class="text-[11px] font-mono text-hast-muted">{time_hm(m.ts)}</span>
                                            </div>
                                        })}
                                        <div class=format!("px-4 py-2.5 rounded-lg {bubble}")>
                                            {m.tampered.then(|| view! { <div data-status="failed" class="flex items-center gap-1 text-xs font-medium text-hast-danger mb-1"><Icon name="shield-alert" class="w-3.5 h-3.5" /><span>"Integrity check failed"</span></div> })}
                                            {(m.unconfirmed && !m.tampered).then(|| view! { <div data-status="unconfirmed" class="flex items-center gap-1 text-xs font-medium text-hast-warning mb-1"><Icon name="alert-triangle" class="w-3.5 h-3.5" /><span>"Unconfirmed keys"</span></div> })}
                                            <p class="text-sm leading-relaxed break-words">{m.text.clone()}</p>
                                            {m.hamming.map(|(fixed, bad)| view! {
                                                <p class=format!("font-mono text-[11px] mt-1.5 {}", if bad > 0 { "text-hast-warning" } else { "text-hast-muted" })>
                                                    {if bad > 0 { format!("Hamming: {fixed} bit errors corrected, {bad} bytes damaged beyond repair") } else { format!("Hamming: {fixed} bit errors corrected") }}
                                                </p>
                                            })}
                                            {(!m.note.is_empty()).then(|| view! { <p class="text-[11px] text-hast-muted mt-1">{m.note}</p> })}
                                        </div>
                                    </div>
                                </div>
                            }
                        }).collect_view()
                    }}
                </div>
                {move || (pending.get() > 0 && !near_bottom.get()).then(|| view! {
                    <button on:click=jump_to_latest class=format!("{BTN_BASE} {BTN_DEFAULT} {SZ_SM} absolute bottom-4 right-6 shadow-lg")>
                        <Icon name="chevron-down" class="w-4 h-4" />
                        {format!("{} new message{}", pending.get(), if pending.get() > 1 { "s" } else { "" })}
                    </button>
                })}
            </main>

            <div class="border-t border-hast-border bg-hast-surface/60 p-4">
                <div class="flex gap-2">
                    <input class=format!("{INPUT} hast-input h-11 flex-1") placeholder="Type a secure message..." aria-label="Message"
                        prop:value=move || input.get() on:input=move |e| input.set(event_target_value(&e))
                        on:keydown=move |e| if e.key() == "Enter" && !e.shift_key() { e.prevent_default(); on_send(); } />
                    <button on:click=move |_| on_send() disabled=move || input.get().trim().is_empty() aria-label="Send"
                        class=format!("{BTN} {BTN_DEFAULT} h-11 px-5")>
                        <Icon name="send" class="w-4 h-4" />
                    </button>
                </div>
            </div>
        </div>
    }
}
