//! LiveChat: a lobby plus private rooms of two. Every message is sealed through forward-secret ratchet sessions with
//! the members' devices (the lobby through sender-key chains), and the envelope is signed with the account's HBSS key
//! and co-signed with its SLH-DSA key. Senders are checked against the key chains the server publishes for their
//! account, verified here.
//!
//! * `mod.rs`: the page (state, composer, layout) and the connection loop.
//! * `crypto`: signing, sealing, checking and opening; key handovers. The security-sensitive part.
//! * `protocol`: what each server frame does, and local history on load.
//! * `model`: the message as shown, and how edits and deletes fold into it.
//! * `inspector`: the signature inspector's views.
use crate::auth::{self, use_auth};
use crate::contacts::{directory, needs_confirmation, recipients, safety_changed, trust_load, trust_set, Dir, Recipient, Trust};
use crate::history;
use crate::ui::*;
use crate::util::*;
use futures::{channel::mpsc, SinkExt, StreamExt};
use gloo_net::websocket::{futures::WebSocket, Message};
use gloo_timers::future::TimeoutFuture;
use hast_core::content::{self, Content};
use hast_core::hbss::{self, KeyPair, PublicKey, Signature};
use hast_core::identity;
use hast_core::pq::{self, LongTermKeys};
use hast_core::ratchet;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::components::A;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

mod crypto;
mod inspector;
mod model;
mod protocol;
use crypto::*;
use inspector::*;
use model::*;
use protocol::*;

/// Signatures per key before handing over to a fresh one: every signature reveals ~6% of the preimages.
pub(super) const ROTATE_AFTER: u32 = 8;
const MAX_TEXT_CHARS: usize = 4000;
pub(super) const DAY_MS: f64 = 24.0 * 3600.0 * 1000.0;
/// Replace the ML-KEM key at least this often, even without sending (forward secrecy for quiet members).
pub(super) const KEM_MAX_AGE_MS: f64 = 7.0 * DAY_MS;
/// Retired decryption keys are deleted after this. With history kept in this browser, they only still open the start of
/// a conversation (sealed to the long-term key) and messages that arrive while the browser was away.
const KEM_KEEP_MS: f64 = 7.0 * DAY_MS;
/// A live message signed longer ago than this is shown as a possible replay (the server enforces the same window).
const MAX_SKEW_MS: f64 = 5.0 * 60.0 * 1000.0;

#[component]
pub fn LiveChat() -> impl IntoView {
    let auth = use_auth();
    let me = RwSignal::new(auth.username_untracked().unwrap_or_default());
    let key_pair = RwSignal::new(auth::load_keys(&me.get_untracked()));
    let lt = RwSignal::new(auth::load_lt(&me.get_untracked()));
    // set on connect when the account has no long-term keys yet or its ML-KEM key is old
    let rotate_due = RwSignal::new(false);
    let connected = RwSignal::new(false);
    let messages = RwSignal::new(Vec::<ChatMessage>::new());
    let input = RwSignal::new(String::new());
    let signing = RwSignal::new(false);
    let stats = RwSignal::new(Stats::default());
    let selected = RwSignal::<Option<ChatMessage>>::new(None);
    let tab = RwSignal::new("chat");
    let online = RwSignal::new(Vec::<String>::new());
    // every account (the directory), for starting private rooms
    let members = RwSignal::new(Vec::<String>::new());
    let room = RwSignal::new(identity::LOBBY.to_string());
    // messages counted per room when it was last on screen, for unread badges
    let read_upto = RwSignal::new(HashMap::<String, usize>::new());
    // rooms whose whole history is loaded (the server said there is nothing older)
    let older_done = RwSignal::new(HashSet::<String>::new());
    let tx = RwSignal::<Option<mpsc::UnboundedSender<String>>>::new(None);
    let chains = RwSignal::new(HashMap::<String, Dir>::new());
    // `sender:id` of every message shown, to catch the same message delivered twice
    let seen = RwSignal::new(HashSet::<String>::new());
    let uses = RwSignal::new(auth::key_uses(&me.get_untracked()));
    let notice = RwSignal::new(String::new());
    let trust_rev = RwSignal::new(0u32); // bumped when the user marks a safety number as verified
    let alive = alive_flag();
    let alive_sv = StoredValue::new(alive.clone());
    // another tab of this browser has LiveChat open (two would advance the same ratchets)
    let locked_out = RwSignal::new(false);

    // Auto-scroll, and everything in the open room counts as read
    Effect::new(move |_| {
        let r = room.get();
        let n = messages.with(|m| shown(m, &r).len());
        read_upto.update(|u| {
            u.insert(r, n);
        });
        request_scroll();
    });

    // The session cookie authenticates the socket; the server knows who we are, so there is no join step.
    {
        let alive = alive.clone();
        spawn_local(async move {
            let name = me.get_untracked();
            if !take_tab_lock(&format!("hast-livechat:{}", name.to_lowercase())).await {
                locked_out.set(true);
                return;
            }
            load_local(&name, messages, chains, seen).await;
            while is_alive(&alive) {
                if let Ok(ws) = WebSocket::open(&chat_ws_url()) {
                    let (mut write, mut read) = ws.split();
                    let (s, mut r) = mpsc::unbounded::<String>();
                    tx.set(Some(s));
                    connected.set(true);
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
                        if let Ok(v) = serde_json::from_str::<Value>(&t) {
                            let welcome = v["type"] == "welcome";
                            if welcome || v["type"] == "users" {
                                spawn_local(load_members(members, alive.clone()));
                            }
                            handle_incoming(v, &me.get_untracked(), key_pair, lt, rotate_due, messages, online, stats, chains, seen, older_done, notice).await;
                            if !is_alive(&alive) {
                                break;
                            }
                            if welcome && rotate_due.get_untracked() {
                                if let Some(s) = tx.get_untracked() {
                                    rotate(&me.get_untracked(), &s, key_pair, lt, uses, rotate_due).await;
                                }
                            }
                        }
                    }
                    if !is_alive(&alive) {
                        break;
                    }
                    tx.set(None);
                    connected.set(false);
                }
                // if the session ended, this drops back to the sign-in page and the page (and this loop) goes away
                auth::refresh(auth).await;
                if !is_alive(&alive) {
                    break;
                }
                TimeoutFuture::new(3000).await;
            }
        });
    }

    // the user compared `who`'s safety number out of band and marked it verified
    let confirm_contact = Callback::new(move |who: String| {
        let clear = |m: &mut ChatMessage| {
            if m.sender.eq_ignore_ascii_case(&who) && m.unconfirmed {
                m.unconfirmed = false;
                m.note = "Safety number confirmed by you";
            }
        };
        messages.update(|ms| ms.iter_mut().for_each(clear));
        selected.update(|s| s.iter_mut().for_each(clear));
    });

    // what the composer does besides writing a new message: the id of the message being edited, or awaiting delete
    let editing = RwSignal::new(None::<String>);
    let confirm_delete = RwSignal::new(None::<String>);

    // Encrypts, signs and sends any content: text, a file, or an edit or delete of one of our messages.
    let send = move |content: Content| {
        let (Some(_), Some(s)) = (key_pair.get_untracked(), tx.get_untracked()) else {
            return;
        };
        if signing.get_untracked() {
            return;
        }
        if let Content::Text { text } | Content::Edit { text, .. } = &content {
            if text.trim().is_empty() {
                return;
            }
            if text.chars().count() > MAX_TEXT_CHARS {
                notice.set(format!("Messages are limited to {MAX_TEXT_CHARS} characters"));
                return;
            }
        }
        let plaintext = content.encode();
        signing.set(true);
        let (name, alive) = (me.get_untracked(), alive_sv.get_value());
        spawn_local(async move {
            let found = recipients(&name, chains).await;
            if !is_alive(&alive) {
                return;
            }
            let Ok((mut to, mut skipped)) = found else {
                notice.set("Could not load the member list, so the message was not sent".into());
                signing.set(false);
                return;
            };
            let room_id = room.get_untracked();
            to.retain(|r| identity::in_room(&room_id, identity::base_name(&r.label)));
            skipped.retain(|n| identity::in_room(&room_id, n));
            let lobby = room_id == identity::LOBBY;
            if !lobby && to.is_empty() {
                notice.set("Not sent: nobody in this room has a verified encryption key yet (they need to open LiveChat once)".into());
                signing.set(false);
                return;
            }
            // in the lobby a new group key may cost a second signature; never let one HBSS key sign more than ROTATE_AFTER
            let needed = if room_id == identity::LOBBY { 2 } else { 1 };
            if uses.get_untracked() + needed > ROTATE_AFTER || rotate_due.get_untracked() || lt.get_untracked().is_none() {
                rotate(&name, &s, key_pair, lt, uses, rotate_due).await;
            }
            let (Some(kp), Some(keys)) = (key_pair.get_untracked(), lt.get_untracked()) else {
                signing.set(false);
                return;
            };
            let t0 = perf_now();
            let me_lc = name.to_lowercase();
            let commitment = kp.public_key.commitment_root.clone();
            // Forward secrecy: sealed through this browser's session with every other device (it keeps its own copy
            // in local history), lobby messages under a sender-key chain. The ratchet state is saved before any await,
            // so nothing else can interleave with a half-done update.
            let body = if lobby {
                // a new sender key when the members (devices and identities) or our HBSS key change
                let mut sorted: Vec<String> = to.iter().map(|r| format!("{}:{}", r.label, r.identity)).collect();
                sorted.sort();
                let members = hbss::sha512(&sorted.join(","));
                let mut st = auth::load_chat_state(&name);
                if !st.mine.as_ref().is_some_and(|(_, m, root)| *m == members && *root == commitment) {
                    let k = ratchet::SendKey::generate();
                    let sealed = (!to.is_empty()).then(|| seal_to(&mut st, &k.distribution(), &me_lc, &to));
                    st.mine = Some((k, members, commitment.clone()));
                    auth::save_chat_state(&name, &st);
                    if let Some(sealed) = sealed {
                        let frame = signed_frame("senderkey", identity::LOBBY, &sealed, &name, &kp, &keys).await;
                        let _ = s.unbounded_send(frame.to_string());
                        uses.try_update(|u| *u += 1);
                    }
                }
                let mut st = auth::load_chat_state(&name);
                let ct = st.mine.as_mut().map(|(k, ..)| ratchet::group_seal(k, &plaintext, &me_lc));
                auth::save_chat_state(&name, &st);
                serde_json::to_string(&ct).unwrap_or_default()
            } else {
                let mut st = auth::load_chat_state(&name);
                let sealed = seal_to(&mut st, &plaintext, &me_lc, &to);
                auth::save_chat_state(&name, &st);
                sealed
            };
            let frame = signed_frame("message", &room_id, &body, &name, &kp, &keys).await;
            let sign_time = perf_now() - t0;
            if !is_alive(&alive) {
                return;
            }
            let _ = s.unbounded_send(frame.to_string());
            let (id, signature) = (frame["id"].as_str().unwrap_or_default().to_string(), parse_sig(&frame["signature"]));
            seen.update(|v| {
                v.insert(format!("{me_lc}:{id}"));
            });
            // nobody can decrypt our own message for us later: this copy is what this browser shows from now on
            let mut kept = frame.clone();
            kept["device"] = auth::my_device(&name).into();
            history::put(&name, &format!("chat:{me_lc}:{id}"), &json!({ "frame": kept, "text": plaintext, "at": now_ms() })).await;
            if !is_alive(&alive) {
                return;
            }
            messages.update(|m| {
                m.push(
                    ChatMessage {
                        id,
                        sender: name.clone(),
                        sender_avatar: String::new(),
                        message: String::new(),
                        signature,
                        commitment,
                        device: auth::my_device(&name),
                        timestamp: now_ms(),
                        verified: true,
                        unconfirmed: false,
                        note: "",
                        is_own: true,
                        cosigned: true,
                        recipients: if lobby { 0 } else { to.len() },
                        group: lobby,
                        fingerprint: identity::fingerprint(&name, &keys.slh_pk),
                        room: room_id.clone(),
                        seq: 0,
                        change: None,
                        file: None,
                        edited: false,
                        deleted: false,
                    }
                    .with_content(&plaintext),
                )
            });
            if !skipped.is_empty() {
                notice.set(format!(
                    "Not encrypted to {}: no verified encryption key yet (they need to open LiveChat once)",
                    skipped.join(", ")
                ));
            }
            stats.update(|st| {
                st.avg_sign = (st.avg_sign * st.signed as f64 + sign_time) / (st.signed as f64 + 1.0);
                st.signed += 1;
            });
            uses.update(|u| *u += 1);
            auth::set_key_uses(&name, uses.get_untracked());
            if matches!(content, Content::Text { .. } | Content::Edit { .. }) {
                input.set(String::new());
            }
            editing.set(None);
            confirm_delete.set(None);
            signing.set(false);
        });
    };
    // a picked file is read here and sent like any message (encrypted, then signed)
    let attach = move |e: web_sys::Event| {
        let el = event_target::<web_sys::HtmlInputElement>(&e);
        let Some(file) = el.files().and_then(|f| f.get(0)) else { return };
        el.set_value(""); // so picking the same file again still fires
        if file.size() as usize > content::MAX_FILE_BYTES {
            notice.set(format!("Files are limited to {} KB", content::MAX_FILE_BYTES / 1024));
            return;
        }
        let alive = alive_sv.get_value();
        spawn_local(async move {
            let read = wasm_bindgen_futures::JsFuture::from(file.array_buffer()).await;
            if !is_alive(&alive) {
                return;
            }
            let Ok(buf) = read else {
                notice.set("Could not read that file".into());
                return;
            };
            match Content::file(&file.name(), &file.type_(), &js_sys::Uint8Array::new(&buf).to_vec()) {
                Ok(c) => send(c),
                Err(m) => notice.set(m),
            }
        });
    };
    let send_message = move || {
        let text = input.get_untracked();
        send(match editing.get_untracked() {
            Some(target) => Content::Edit { target, text },
            None => Content::Text { text },
        });
    };

    view! {
        {move || {
            if locked_out.get() {
                return view! {
                    <div class="h-full flex flex-col items-center justify-center gap-3 bg-hast-bg p-6 text-center" data-status="tab-locked">
                        <Icon name="lock" class="w-8 h-8 text-hast-muted" />
                        <p class="text-hast-text font-medium">"LiveChat is open in another tab of this browser"</p>
                        <p class="max-w-md text-sm text-hast-muted">"Its keys move forward with every message, so only one tab may use them at a time. Close the other tab, then reload this one."</p>
                    </div>
                }.into_any();
            }
            if key_pair.get().is_none() {
                return view! {
                    <div class="h-full flex flex-col items-center justify-center gap-3 bg-hast-bg">
                        <crate::ui::Logo class="w-12 h-12" loading=true />
                        <p class="text-hast-text font-medium">"Generating HBSS keys"</p>
                        <p class="text-sm text-hast-muted">"Creating quantum-resistant signing keys in this browser"</p>
                    </div>
                }.into_any();
            }
            let uname = me.get();
            let panel = |icon: &'static str, title: AnyView, body: AnyView| view! {
                <div class="hast-panel">
                    <div class="flex items-center gap-2 border-b border-hast-border px-4 py-3">
                        <Icon name=icon class="w-4 h-4 text-hast-muted" />
                        <h3 class="text-sm font-medium text-hast-text">{title}</h3>
                    </div>
                    <div class="p-4">{body}</div>
                </div>
            };
            view! {
                <div class="h-full flex flex-col bg-hast-bg">
                    <PageHeader icon="message-square" title="HAST LiveChat" subtitle="End-to-end encrypted rooms, signed with HBSS and SLH-DSA">
                        <span class="hidden lg:inline font-mono text-xs text-hast-muted">{uname.clone()}" · "{move || room_label(&room.get(), &me.get())}</span>
                        // below lg the conversation panel is hidden: pick the room here instead
                        <select class="lg:hidden h-9 rounded-md border border-hast-border bg-hast-elevated px-2 text-sm text-hast-text" aria-label="Conversation"
                            prop:value=move || room.get() on:change=move |e| room.set(event_target_value(&e))>
                            {move || {
                                let mine = me.get();
                                std::iter::once((identity::LOBBY.to_string(), "# Everyone".to_string()))
                                    .chain(members.get().into_iter().filter(|u| !u.eq_ignore_ascii_case(&mine)).map(|u| (identity::dm_room(&mine, &u), format!("@{u}"))))
                                    .map(|(id, label)| view! { <option value=id class="bg-hast-surface">{label}</option> })
                                    .collect_view()
                            }}
                        </select>
                        <A href="/hbss-explained" attr:class=format!("{BTN_BASE} {BTN_OUTLINE} {SZ_SM}")>
                            <Icon name="book-open" class="w-4 h-4" /><span class="hidden sm:inline">"Learn HBSS"</span>
                        </A>
                        <span class=move || format!("{BADGE} {}", if connected.get() { "chip-verified" } else { "chip-warning" })>
                            <span class="mr-1.5 h-1.5 w-1.5 rounded-full bg-current"></span>
                            {move || if connected.get() { "Connected" } else { "Connecting..." }}
                        </span>
                    </PageHeader>

                    {move || {
                        // contacts in this room whose keys are not confirmed, newest message to review first
                        let mut who: Vec<String> = messages.with(|m| shown(m, &room.get()).into_iter().filter(|x| x.verified && x.unconfirmed && !x.is_own).map(|x| x.sender).collect());
                        who.sort();
                        who.dedup();
                        (!who.is_empty()).then(|| {
                            let first = who[0].clone();
                            view! {
                                <div data-status="unconfirmed-banner" class="border-b border-hast-warning/30 bg-hast-warning/10 text-hast-warning text-sm px-6 py-2 flex flex-wrap items-center justify-between gap-3">
                                    <span class="flex items-center gap-2"><Icon name="shield-alert" class="w-4 h-4 shrink-0" />
                                        {format!("Keys not confirmed: {}. Their keys came from an account recovery, which only the server vouches for, or their safety number changed. Compare safety numbers with them before trusting these messages.", who.join(", "))}
                                    </span>
                                    <button class=format!("{BTN_BASE} {SZ_SM} border border-hast-warning/50 text-hast-warning hover:bg-hast-warning/15")
                                        on:click=move |_| {
                                            let latest = messages.with_untracked(|m| shown(m, &room.get_untracked()).into_iter().rev().find(|x| x.sender == first && x.unconfirmed));
                                            if let Some(l) = latest {
                                                selected.set(Some(l));
                                                tab.set("inspector");
                                            }
                                        }>"Review"</button>
                                </div>
                            }
                        })
                    }}
                    {move || (!notice.get().is_empty()).then(|| view! {
                        <div class="border-b border-hast-warning/30 bg-hast-warning/10 text-hast-warning text-sm px-6 py-2 flex items-center justify-between gap-4">
                            <span class="flex items-center gap-2"><Icon name="alert-triangle" class="w-4 h-4 shrink-0" />{move || notice.get()}</span>
                            <button class="text-hast-warning hover:text-hast-text" aria-label="Dismiss" on:click=move |_| notice.set(String::new())><Icon name="x" class="w-4 h-4" /></button>
                        </div>
                    })}
                    <div class="flex-1 flex min-h-0">
                        <div class="hidden lg:block w-72 shrink-0 overflow-y-auto border-r border-hast-border bg-hast-surface/40 p-4 space-y-4">
                            {panel("users", view! { {move || format!("Conversations · {} online", online.get().len())} }.into_any(), view! {
                                <div class="space-y-0.5 max-h-64 overflow-y-auto -mx-1">
                                    {move || {
                                        let mine = me.get();
                                        let rooms: Vec<(String, String, bool)> = std::iter::once((identity::LOBBY.to_string(), "# Everyone".to_string(), true))
                                            .chain(members.get().into_iter().filter(|u| !u.eq_ignore_ascii_case(&mine)).map(|u| {
                                                let on = online.with(|o| o.iter().any(|x| x.eq_ignore_ascii_case(&u)));
                                                (identity::dm_room(&mine, &u), format!("@{u}"), on)
                                            }))
                                            .collect();
                                        rooms.into_iter().map(|(id, label, on)| {
                                            let (id2, id3) = (id.clone(), id.clone());
                                            let unread = move || {
                                                let total = messages.with(|m| shown(m, &id3).len());
                                                total.saturating_sub(read_upto.with(|u| u.get(&id3).copied().unwrap_or(0)))
                                            };
                                            view! {
                                                <button class="nav-item w-full" aria-current=move || (room.get() == id).then_some("page")
                                                    on:click=move |_| room.set(id2.clone())>
                                                    <span class=if on { "w-2 h-2 shrink-0 bg-hast-verified rounded-full" } else { "w-2 h-2 shrink-0 bg-hast-border rounded-full" }></span>
                                                    <span class="flex-1 text-left truncate">{label}</span>
                                                    {move || (unread() > 0).then(|| view! { <span class="text-[11px] font-medium bg-hast-primary text-white rounded px-1.5">{unread()}</span> })}
                                                </button>
                                            }
                                        }).collect_view()
                                    }}
                                </div>
                            }.into_any())}

                            {panel("activity", view! { "Statistics" }.into_any(), view! {
                                <dl class="space-y-2 text-xs">
                                    <div class="flex justify-between"><dt class="text-hast-muted">"Messages signed"</dt><dd class="font-mono text-hast-text">{move || stats.get().signed}</dd></div>
                                    <div class="flex justify-between"><dt class="text-hast-muted">"Messages verified"</dt><dd class="font-mono text-hast-verified">{move || stats.get().verified}</dd></div>
                                    <div class="flex justify-between"><dt class="text-hast-muted">"Avg sign time"</dt><dd class="font-mono text-hast-text">{move || format!("{:.2} ms", stats.get().avg_sign)}</dd></div>
                                    <div class="flex justify-between"><dt class="text-hast-muted">"Avg verify time"</dt><dd class="font-mono text-hast-text">{move || format!("{:.2} ms", stats.get().avg_verify)}</dd></div>
                                </dl>
                            }.into_any())}

                            {panel("key", view! { "Your keys" }.into_any(), view! {
                                <div class="space-y-3 text-xs">
                                    <div>
                                        <div class="hast-label mb-1">"HBSS public key"</div>
                                        <code class="hast-mono text-hast-link">
                                            {move || key_pair.get().map(|k| format!("{}...", &k.public_key.commitment_root[..24])).unwrap_or_default()}
                                        </code>
                                    </div>
                                    <div class="text-hast-muted">"HBSS: 1024 Merkle leaves, 1024 preimages"</div>
                                    <div class="text-hast-muted">"Long-term: SLH-DSA-SHAKE-128f, ML-KEM-768"</div>
                                    <div>
                                        <div class="hast-label mb-1">"Your safety number"</div>
                                        <code class="block font-mono text-[12px] leading-relaxed tracking-wide text-hast-text">
                                            {move || lt.get().map(|k| identity::fingerprint(&me.get(), &k.slh_pk)).unwrap_or_else(|| "(created with your first message)".into())}
                                        </code>
                                    </div>
                                    <div class="text-hast-muted">{move || format!("Signatures with this key: {}/{ROTATE_AFTER}", uses.get().min(ROTATE_AFTER))}</div>
                                    <button class=format!("{BTN_BASE} {BTN_OUTLINE} {SZ_SM} w-full text-xs") title="Download your keys, encrypted with your password, to move this account to another browser"
                                        on:click=move |_| {
                                            let name = me.get_untracked();
                                            if let Some(file) = auth::export_vault(&name) {
                                                download_text(&format!("hast-keys-{name}.json"), "application/json", &file);
                                                notice.set("Key file downloaded. It is encrypted with your password; keep it private. Importing it in another browser links that browser in place of this one; history stays here.".into());
                                            }
                                        }><Icon name="download" class="w-3.5 h-3.5" />"Export keys"</button>
                                </div>
                            }.into_any())}
                        </div>

                        <div class="flex-1 flex flex-col min-w-0">
                            <div class=TABS_LIST role="tablist">
                                <button role="tab" aria-selected=move || (tab.get() == "chat").to_string() class=move || format!("{TAB} {}", if tab.get() == "chat" { TAB_ACTIVE } else { "" }) on:click=move |_| tab.set("chat")>"Chat"</button>
                                <button role="tab" aria-selected=move || (tab.get() == "inspector").to_string() class=move || format!("{TAB} {}", if tab.get() == "inspector" { TAB_ACTIVE } else { "" }) on:click=move |_| tab.set("inspector")>"Signature inspector"</button>
                            </div>
                            <div class="flex-1 flex flex-col min-h-0" class:hidden=move || tab.get() != "chat">
                                // focusable so the keyboard can scroll it
                                <div id="msgs" class="flex-1 overflow-y-auto p-6 space-y-4" style=GRID_BG tabindex="0" role="region" aria-label="Messages">
                                    {move || (!older_done.with(|d| d.contains(&room.get()))).then(|| view! {
                                        <div class="text-center">
                                            <button class="text-xs text-hast-link hover:underline" on:click=move |_| {
                                                let r = room.get_untracked();
                                                let before = messages.with_untracked(|m| m.iter().filter(|x| x.room == r && x.seq > 0).map(|x| x.seq).min());
                                                if let Some(s) = tx.get_untracked() {
                                                    let _ = s.unbounded_send(json!({ "type": "older", "before": before, "room": r }).to_string());
                                                }
                                            }>"Load older messages"</button>
                                        </div>
                                    })}
                                    {move || if messages.with(|m| shown(m, &room.get()).is_empty()) {
                                        view! {
                                            <div class="text-center py-16">
                                                <crate::ui::Logo class="w-12 h-12 mx-auto mb-4 opacity-25" />
                                                <p class="text-hast-secondary">"No messages yet"</p>
                                                <p class="text-sm text-hast-muted mt-1">"Messages are end-to-end encrypted and signed with HBSS + SLH-DSA"</p>
                                            </div>
                                        }.into_any()
                                    } else {
                                        shown(&messages.get(), &room.get()).into_iter().map(|msg| {
                                            let m2 = msg.clone();
                                            let sel_id = msg.id.clone();
                                            let sel_id2 = msg.id.clone();
                                            let is_sel = move || selected.get().is_some_and(|s| s.id == sel_id);
                                            let is_sel2 = move || selected.get().is_some_and(|s| s.id == sel_id2);
                                            // neutral bubbles; your own carry a crimson edge; a failed check is its own state
                                            let bubble = if !msg.verified {
                                                "bg-hast-danger/10 text-hast-text border border-hast-danger/50"
                                            } else if msg.unconfirmed {
                                                "bg-hast-warning/5 text-hast-text border border-hast-warning/40 rounded-tl-sm"
                                            } else if msg.is_own {
                                                "bg-hast-elevated text-hast-text border border-hast-border border-r-2 border-r-hast-primary rounded-tr-sm"
                                            } else {
                                                "bg-hast-surface text-hast-text border border-hast-border rounded-tl-sm"
                                            };
                                            // only your own, intact messages can be changed (and receivers check that it was you)
                                            let changeable = msg.is_own && msg.verified && !msg.deleted && msg.change.is_none();
                                            let (edit_id, edit_text, delete_id) = (msg.id.clone(), msg.message.clone(), msg.id.clone());
                                            let can_edit = msg.file.is_none();
                                            let inspect_label = format!("Inspect the signature of {}'s message", msg.sender);
                                            let m3 = msg.clone();
                                            view! {
                                                <div class=format!("flex {} group", if msg.is_own { "justify-end" } else { "justify-start" })
                                                    on:click=move |_| { selected.set(Some(m2.clone())); tab.set("inspector"); }>
                                                    <div class=format!("max-w-[75%] {} flex flex-col gap-1", if msg.is_own { "items-end" } else { "items-start" })>
                                                        <div class="flex items-center gap-2 px-1">
                                                            {changeable.then(|| view! {
                                                                <span class="flex gap-0.5 opacity-0 transition-opacity group-hover:opacity-100 focus-within:opacity-100">
                                                                    {can_edit.then(|| view! {
                                                                        <button class="rounded p-1 text-hast-muted hover:bg-hast-elevated hover:text-hast-text" title="Edit" aria-label="Edit message"
                                                                            on:click=move |e| { e.stop_propagation(); confirm_delete.set(None); editing.set(Some(edit_id.clone())); input.set(edit_text.clone()); }>
                                                                            <Icon name="pencil" class="w-3.5 h-3.5" />
                                                                        </button>
                                                                    })}
                                                                    <button class="rounded p-1 text-hast-muted hover:bg-hast-danger/15 hover:text-hast-danger" title="Delete" aria-label="Delete message"
                                                                        on:click=move |e| { e.stop_propagation(); editing.set(None); confirm_delete.set(Some(delete_id.clone())); }>
                                                                        <Icon name="trash-2" class="w-3.5 h-3.5" />
                                                                    </button>
                                                                </span>
                                                            })}
                                                            // the keyboard's way to the inspector (a click anywhere on the message does the same)
                                                            <button class="rounded p-1 text-hast-muted opacity-60 hover:bg-hast-elevated hover:text-hast-text hover:opacity-100 focus-visible:opacity-100" title="Inspect signature" aria-label=inspect_label
                                                                on:click=move |e| { e.stop_propagation(); selected.set(Some(m3.clone())); tab.set("inspector"); }>
                                                                <Icon name="eye" class="w-3.5 h-3.5" />
                                                            </button>
                                                            <span class="text-xs font-medium text-hast-secondary">{msg.sender.clone()}</span>
                                                            <span class="text-[11px] font-mono text-hast-muted">{time_string(msg.timestamp)}</span>
                                                            {msg.edited.then(|| view! { <span class="text-[11px] text-hast-muted">"edited"</span> })}
                                                            {(!msg.is_own).then(|| if msg.verified && msg.unconfirmed {
                                                                view! { <span data-status="unconfirmed" class="inline-flex items-center gap-1 text-[11px] text-hast-warning"><Icon name="alert-triangle" class="w-3 h-3" />"Unconfirmed keys"</span> }.into_any()
                                                            } else if msg.verified {
                                                                view! { <span data-status="verified" class="inline-flex items-center gap-1 text-[11px] text-hast-verified"><Icon name="check-circle" class="w-3 h-3" />"Verified"</span> }.into_any()
                                                            } else {
                                                                view! { <span data-status="failed" class="inline-flex items-center gap-1 text-[11px] text-hast-danger"><Icon name="x-circle" class="w-3 h-3" />"Not verified"</span> }.into_any()
                                                            })}
                                                        </div>
                                                        <div class=move || format!("px-4 py-2.5 rounded-lg cursor-pointer transition-colors hover:border-hast-muted relative {} {bubble}",
                                                            if is_sel() { "ring-1 ring-hast-primary/70" } else { "" })>
                                                            {if msg.deleted {
                                                                view! { <p class="flex items-center gap-1.5 text-sm italic text-hast-muted"><Icon name="trash-2" class="w-3.5 h-3.5" />"Message deleted"</p> }.into_any()
                                                            } else if let Some((name, mime, data)) = msg.file.clone() {
                                                                attachment(name, mime, data).into_any()
                                                            } else {
                                                                view! { <p class="text-sm leading-relaxed break-words">{msg.message.clone()}</p> }.into_any()
                                                            }}
                                                            {move || is_sel2().then(|| view! {
                                                                <div class="absolute -top-2 -right-2 w-5 h-5 bg-hast-primary rounded-full flex items-center justify-center">
                                                                    <Icon name="eye" class="w-3 h-3 text-white" />
                                                                </div>
                                                            })}
                                                        </div>
                                                    </div>
                                                </div>
                                            }
                                        }).collect_view().into_any()
                                    }}
                                </div>
                                <div class="border-t border-hast-border bg-hast-surface/60 p-4">
                                    {move || editing.get().map(|_| view! {
                                        <div class="mb-2 flex items-center justify-between rounded-md border border-hast-primary/40 bg-hast-primary/10 px-3 py-1.5 text-xs text-hast-text">
                                            <span class="flex items-center gap-1.5"><Icon name="pencil" class="w-3.5 h-3.5" />"Editing your message: everyone in the room sees the new text, marked edited"</span>
                                            <button class="text-hast-secondary hover:text-hast-text" on:click=move |_| { editing.set(None); input.set(String::new()); }>"Cancel"</button>
                                        </div>
                                    })}
                                    {move || confirm_delete.get().map(|target| view! {
                                        <div class="mb-2 flex flex-wrap items-center justify-between gap-3 rounded-md border px-3 py-2 text-sm chip-danger">
                                            <span class="flex items-center gap-1.5"><Icon name="trash-2" class="w-4 h-4" />"Delete this message for everyone in the room?"</span>
                                            <div class="flex gap-2">
                                                <button class=format!("{BTN_BASE} {SZ_SM} border border-hast-danger/60 bg-hast-danger/15 text-hast-danger hover:bg-hast-danger/25")
                                                    disabled=move || signing.get() on:click=move |_| send(Content::Delete { target: target.clone() })>"Delete"</button>
                                                <button class=format!("{BTN_BASE} {BTN_OUTLINE} {SZ_SM}") on:click=move |_| confirm_delete.set(None)>"Cancel"</button>
                                            </div>
                                        </div>
                                    })}
                                    <div class="flex gap-2">
                                        <label class=format!("{BTN_BASE} {BTN_OUTLINE} h-11 w-11 shrink-0 cursor-pointer") title=format!("Attach a file (up to {} KB), encrypted and signed like a message", content::MAX_FILE_BYTES / 1024)>
                                            <Icon name="paperclip" class="w-4 h-4" />
                                            <input type="file" class="sr-only" aria-label="Attach a file" disabled=move || signing.get() on:change=attach />
                                        </label>
                                        <input type="text" placeholder="Type a message... (encrypted, then signed)" aria-label="Message"
                                            class=format!("{INPUT} hast-input h-11 flex-1")
                                            prop:value=move || input.get() disabled=move || signing.get()
                                            on:input=move |e| input.set(event_target_value(&e))
                                            on:keydown=move |e| if e.key() == "Enter" && !signing.get_untracked() { send_message() } />
                                        <button class=format!("{BTN} {BTN_DEFAULT} h-11 px-5") aria-label=move || if editing.get().is_some() { "Save edit" } else { "Send" }
                                            disabled=move || input.get().trim().is_empty() || signing.get() on:click=move |_| send_message()>
                                            {move || view! { <Icon name=if editing.get().is_some() { "check" } else { "send" } class="w-4 h-4" /> }}
                                        </button>
                                    </div>
                                    <div class="mt-2 flex flex-wrap items-center justify-between gap-2 text-[11px] text-hast-muted">
                                        <div class="flex items-center gap-1.5"><Icon name="lock" class="w-3 h-3" />"End-to-end encrypted (ML-KEM-768), signed with HBSS + SLH-DSA"</div>
                                        <div class="flex items-center gap-1.5"><Icon name="eye" class="w-3 h-3" />"Select a message (or its eye button) to inspect its signature"</div>
                                    </div>
                                </div>
                            </div>
                            <div class="flex-1 m-0 overflow-y-auto" class:hidden=move || tab.get() != "inspector">
                                {move || match selected.get() {
                                    Some(m) => inspector(m, me.get_untracked(), trust_rev, chains, confirm_contact).into_any(),
                                    None => view! {
                                        <div class="flex items-center justify-center h-full min-h-[400px] p-6">
                                            <div class="text-center p-8 rounded-lg border border-dashed border-hast-border max-w-md">
                                                <Icon name="eye" class="w-10 h-10 mx-auto mb-4 text-hast-muted" />
                                                <h3 class="hast-title text-lg mb-2">"No message selected"</h3>
                                                <p class="text-sm text-hast-secondary">"Select any message in the chat to inspect its HBSS signature, SLH-DSA co-signature and safety number."</p>
                                            </div>
                                        </div>
                                    }.into_any(),
                                }}
                            </div>
                        </div>
                    </div>
                </div>
            }.into_any()
        }}
    }
}
