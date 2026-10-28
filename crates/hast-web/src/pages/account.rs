//! Account settings: the passkeys that, once there is one, sign-in also needs, and this account's devices (browsers).
use crate::auth::{self, use_auth};
use crate::ui::*;
use crate::util::*;
use crate::webauthn;
use hast_core::identity;
use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::{json, Value};

#[derive(Clone, PartialEq)]
struct Passkey {
    id: String,
    name: String,
    created_at: u64,
}

async fn load(list: RwSignal<Option<Vec<Passkey>>>, alive: std::sync::Arc<std::sync::atomic::AtomicBool>) {
    let v = auth::call("GET", "/api/passkeys", None).await.unwrap_or(Value::Null);
    if !is_alive(&alive) {
        return;
    }
    let keys = v["passkeys"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|p| Passkey {
                    id: p["id"].as_str().unwrap_or_default().into(),
                    name: p["name"].as_str().unwrap_or_default().into(),
                    created_at: p["createdAt"].as_u64().unwrap_or(0),
                })
                .collect()
        })
        .unwrap_or_default();
    list.set(Some(keys));
}

#[derive(Clone, PartialEq)]
struct Device {
    id: String,
    name: String,
    created_at: u64,
}

async fn load_devices(list: RwSignal<Option<Vec<Device>>>, alive: std::sync::Arc<std::sync::atomic::AtomicBool>) {
    let v = auth::call("GET", "/api/devices", None).await.unwrap_or(Value::Null);
    if !is_alive(&alive) {
        return;
    }
    let devices = v["devices"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|d| d["removed"] != true)
                .map(|d| Device {
                    id: d["device"].as_str().unwrap_or_default().into(),
                    name: d["name"].as_str().filter(|n| !n.is_empty()).unwrap_or("First browser").into(),
                    created_at: d["createdAt"].as_u64().unwrap_or(0),
                })
                .collect()
        })
        .unwrap_or_default();
    list.set(Some(devices));
}

/// How long this browser keeps the messages it decrypted (they can't be decrypted again).
#[component]
fn HistorySetting(me: String) -> impl IntoView {
    let days = RwSignal::new(auth::history_days(&me));
    view! {
        <div class="hast-panel p-6 space-y-3">
            <h2 class="hast-title text-lg flex items-center gap-2"><Icon name="clock" class="w-5 h-5 text-hast-muted" />"History on this browser"</h2>
            <p class="text-sm text-hast-secondary">
                "Messages are forward secret: the keys that opened them are deleted, so this browser keeps its own encrypted copy, and that copy is your history here. Another browser has its own, from the day it was linked."
            </p>
            <label class="flex flex-wrap items-center gap-3 text-sm text-hast-secondary">
                "Keep messages"
                <select class="h-9 rounded-md border border-hast-border bg-hast-elevated px-2 text-sm text-hast-text" aria-label="Keep messages"
                    prop:value=move || days.get().to_string()
                    on:change=move |e| {
                        let d = event_target_value(&e).parse().unwrap_or(0);
                        auth::set_history_days(&me, d);
                        days.set(d);
                    }>
                    <option value="0" class="bg-hast-surface">"for good"</option>
                    <option value="90" class="bg-hast-surface">"for 90 days"</option>
                    <option value="30" class="bg-hast-surface">"for 30 days"</option>
                </select>
            </label>
            <p class="text-xs text-hast-muted">"Older messages are deleted from this browser the next time LiveChat or Messaging opens."</p>
        </div>
    }
}

/// The account's browsers: this one, the others (removable), and a code to link one more.
#[component]
fn Devices(me: String) -> impl IntoView {
    let this = auth::my_device(&me);
    let list = RwSignal::new(None::<Vec<Device>>);
    let code = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let message = RwSignal::new(None::<(bool, String)>);
    let removing = RwSignal::new(None::<String>);
    let alive = StoredValue::new(alive_flag());
    spawn_local(load_devices(list, alive.get_value()));

    let offer = move || {
        busy.set(true);
        message.set(None);
        let (me, alive) = (me.clone(), alive.get_value());
        spawn_local(async move {
            let r = auth::offer_link(&me).await;
            if !is_alive(&alive) {
                return;
            }
            busy.set(false);
            match r {
                Ok(c) => code.set(Some(c)),
                Err(e) => message.set(Some((false, e))),
            }
        });
    };
    let remove = move |id: String| {
        busy.set(true);
        let alive = alive.get_value();
        spawn_local(async move {
            let r = auth::call("DELETE", &format!("/api/devices/{id}"), None).await;
            if !is_alive(&alive) {
                return;
            }
            busy.set(false);
            removing.set(None);
            match r {
                Ok(_) => {
                    message.set(Some((true, "Browser removed. Nobody seals messages to it any more, and it can no longer send.".into())));
                    load_devices(list, alive).await;
                }
                Err(e) => message.set(Some((false, e.message))),
            }
        });
    };

    view! {
        <div class="hast-panel p-6 space-y-5">
            <div>
                <h2 class="hast-title text-lg flex items-center gap-2"><Icon name="layers" class="w-5 h-5 text-hast-muted" />"Browsers"</h2>
                <p class="mt-1 text-sm text-hast-secondary">
                    "Every browser you link has keys of its own and reads new messages. They share your identity key, so your safety number stays the same and nobody sees a recovery."
                </p>
            </div>

            {move || message.get().map(|(ok, text)| view! {
                <div class=format!("flex items-start gap-2 rounded-md border px-3 py-2 text-sm {}", if ok { "chip-verified" } else { "chip-danger" })>
                    <Icon name=if ok { "check-circle" } else { "alert-triangle" } class="w-4 h-4 mt-0.5 shrink-0" /><span>{text}</span>
                </div>
            })}

            <div class="space-y-2" data-status="devices">
                {move || match list.get() {
                    None => view! { <div class="h-12 rounded-md bg-hast-elevated animate-pulse"></div> }.into_any(),
                    Some(l) => l.into_iter().map(|d| {
                        let (id, id2, current) = (d.id.clone(), d.id.clone(), d.id == this);
                        view! {
                            <div class="rounded-md border border-hast-border bg-hast-elevated/60 p-3">
                                <div class="flex items-center gap-3">
                                    <Icon name="smartphone" class="w-4 h-4 shrink-0 text-hast-muted" />
                                    <div class="min-w-0 flex-1">
                                        <div class="flex items-center gap-2 truncate text-sm text-hast-text">
                                            {d.name.clone()}
                                            {current.then(|| view! { <span class=format!("{BADGE} chip-verified")>"This browser"</span> })}
                                        </div>
                                        <div class="text-[11px] text-hast-muted">{format!("Added {}{}", date_string(d.created_at as f64 * 1000.0), if d.id == identity::PRIMARY { " · first browser of the account" } else { "" })}</div>
                                    </div>
                                    {(!current).then(|| view! {
                                        <button class=format!("{BTN_BASE} {BTN_OUTLINE} {SZ_SM}") aria-label=format!("Remove {}", d.name)
                                            on:click=move |_| removing.set(Some(id.clone()))>"Remove"</button>
                                    })}
                                </div>
                                {move || (removing.get().as_deref() == Some(id2.as_str())).then(|| {
                                    let id3 = id2.clone();
                                    view! {
                                        <div class="mt-3 flex flex-wrap items-center gap-2 rounded-md border px-3 py-2 chip-danger">
                                            <span class="text-sm">"It stops receiving messages. If it was lost or stolen, also create new keys: only that cuts it off for sure."</span>
                                            <button class=format!("{BTN_BASE} {SZ_SM} border border-hast-danger/60 bg-hast-danger/15 text-hast-danger hover:bg-hast-danger/25")
                                                disabled=move || busy.get() on:click=move |_| remove(id3.clone())>"Remove browser"</button>
                                            <button class=format!("{BTN_BASE} {BTN_GHOST} {SZ_SM}") on:click=move |_| removing.set(None)>"Cancel"</button>
                                        </div>
                                    }
                                })}
                            </div>
                        }
                    }).collect_view().into_any(),
                }}
            </div>

            <div class="border-t border-hast-border pt-5 space-y-3">
                {move || match code.get() {
                    Some(c) => view! {
                        <div class="rounded-md border border-hast-border bg-hast-bg/60 p-4 space-y-2">
                            <div class="hast-label">"Link code"</div>
                            <div class="font-mono text-2xl tracking-widest text-hast-text" data-status="link-code">{c}</div>
                            <p class="text-xs text-hast-muted">"On the new browser, sign in and type this code under Link this browser. It works once, for 10 minutes. Anyone with the code and your sign-in can link a browser, so don't share it."</p>
                        </div>
                    }.into_any(),
                    None => ().into_any(),
                }}
                <button class=format!("{BTN} {BTN_DEFAULT}") disabled=move || busy.get() on:click=move |_| offer()>
                    <Icon name="plus" class="w-4 h-4" />{move || if code.get().is_some() { "New code" } else { "Link a new browser" }}
                </button>
            </div>
        </div>
    }
}

#[component]
pub fn Account() -> impl IntoView {
    let me = use_auth().username_untracked().unwrap_or_default();
    let list = RwSignal::new(None::<Vec<Passkey>>);
    let name = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let message = RwSignal::new(None::<(bool, String)>); // (ok, text)
    let removing = RwSignal::new(None::<String>);
    let password = RwSignal::new(String::new());
    let alive = StoredValue::new(alive_flag());
    spawn_local(load(list, alive.get_value()));

    let add = move || {
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        message.set(None);
        let (label, alive) = (name.get_untracked(), alive.get_value());
        spawn_local(async move {
            let r = async {
                let options = auth::call("POST", "/api/passkeys/options", None).await.map_err(|e| e.message)?;
                let mut answer = webauthn::create(&options).await?;
                answer["name"] = label.into();
                auth::call("POST", "/api/passkeys", Some(answer)).await.map_err(|e| e.message)
            }
            .await;
            if !is_alive(&alive) {
                return;
            }
            busy.set(false);
            match r {
                Ok(_) => {
                    name.set(String::new());
                    message.set(Some((true, "Passkey added. From now on, signing in asks for it after your password.".into())));
                    load(list, alive).await;
                }
                Err(e) => message.set(Some((false, e))),
            }
        });
    };

    let remove = move |id: String| {
        let (pw, alive) = (password.get_untracked(), alive.get_value());
        busy.set(true);
        spawn_local(async move {
            let r = auth::call("DELETE", &format!("/api/passkeys/{id}"), Some(json!({ "password": pw }))).await;
            if !is_alive(&alive) {
                return;
            }
            busy.set(false);
            match r {
                Ok(_) => {
                    removing.set(None);
                    password.set(String::new());
                    message.set(Some((true, "Passkey removed.".into())));
                    load(list, alive).await;
                }
                Err(e) => message.set(Some((false, e.message))),
            }
        });
    };

    view! {
        <div>
            <PageHeader icon="settings" title="Account" subtitle="How you sign in, and where" />
            <div class="max-w-3xl mx-auto p-6 space-y-6">
                <Devices me=me.clone() />
                <HistorySetting me=me.clone() />
                <div class="hast-panel p-6 space-y-5">
                    <div class="flex items-start justify-between gap-4">
                        <div>
                            <h2 class="hast-title text-lg flex items-center gap-2"><Icon name="fingerprint" class="w-5 h-5 text-hast-muted" />"Passkeys"</h2>
                            <p class="mt-1 text-sm text-hast-secondary">
                                "A passkey is a second factor kept by your device (fingerprint, face, PIN or security key). Once you add one, signing in as "
                                <span class="font-mono text-hast-text">{me.clone()}</span>
                                " needs your password and the passkey; the password alone no longer opens a session."
                            </p>
                        </div>
                        {move || match list.get() {
                            Some(l) if !l.is_empty() => view! { <span class=format!("{BADGE} chip-verified shrink-0")>"On"</span> }.into_any(),
                            Some(_) => view! { <span class=format!("{BADGE} chip-neutral shrink-0")>"Off"</span> }.into_any(),
                            None => ().into_any(),
                        }}
                    </div>

                    {move || message.get().map(|(ok, text)| view! {
                        <div class=format!("flex items-start gap-2 rounded-md border px-3 py-2 text-sm {}", if ok { "chip-verified" } else { "chip-danger" })>
                            <Icon name=if ok { "check-circle" } else { "alert-triangle" } class="w-4 h-4 mt-0.5 shrink-0" /><span>{text}</span>
                        </div>
                    })}

                    <div class="space-y-2">
                        {move || match list.get() {
                            None => view! { <div class="h-12 rounded-md bg-hast-elevated animate-pulse"></div> }.into_any(),
                            Some(l) if l.is_empty() => view! { <p class="text-sm text-hast-muted">"No passkeys yet."</p> }.into_any(),
                            Some(l) => l.into_iter().map(|p| {
                                let (id, id2) = (p.id.clone(), p.id.clone());
                                view! {
                                    <div class="rounded-md border border-hast-border bg-hast-elevated/60 p-3">
                                        <div class="flex items-center gap-3">
                                            <Icon name="key" class="w-4 h-4 shrink-0 text-hast-muted" />
                                            <div class="min-w-0 flex-1">
                                                <div class="truncate text-sm text-hast-text">{p.name.clone()}</div>
                                                <div class="text-[11px] text-hast-muted">{format!("Added {}", date_string(p.created_at as f64 * 1000.0))}</div>
                                            </div>
                                            <button class=format!("{BTN_BASE} {BTN_OUTLINE} {SZ_SM}") aria-label=format!("Remove {}", p.name)
                                                on:click=move |_| { password.set(String::new()); removing.set(Some(id.clone())); }>"Remove"</button>
                                        </div>
                                        {move || (removing.get().as_deref() == Some(id2.as_str())).then(|| {
                                            let id3 = id2.clone();
                                            view! {
                                                <div class="mt-3 flex flex-wrap items-center gap-2 rounded-md border px-3 py-2 chip-danger">
                                                    <span class="text-sm">"Your password, to remove this passkey:"</span>
                                                    <input type="password" aria-label="Password" autocomplete="current-password" class=format!("{INPUT} hast-input h-9 w-48 flex-none")
                                                        prop:value=move || password.get() on:input=move |e| password.set(event_target_value(&e)) />
                                                    <button class=format!("{BTN_BASE} {SZ_SM} border border-hast-danger/60 bg-hast-danger/15 text-hast-danger hover:bg-hast-danger/25")
                                                        disabled=move || busy.get() || password.get().is_empty() on:click=move |_| remove(id3.clone())>"Remove passkey"</button>
                                                    <button class=format!("{BTN_BASE} {BTN_GHOST} {SZ_SM}") on:click=move |_| removing.set(None)>"Cancel"</button>
                                                </div>
                                            }
                                        })}
                                    </div>
                                }
                            }).collect_view().into_any(),
                        }}
                    </div>

                    <div class="border-t border-hast-border pt-5 space-y-2">
                        <label class="text-xs font-medium text-hast-secondary" for="passkey-name">"Name for the new passkey"</label>
                        <div class="flex flex-wrap gap-2">
                            <input id="passkey-name" class=format!("{INPUT} hast-input flex-1 min-w-[12rem]") placeholder="e.g. Laptop, Phone, Security key" maxlength="60"
                                prop:value=move || name.get() on:input=move |e| name.set(event_target_value(&e)) />
                            <button class=format!("{BTN} {BTN_DEFAULT}") disabled=move || busy.get() || !webauthn::supported() on:click=move |_| add()>
                                <Icon name="plus" class="w-4 h-4" />{move || if busy.get() { "Waiting for your device..." } else { "Add a passkey" }}
                            </button>
                        </div>
                        {(!webauthn::supported()).then(|| view! { <p class="text-xs text-hast-warning">"This browser doesn't support passkeys."</p> })}
                        <p class="text-xs text-hast-muted">"Your encryption keys still stay in this browser's vault, under your password. A passkey protects signing in, not the vault."</p>
                    </div>
                </div>
            </div>
        </div>
    }
}
