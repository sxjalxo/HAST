//! Port of components/BlackBerrySecureChat.tsx (+ the BlackBerryDynamics service mock from hast-core)
use crate::ui::*;
use crate::util::*;
use gloo_timers::future::TimeoutFuture;
use hast_core::bbd::BlackBerryDynamics;
use leptos::prelude::*;
use leptos::task::spawn_local;

#[derive(Clone, PartialEq)]
struct Msg {
    id: String,
    sender: String,
    content: String,
    ts: f64,
    encrypted: bool,
    status: &'static str, // sending | delivered | read
    file: Option<(&'static str, &'static str)>,
    own: bool,
}

#[derive(Clone, PartialEq)]
struct Contact {
    id: &'static str,
    name: &'static str,
    email: &'static str,
    status: &'static str, // online | away | offline
    department: &'static str,
    last_seen: Option<f64>,
}

fn contacts() -> Vec<Contact> {
    let now = now_ms();
    vec![
        Contact {
            id: "1",
            name: "Sarah Connor",
            email: "s.connor@cyberdyne.corp",
            status: "online",
            department: "Security Operations",
            last_seen: None,
        },
        Contact {
            id: "2",
            name: "John Matrix",
            email: "j.matrix@defense.mil",
            status: "away",
            department: "Military Intelligence",
            last_seen: Some(now - 300_000.0),
        },
        Contact {
            id: "3",
            name: "Diana Prince",
            email: "d.prince@justice.gov",
            status: "online",
            department: "Federal Security",
            last_seen: None,
        },
        Contact {
            id: "4",
            name: "Bruce Wayne",
            email: "b.wayne@waynetech.com",
            status: "offline",
            department: "Technology Division",
            last_seen: Some(now - 7_200_000.0),
        },
    ]
}

fn sample_messages(contact: &Contact) -> Vec<Msg> {
    let now = now_ms();
    let m = |id: &str, sender: &str, content: &str, ago: f64, status, file, own| Msg {
        id: id.into(),
        sender: sender.into(),
        content: content.into(),
        ts: now - ago,
        encrypted: true,
        status,
        file,
        own,
    };
    vec![
        m(
            "1",
            contact.name,
            "The quantum encryption keys have been rotated successfully.",
            600_000.0,
            "read",
            None,
            false,
        ),
        m("2", "You", "Confirmed. All BlackBerry Dynamics policies are enforced.", 300_000.0, "read", None, true),
        m(
            "3",
            contact.name,
            "Sending classified document via secure channel.",
            120_000.0,
            "delivered",
            Some(("threat_assessment_report.pdf", "2.4 MB")),
            false,
        ),
        m("4", "You", "Document received and verified. Integrity check passed.", 60_000.0, "delivered", None, true),
    ]
}

fn initials(name: &str) -> String {
    name.split(' ').filter_map(|n| n.chars().next()).collect()
}

fn status_color(s: &str) -> &'static str {
    match s {
        "online" => "bg-hast-verified",
        "away" => "bg-hast-warning",
        _ => "bg-hast-muted",
    }
}

#[component]
pub fn BlackBerrySecureChat() -> impl IntoView {
    let list = contacts();
    let first = list.first().cloned();
    let contacts_sig = RwSignal::new(list);
    let selected = RwSignal::new(first.clone());
    let messages = RwSignal::new(first.as_ref().map(sample_messages).unwrap_or_default());
    let input = RwSignal::new(String::new());
    let search = RwSignal::new(String::new());
    let encrypted = RwSignal::new(true);
    // The original never initialised the SDK mock, so every send threw "SDK not initialized". Initialise it here.
    let sdk = StoredValue::new_local({
        let mut s = BlackBerryDynamics::default();
        s.initialize();
        s
    });

    let send = move || {
        let text = input.get_untracked();
        if text.trim().is_empty() || selected.get_untracked().is_none() {
            return;
        }
        if sdk.with_value(|s| s.encrypt_message(&text)).is_err() {
            return;
        }
        let id = (now_ms() as u64).to_string();
        messages.update(|m| {
            m.push(Msg {
                id: id.clone(),
                sender: "You".into(),
                content: text,
                ts: now_ms(),
                encrypted: encrypted.get_untracked(),
                status: "sending",
                file: None,
                own: true,
            })
        });
        input.set(String::new());
        spawn_local(async move {
            TimeoutFuture::new(1000).await;
            messages.try_update(|m| {
                for x in m.iter_mut().filter(|x| x.id == id) {
                    x.status = "delivered";
                }
            });
        });
    };

    let filtered = move || {
        let q = search.get().to_lowercase();
        contacts_sig
            .get()
            .into_iter()
            .filter(|c| c.name.to_lowercase().contains(&q) || c.email.to_lowercase().contains(&q) || c.department.to_lowercase().contains(&q))
            .collect::<Vec<_>>()
    };

    view! {
        <div class="h-full flex flex-col bg-hast-bg">
            <PageHeader icon="smartphone" title="BlackBerry SecureChat" demo=true subtitle="The chat as it would look inside a BlackBerry Dynamics container" />
            <div class="max-w-7xl w-full mx-auto flex-1 min-h-0 flex flex-col md:flex-row">
                // on phones the contact list stacks above the conversation
                <div class="w-full md:w-80 max-h-56 md:max-h-none shrink-0 border-b md:border-b-0 md:border-r border-hast-border bg-hast-surface flex flex-col">
                    <div class="p-4 border-b border-hast-border">
                        <div class="relative">
                            <Icon name="search" class="w-4 h-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-hast-muted" />
                            <input class=format!("{INPUT} hast-input pl-10") placeholder="Search contacts..." prop:value=move || search.get() on:input=move |e| search.set(event_target_value(&e)) />
                        </div>
                    </div>
                    <div class="flex-1 overflow-y-auto">
                        {move || filtered().into_iter().map(|c| {
                            let c2 = c.clone();
                            let cid = c.id;
                            view! {
                                <div on:click=move |_| { selected.set(Some(c2.clone())); messages.set(sample_messages(&c2)); }
                                    class=move || format!("p-4 cursor-pointer transition-colors hover:bg-hast-elevated border-b border-hast-border {}", if selected.get().is_some_and(|s| s.id == cid) { "bg-hast-primary/10 shadow-[inset_2px_0_0_0_theme(colors.hast.primary)]" } else { "" })>
                                    <div class="flex items-center space-x-3">
                                        <div class="relative">
                                            <div class="w-10 h-10 bg-hast-elevated border border-hast-border rounded-md flex items-center justify-center"><span class="text-sm font-mono">{initials(c.name)}</span></div>
                                            <div class=format!("absolute -bottom-1 -right-1 w-3 h-3 rounded-full border-2 border-hast-border {}", status_color(c.status))></div>
                                        </div>
                                        <div class="flex-1 min-w-0">
                                            <div class="flex items-center justify-between">
                                                <h4 class="text-sm font-medium truncate">{c.name}</h4>
                                                <span class=format!("{BADGE_OUTLINE} border-hast-link/40 text-hast-link text-xs")>"BB-DYN"</span>
                                            </div>
                                            <p class="text-xs text-hast-muted truncate">{c.email}</p>
                                            <p class="text-xs text-hast-link">{c.department}</p>
                                            {(c.status == "offline").then(|| c.last_seen.map(|t| view! { <p class="text-xs text-hast-muted">{format!("Last seen: {}", time_string(t))}</p> }))}
                                        </div>
                                    </div>
                                </div>
                            }
                        }).collect_view()}
                    </div>
                </div>

                <div class="flex-1 flex flex-col min-w-0 min-h-0">
                    {move || selected.get().map(|c| view! {
                        <div class="p-4 border-b border-border bg-hast-surface">
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-3">
                                    <div class="relative">
                                        <div class="w-10 h-10 bg-hast-elevated border border-hast-border rounded-md flex items-center justify-center"><span class="text-sm font-mono">{initials(c.name)}</span></div>
                                        <div class=format!("absolute -bottom-1 -right-1 w-3 h-3 rounded-full border-2 border-hast-border {}", status_color(c.status))></div>
                                    </div>
                                    <div>
                                        <h3 class="font-semibold">{c.name}</h3>
                                        <p class="text-xs text-hast-muted">{c.email}</p>
                                        <div class="flex items-center space-x-2 mt-1">
                                            <span class=format!("{BADGE_OUTLINE} border-hast-link/40 text-hast-link text-xs")><Icon name="shield" class="w-3 h-3 mr-1" />"E2EE Active"</span>
                                            <span class=format!("{BADGE_OUTLINE} border-hast-verified text-hast-verified text-xs")><Icon name="lock" class="w-3 h-3 mr-1" />"AES-256-GCM"</span>
                                        </div>
                                    </div>
                                </div>
                                <div class="flex items-center space-x-2">
                                    <button class=format!("{BTN_BASE} {BTN_GHOST} {SZ_SM}")><Icon name="phone" class="w-4 h-4" /></button>
                                    <button class=format!("{BTN_BASE} {BTN_GHOST} {SZ_SM}")><Icon name="video" class="w-4 h-4" /></button>
                                    <button class=format!("{BTN_BASE} {BTN_GHOST} {SZ_SM}")><Icon name="more-vertical" class="w-4 h-4" /></button>
                                </div>
                            </div>
                        </div>
                    })}

                    <div class="flex-1 overflow-y-auto p-4 space-y-4">
                        {move || if selected.get().is_some() {
                            messages.get().into_iter().map(|m| {
                                let status_icon = if m.own { Some(match m.status {
                                    "sending" => view! { <div class="w-3 h-3 border border-hast-muted border-t-transparent rounded-full animate-spin"></div> }.into_any(),
                                    "delivered" => view! { <Icon name="check" class="w-3 h-3 text-hast-muted" /> }.into_any(),
                                    _ => view! { <div class="flex -space-x-1"><Icon name="check" class="w-3 h-3 text-hast-secondary" /><Icon name="check" class="w-3 h-3 text-hast-secondary" /></div> }.into_any(),
                                }) } else { None };
                                view! {
                                    <div class=format!("flex {}", if m.own { "justify-end" } else { "justify-start" })>
                                        <div class=format!("max-w-xs lg:max-w-md px-4 py-2 rounded-lg {}", if m.own { "bg-hast-elevated text-hast-text border border-hast-border border-r-2 border-r-hast-primary" } else { "hast-panel" })>
                                            {(!m.own).then(|| view! { <p class="text-xs text-hast-link mb-1">{m.sender.clone()}</p> })}
                                            {match m.file {
                                                Some((name, size)) => view! {
                                                    <div class="space-y-2">
                                                        <div class="flex items-center space-x-2">
                                                            <Icon name="file-text" class="w-5 h-5 text-hast-muted" />
                                                            <div><p class="text-sm font-medium">{name}</p><p class="text-xs text-hast-muted">{size}</p></div>
                                                        </div>
                                                        <div class="flex space-x-2">
                                                            <button class=format!("{BTN_BASE} {BTN_OUTLINE} {SZ_SM} text-xs")><Icon name="download" class="w-3 h-3 mr-1" />"Download"</button>
                                                            <button class=format!("{BTN_BASE} {BTN_OUTLINE} {SZ_SM} text-xs")><Icon name="eye" class="w-3 h-3 mr-1" />"Preview"</button>
                                                        </div>
                                                        <p class="text-sm">{m.content.clone()}</p>
                                                    </div>
                                                }.into_any(),
                                                None => view! { <p class="text-sm">{m.content.clone()}</p> }.into_any(),
                                            }}
                                            <div class="flex items-center justify-between mt-2">
                                                <div class="flex items-center space-x-1">
                                                    {m.encrypted.then(|| view! { <Icon name="lock" class="w-3 h-3 text-hast-verified" /> })}
                                                    <span class="text-xs text-hast-muted">{time_string(m.ts)}</span>
                                                </div>
                                                {status_icon.map(|i| view! { <div class="flex items-center">{i}</div> })}
                                            </div>
                                        </div>
                                    </div>
                                }
                            }).collect_view().into_any()
                        } else { view! {
                            <div class="flex-1 flex items-center justify-center">
                                <div class="text-center">
                                    <Icon name="shield" class="w-16 h-16 text-hast-link mx-auto mb-4" />
                                    <h3 class="text-lg font-semibold mb-2">"BlackBerry SecureChat"</h3>
                                    <p class="text-hast-muted">"Select a contact to start secure messaging"</p>
                                </div>
                            </div>
                        }.into_any() }}
                    </div>

                    {move || selected.get().map(|_| view! {
                        <div class="p-4 border-t border-border bg-hast-surface">
                            <div class="flex items-center space-x-2 mb-2">
                                <span class=format!("{BADGE_OUTLINE} border-hast-verified text-hast-verified text-xs")><Icon name="lock" class="w-3 h-3 mr-1" />"End-to-End Encrypted"</span>
                                <span class=format!("{BADGE_OUTLINE} border-hast-link/40 text-hast-link text-xs")><Icon name="shield" class="w-3 h-3 mr-1" />"BlackBerry Dynamics"</span>
                            </div>
                            <div class="flex items-center space-x-2">
                                <button class=format!("{BTN_BASE} {BTN_GHOST} {SZ_SM}")><Icon name="paperclip" class="w-4 h-4" /></button>
                                <div class="flex-1 relative">
                                    <input class=format!("{INPUT} hast-input pr-12") placeholder="Type a secure message..." prop:value=move || input.get()
                                        on:input=move |e| input.set(event_target_value(&e)) on:keypress=move |e| if e.key() == "Enter" { send() } />
                                    <button class=format!("{BTN_BASE} {BTN_GHOST} {SZ_SM} absolute right-2 top-1/2 transform -translate-y-1/2") on:click=move |_| encrypted.update(|e| *e = !*e)>
                                        {move || if encrypted.get() { view! { <Icon name="eye" class="w-4 h-4 text-hast-verified" /> }.into_any() } else { view! { <Icon name="eye-off" class="w-4 h-4 text-hast-danger" /> }.into_any() }}
                                    </button>
                                </div>
                                <button class=format!("{BTN_BASE} {BTN_DEFAULT} {SZ_MD}") disabled=move || input.get().trim().is_empty() on:click=move |_| send()><Icon name="send" class="w-4 h-4" /></button>
                            </div>
                        </div>
                    })}
                </div>
            </div>
        </div>
    }
}
