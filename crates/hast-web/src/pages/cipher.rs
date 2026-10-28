//! Ports of components/CipherChat.tsx and components/CipherBuilder.tsx
use crate::ui::*;
use crate::util::*;
use gloo_timers::future::TimeoutFuture;
use hast_core::cipher::{self, Step};
use hast_core::hbss::base64_bytes;
use leptos::prelude::*;
use leptos::task::spawn_local;

#[derive(Clone)]
struct Msg {
    id: String,
    sender: &'static str,
    sender_hash: &'static str,
    content: String,
    timestamp: String,
    level: &'static str,
    ttl: &'static str,
    encrypted: bool,
    debug: &'static str,
}

#[component]
pub fn CipherChat() -> impl IntoView {
    let messages = RwSignal::new(vec![
        Msg {
            id: "1".into(),
            sender: "Alice",
            sender_hash: "7F3A2B9E",
            content: "Quantum encryption test successful. Ready for phase 2.".into(),
            timestamp: "14:23:15".into(),
            level: "AES-256",
            ttl: "5h 23m",
            encrypted: false,
            debug: "Enc: AES-256-GCM | Key: 0x7F3A...9E2B | IV: 0x123...ABC | MAC: Valid",
        },
        Msg {
            id: "2".into(),
            sender: "Bob",
            sender_hash: "2E9DC4F1",
            content: "AGkgbmVlZCB0byB0ZXN0IHRoZSBuZXcgY2lwaGVyIGFsZ29yaXRobQ==".into(),
            timestamp: "14:25:33".into(),
            level: "CUSTOM",
            ttl: "2h 45m",
            encrypted: true,
            debug: "Enc: Custom-XOR-ROT13 | Seed: 0x2E9D...F1C4 | Rounds: 7 | Status: Encrypted",
        },
    ]);
    let input = RwSignal::new(String::new());
    let show_debug = RwSignal::new(false);
    let selected = RwSignal::<Option<String>>::new(None);

    Effect::new(move |_| {
        messages.track();
        spawn_local(async {
            TimeoutFuture::new(0).await;
            scroll_to_bottom("cipher-msgs");
        });
    });

    let send = move || {
        let text = input.get_untracked();
        if text.trim().is_empty() {
            return;
        }
        messages.update(|m| {
            m.push(Msg {
                id: (now_ms() as u64).to_string(),
                sender: "You",
                sender_hash: "A1B2C3D4",
                content: text,
                timestamp: time_hms(now_ms()),
                level: "AES-256",
                ttl: "24h 0m",
                encrypted: false,
                debug: "Enc: AES-256-GCM | Key: 0xA1B2...D4E5 | IV: 0x567...DEF | MAC: Valid",
            })
        });
        input.set(String::new());
        // typing sound effect
        if let Ok(a) = web_sys::HtmlAudioElement::new_with_src("data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJmMiI4gDg4mJQ==") {
            a.set_volume(0.1);
            let _ = a.play();
        }
    };

    let decrypt = move |id: String| {
        messages.update(|m| {
            for x in m.iter_mut().filter(|x| x.id == id) {
                x.content = "I need to test the new cipher algorithm".into();
                x.encrypted = false;
            }
        })
    };

    view! {
        <div class="min-h-full bg-hast-bg flex flex-col">
            <PageHeader icon="message-circle" title="Cipher Chat" demo=true subtitle="Channel #alpha · end-to-end encrypted">
                <span class=format!("{BADGE} chip-verified")><Icon name="shield-check" class="w-3 h-3" />"Secure"</span>
                        <button class=format!("{BTN_BASE} {BTN_GHOST} {SZ_SM} font-mono text-xs") on:click=move |_| show_debug.update(|d| *d = !*d)>
                            <Icon name="eye" class="w-4 h-4" />"DEBUG"
                        </button>
            </PageHeader>

            <div id="cipher-msgs" class="flex-1 p-4 overflow-y-auto">
                <div class="space-y-4 max-w-4xl mx-auto">
                    {move || messages.get().into_iter().map(|m| {
                        let id = m.id.clone();
                        let id2 = m.id.clone();
                        let id3 = m.id.clone();
                        let id4 = m.id.clone();
                        let lvl = if m.level == "AES-256" { "chip-verified" } else { "chip-warning" };
                        view! {
                            <div class="hast-row">
                                <div class="flex items-center justify-between mb-2">
                                    <div class="flex items-center space-x-2">
                                        <span class="text-sm font-semibold">{m.sender}</span>
                                        <span class=format!("{BADGE_OUTLINE} text-xs font-mono")><Icon name="hash" class="w-3 h-3 mr-1" />{m.sender_hash}</span>
                                    </div>
                                    <div class="flex items-center space-x-2">
                                        <span class=format!("{BADGE_OUTLINE} text-xs {lvl}")>{m.level}</span>
                                        <span class="text-xs text-hast-muted font-mono">{m.timestamp.clone()}</span>
                                    </div>
                                </div>
                                <div class="mb-3">
                                    {if m.encrypted { view! {
                                        <div class="bg-hast-elevated p-3 rounded border-l-2 border-l-cipher-amber">
                                            <div class="flex items-center justify-between mb-2">
                                                <span class="text-xs text-hast-warning font-mono">"ENCRYPTED MESSAGE"</span>
                                                <button class=format!("{BTN_BASE} {BTN_OUTLINE} h-7 rounded-md px-3 border-hast-warning text-hast-warning hover:bg-hast-warning/10") on:click=move |_| decrypt(id.clone())>
                                                    <Icon name="unlock" class="w-3 h-3 mr-1" />"Decrypt"
                                                </button>
                                            </div>
                                            <p class="font-mono text-sm text-hast-muted break-all">{m.content.clone()}</p>
                                        </div>
                                    }.into_any() } else { view! { <p class="text-sm leading-relaxed animate-decrypt-reveal">{m.content.clone()}</p> }.into_any() }}
                                </div>
                                <div class="flex items-center justify-between text-xs text-hast-muted">
                                    <div class="flex items-center space-x-3">
                                        <div class="flex items-center"><Icon name="clock" class="w-3 h-3 mr-1" />"TTL: "{m.ttl}</div>
                                        <div class="flex items-center"><Icon name="zap" class="w-3 h-3 mr-1" />{m.level}</div>
                                    </div>
                                    {move || show_debug.get().then(|| { let id = id2.clone(); let idc = id2.clone(); view! {
                                        <button class=format!("{BTN_BASE} {BTN_GHOST} h-6 rounded-md px-3 text-xs font-mono")
                                            on:click=move |_| selected.update(|s| *s = if s.as_deref() == Some(&id) { None } else { Some(id.clone()) })>
                                            <span class=move || format!("inline-flex transition-transform {}", if selected.get().as_deref() == Some(&idc) { "rotate-180" } else { "" })><Icon name="chevron-up" class="w-3 h-3" /></span>"Debug"
                                        </button>
                                    } })}
                                </div>
                                {move || (show_debug.get() && selected.get().as_deref() == Some(&id3)).then(|| view! {
                                    <div class="mt-3 bg-hast-elevated p-3 rounded border font-mono text-xs">
                                        <div class="hast-label mb-1">"Encryption debug info"</div>
                                        <div class="text-hast-muted whitespace-pre-wrap">{m.debug}</div>
                                    </div>
                                })}
                                <span class="hidden">{id4}</span>
                            </div>
                        }
                    }).collect_view()}
                </div>
            </div>

            <div class="hast-panel p-4 m-4 mt-0">
                <div class="flex items-center space-x-3 max-w-4xl mx-auto">
                    <div class="flex-1 relative">
                        <input class=format!("{INPUT} hast-input pr-12") placeholder="Type secure message..."
                            prop:value=move || input.get() on:input=move |e| input.set(event_target_value(&e))
                            on:keypress=move |e| if e.key() == "Enter" { send() } />
                        <div class="absolute right-3 top-1/2 transform -translate-y-1/2">
                            <span class=format!("{BADGE} chip-neutral font-mono")><Icon name="lock" class="w-3 h-3 mr-1" />"AES-256"</span>
                        </div>
                    </div>
                    <button class=format!("{BTN_BASE} {BTN_DEFAULT} {SZ_MD}") disabled=move || input.get().trim().is_empty() on:click=move |_| send()>
                        <Icon name="send" class="w-4 h-4" />
                    </button>
                </div>
            </div>
        </div>
    }
}

fn step_value(s: &Step) -> String {
    match s {
        Step::Xor { key } => format!("0x{key:02X}"),
        Step::Mask { mask } => format!("0x{mask:02X}"),
        Step::Rotate { bits } => bits.to_string(),
        Step::Substitute { shift } => shift.to_string(),
    }
}

fn step_param_label(s: &Step) -> &'static str {
    match s {
        Step::Xor { .. } => "key (0x00-0xFF)",
        Step::Mask { .. } => "mask on odd bytes (0x00-0xFF)",
        Step::Rotate { .. } => "bits to rotate left (0-7)",
        Step::Substitute { .. } => "letter shift (0-25, 13 = ROT13)",
    }
}

/// New value for the step from the text typed into its parameter box, if valid.
fn with_param(s: &Step, text: &str) -> Option<Step> {
    Some(match s {
        Step::Xor { .. } => Step::Xor { key: cipher::parse_byte(text)? },
        Step::Mask { .. } => Step::Mask { mask: cipher::parse_byte(text)? },
        Step::Rotate { .. } => Step::Rotate {
            bits: text.trim().parse::<u8>().ok().filter(|b| *b < 8)?,
        },
        Step::Substitute { .. } => Step::Substitute {
            shift: text.trim().parse::<u8>().ok().filter(|b| *b < 26)?,
        },
    })
}

#[component]
pub fn CipherBuilder() -> impl IntoView {
    let steps = RwSignal::new(Vec::<(u32, Step)>::new());
    let next_id = RwSignal::new(0u32);
    let test_input = RwSignal::new("Hello, World!".to_string());
    let output = RwSignal::new(String::new());
    let round_trip = RwSignal::new(None::<bool>);
    let show_qr = RwSignal::new(false);
    let notice = RwSignal::new(String::new());
    let alive = alive_flag();

    let add_step = move |kind: &'static str| {
        if let Some(step) = Step::default_for(kind) {
            let id = next_id.get_untracked();
            next_id.set(id + 1);
            steps.update(|s| s.push((id, step)));
            output.set(String::new());
        }
    };

    let current = move || steps.get_untracked().into_iter().map(|(_, s)| s).collect::<Vec<_>>();
    let run_test = move || {
        let plain = test_input.get_untracked();
        let st = current();
        let enc = cipher::encrypt(&st, plain.as_bytes());
        round_trip.set(Some(cipher::decrypt(&st, &enc) == plain.as_bytes()));
        output.set(base64_bytes(&enc));
    };

    let flash = move |msg: String| {
        notice.set(msg);
        let alive = alive.clone();
        spawn_local(async move {
            TimeoutFuture::new(3000).await;
            if is_alive(&alive) {
                notice.set(String::new());
            }
        });
    };

    let import = move || {
        let Some(w) = web_sys::window() else { return };
        let Ok(Some(text)) = w.prompt_with_message("Paste a cipher configuration (JSON)") else {
            return;
        };
        match cipher::import_config(&text) {
            Ok(list) => {
                let base = next_id.get_untracked();
                next_id.set(base + list.len() as u32);
                let n = list.len();
                steps.set(list.into_iter().enumerate().map(|(i, s)| (base + i as u32, s)).collect());
                output.set(String::new());
                flash(format!("Imported {n} step(s)"));
            }
            Err(e) => flash(format!("Import failed: {e}")),
        }
    };

    let qr_svg = move || {
        qrcode::QrCode::new(cipher::export_config(&current()).as_bytes())
            .map(|c| c.render::<qrcode::render::svg::Color>().min_dimensions(192, 192).quiet_zone(true).build())
            .unwrap_or_default()
    };

    view! {
        <div>
            <PageHeader icon="flask-conical" title="Cipher Lab" subtitle="Design and test custom encryption algorithms">
                <span class="text-xs text-hast-secondary font-mono">{move || notice.get()}</span>
                            <button class=format!("{BTN_BASE} {BTN_OUTLINE} {SZ_SM}") on:click=move |_| import()><Icon name="upload" class="w-4 h-4" />"Import"</button>
                            <button class=format!("{BTN_BASE} {BTN_OUTLINE} {SZ_SM}") disabled=move || steps.get().is_empty() on:click=move |_| show_qr.set(true)><Icon name="qr-code" class="w-4 h-4" />"Export QR"</button>
                            <button class=format!("{BTN_BASE} {BTN_DEFAULT} {SZ_SM}") on:click=move |_| run_test()><Icon name="play" class="w-4 h-4" />"Test Cipher"</button>
            </PageHeader>
            <div class="max-w-6xl mx-auto p-6 space-y-6">
                <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    <div class=format!("{CARD} hast-panel p-6")>
                        <h3 class="hast-title text-lg mb-4">"Available Operations"</h3>
                        <div class="space-y-3">
                            {cipher::KINDS.iter().map(|&(kind, icon, desc)| view! {
                                <button class=format!("{BTN_BASE} {BTN_OUTLINE} {SZ_MD} w-full justify-start") on:click=move |_| add_step(kind)>
                                    <span class="text-lg mr-3">{icon}</span>
                                    <div class="text-left"><div class="font-semibold text-sm">{kind}</div><div class="text-xs text-hast-muted">{desc}</div></div>
                                    <Icon name="plus" class="w-4 h-4 ml-auto" />
                                </button>
                            }).collect_view()}
                        </div>
                    </div>

                    <div class=format!("{CARD} hast-panel p-6")>
                        <div class="flex items-center justify-between mb-4">
                            <h3 class="hast-title text-lg">"Cipher Pipeline"</h3>
                            <button class=format!("{BTN_BASE} {BTN_GHOST} {SZ_SM}") disabled=move || steps.get().is_empty() on:click=move |_| { steps.set(vec![]); output.set(String::new()); }>
                                <Icon name="rotate-ccw" class="w-4 h-4 mr-1" />"Clear"
                            </button>
                        </div>
                        {move || if steps.get().is_empty() { view! {
                            <div class="text-center py-8 text-hast-muted">
                                <Icon name="shuffle" class="w-12 h-12 mx-auto mb-3 opacity-50" />
                                <p class="font-mono text-sm">"No operations added"</p>
                                <p class="text-xs">"Click an operation on the left to add it"</p>
                            </div>
                        }.into_any() } else { view! {
                            <div class="space-y-3">
                                <For each={move || steps.get()} key={|(id, _)| *id}
                                    children=move |(id, step)| {
                                        let pos = move || steps.get().iter().position(|x| x.0 == id).unwrap_or(0);
                                        let ok = RwSignal::new(true);
                                        view! {
                                            <div class="hast-row">
                                                <div class="flex items-center justify-between mb-2">
                                                    <div class="flex items-center space-x-2">
                                                        <span class=format!("{BADGE} chip-neutral font-mono")>{move || format!("Step {}", pos() + 1)}</span>
                                                        <span class="font-semibold text-sm">{step.kind()}</span>
                                                    </div>
                                                    <div class="flex items-center">
                                                        <button class=format!("{BTN_BASE} {BTN_GHOST} h-6 w-6 p-0") title="Move up" disabled=move || pos() == 0
                                                            on:click=move |_| { steps.update(|v| if let Some(p) = v.iter().position(|x| x.0 == id) { if p > 0 { v.swap(p, p - 1); } }); output.set(String::new()); }>"↑"</button>
                                                        <button class=format!("{BTN_BASE} {BTN_GHOST} h-6 w-6 p-0 text-hast-danger hover:text-hast-danger") on:click=move |_| { steps.update(|v| v.retain(|x| x.0 != id)); output.set(String::new()); }>"×"</button>
                                                    </div>
                                                </div>
                                                <p class="text-xs text-hast-muted mb-2">{step.description()}</p>
                                                <label class="text-xs text-hast-muted block mb-1">{step_param_label(&step)}</label>
                                                <input class=move || format!("font-mono text-xs bg-hast-elevated p-2 rounded w-full border {}", if ok.get() { "border-transparent" } else { "border-hast-danger/50" })
                                                    value=step_value(&step)
                                                    on:input=move |e| {
                                                        let text = event_target_value(&e);
                                                        let cur = steps.get_untracked().into_iter().find(|x| x.0 == id).map(|x| x.1);
                                                        match cur.and_then(|c| with_param(&c, &text)) {
                                                            Some(n) => { ok.set(true); steps.update(|v| if let Some(x) = v.iter_mut().find(|x| x.0 == id) { x.1 = n; }); output.set(String::new()); }
                                                            None => ok.set(false),
                                                        }
                                                    } />
                                            </div>
                                        }
                                    } />
                            </div>
                        }.into_any() }}
                    </div>

                    <div class=format!("{CARD} hast-panel p-6")>
                        <h3 class="hast-title text-lg mb-4">"Test & Debug"</h3>
                        <div class="space-y-4">
                            <div>
                                <label class="text-sm font-medium text-hast-muted mb-2 block">"Input Text"</label>
                                <input class=format!("{INPUT} hast-input") placeholder="Enter test message..." prop:value=move || test_input.get() on:input=move |e| { test_input.set(event_target_value(&e)); output.set(String::new()); } />
                            </div>
                            <div>
                                <label class="text-sm font-medium text-hast-muted mb-2 block">"Encrypted Output (Base64)"</label>
                                <div class="relative">
                                    <div class="hast-input min-h-[100px] p-3 font-mono text-sm break-all">
                                        {move || { let o = output.get(); if o.is_empty() { "Run test to see encrypted output...".to_string() } else { o } }}
                                    </div>
                                    {move || (!output.get().is_empty()).then(|| view! {
                                        <button class=format!("{BTN_BASE} {BTN_GHOST} {SZ_SM} absolute top-2 right-2") on:click=move |_| copy_text(&output.get_untracked())><Icon name="copy" class="w-4 h-4" /></button>
                                    })}
                                </div>
                            </div>
                            <button class=format!("{BTN_BASE} {BTN_DEFAULT} {SZ_MD} w-full") disabled=move || steps.get().is_empty() on:click=move |_| run_test()>
                                <Icon name="play" class="w-4 h-4 mr-2" />"Execute Test"
                            </button>
                            {move || round_trip.get().filter(|_| !output.get().is_empty()).map(|ok| if ok { view! {
                                <div class="flex items-center space-x-2 text-sm text-hast-verified"><Icon name="check-circle" class="w-4 h-4" /><span>"Encryption successful: decrypting gives the input back"</span></div>
                            }.into_any() } else { view! {
                                <div class="flex items-center space-x-2 text-sm text-hast-danger"><Icon name="alert-triangle" class="w-4 h-4" /><span>"Round trip failed"</span></div>
                            }.into_any() })}
                        </div>
                    </div>
                </div>

                {move || show_qr.get().then(|| view! {
                    <div class="fixed inset-0 bg-hast-bg/80 flex items-center justify-center z-50">
                        <div class=format!("{CARD} hast-panel p-8 max-w-md w-full mx-4")>
                            <div class="text-center">
                                <h3 class="hast-title text-lg mb-4">"Cipher Configuration"</h3>
                                <div class="w-48 h-48 mx-auto mb-4 bg-white rounded-lg overflow-hidden" inner_html=qr_svg()></div>
                                <p class="text-sm text-hast-muted mb-4 font-mono">"Scan to import cipher configuration"</p>
                                <div class="flex space-x-2">
                                    <button class=format!("{BTN_BASE} {BTN_OUTLINE} {SZ_MD} flex-1") on:click=move |_| download_text("cipher-config.json", "application/json", &cipher::export_config(&current()))><Icon name="download" class="w-4 h-4 mr-2" />"Save Config"</button>
                                    <button class=format!("{BTN_BASE} {BTN_DEFAULT} {SZ_MD} flex-1") on:click=move |_| show_qr.set(false)>"Close"</button>
                                </div>
                            </div>
                        </div>
                    </div>
                })}
            </div>
        </div>
    }
}
