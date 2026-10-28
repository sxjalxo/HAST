//! Ports of the components that were never reachable from a route in the original:
//! PerformanceAnalyzer, SchemeComparison, HashPlayground, VisualHashFlow. The original docs describe a
//! tabbed "HBSS Enhanced" page (/hbss) that no longer exists; `HBSSLab` is that page, at /hbss-lab.
use crate::ui::*;
use crate::util::*;
use gloo_timers::future::TimeoutFuture;
use hast_core::hashlab::{self, Algo};
use hast_core::hbss::sha512;
use hast_core::multi::{self, format_bytes, format_time, Metrics, Scheme};
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::components::A;

const HEADER: &str = "hast-title flex items-center gap-2 text-lg";

#[component]
pub fn HBSSLab() -> impl IntoView {
    let tab = RwSignal::new("benchmark");
    let t = move |id: &'static str, label: &'static str| {
        view! {
            <button class=move || format!("{TAB} {}", if tab.get() == id { TAB_ACTIVE } else { "" }) on:click=move |_| tab.set(id)>{label}</button>
        }
    };
    view! {
        <div>
            <PageHeader icon="fingerprint" title="HBSS Lab" subtitle="Benchmarks, hash functions, scheme comparison and the signing flow">
                <A href="/chat" attr:class=format!("{BTN_BASE} {BTN_OUTLINE} {SZ_SM}")><Icon name="message-square" class="w-4 h-4" />"LiveChat"</A>
            </PageHeader>
            <div class=TABS_LIST>
                {t("benchmark", "Benchmark")}{t("hash", "Hash lab")}{t("compare", "Compare")}{t("visualize", "Signing flow")}
            </div>
            <div class="max-w-6xl mx-auto p-6 space-y-6">
                <div class:hidden=move || tab.get() != "benchmark"><PerformanceAnalyzer /></div>
                <div class:hidden=move || tab.get() != "hash"><HashPlayground /></div>
                <div class:hidden=move || tab.get() != "compare"><SchemeComparison /></div>
                <div class:hidden=move || tab.get() != "visualize"><VisualHashFlow /></div>
            </div>
        </div>
    }
}

fn speed_color(t: f64) -> &'static str {
    if t < 10.0 {
        "text-hast-verified"
    } else {
        "text-hast-warning"
    }
}

#[component]
fn PerformanceAnalyzer() -> impl IntoView {
    let selected = RwSignal::new(Scheme::ALL.to_vec());
    let results = RwSignal::new(Vec::<(Scheme, Metrics)>::new());
    let running = RwSignal::new(false);
    let progress = RwSignal::new(0.0f64);
    let message = "The quick brown fox jumps over the lazy dog";
    let alive = alive_flag();

    let run = move || {
        running.set(true);
        progress.set(0.0);
        results.set(vec![]);
        let schemes = selected.get_untracked();
        let alive = alive.clone();
        spawn_local(async move {
            for (i, s) in schemes.iter().enumerate() {
                if !is_alive(&alive) {
                    return;
                }
                progress.set((i + 1) as f64 / schemes.len() as f64 * 100.0);
                TimeoutFuture::new(20).await; // let the UI paint the progress bar before the blocking run
                if !is_alive(&alive) {
                    return;
                }
                let m = multi::benchmark(*s, message, &perf_now);
                results.update(|r| r.push((*s, m)));
            }
            if is_alive(&alive) {
                running.set(false);
            }
        });
    };

    let export = move || {
        let rows: Vec<_> = results
            .get_untracked()
            .into_iter()
            .map(|(s, m)| {
                serde_json::json!({
                    "scheme": s.name(), "keygenTime": m.keygen_ms, "signTime": m.sign_ms, "verifyTime": m.verify_ms,
                    "publicKeySize": m.public_key_size, "privateKeySize": m.private_key_size, "signatureSize": m.signature_size,
                    "memoryFootprint": m.memory_footprint, "maxSignatures": null,
                })
            })
            .collect();
        download_text(
            &format!("hast-benchmark-{}.json", now_ms() as u64),
            "application/json",
            &serde_json::to_string_pretty(&rows).unwrap_or_default(),
        );
    };

    let th = "py-3 px-4 text-sm font-medium text-hast-secondary";
    view! {
        <div class="space-y-6">
            <div class=CARD_LAB>
                <div class=CARD_HEADER>
                    <h3 class=HEADER><Icon name="cpu" class="w-5 h-5 text-hast-muted" />"Performance Analyzer"</h3>
                    <p class="text-sm text-hast-muted">"Benchmark and compare post-quantum signature schemes"</p>
                </div>
                <div class=format!("{CARD_CONTENT} space-y-4")>
                    <div>
                        <label class="text-sm font-medium text-hast-secondary mb-3 block">"Select Schemes to Benchmark"</label>
                        <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
                            {Scheme::ALL.iter().map(|&s| view! {
                                <button class=move || format!("p-3 rounded-lg border transition-colors {}", if selected.get().contains(&s) { "border-hast-primary bg-hast-primary/10 text-hast-text" } else { "border-hast-border bg-hast-elevated/50 text-hast-secondary hover:border-hast-muted" })
                                    on:click=move |_| selected.update(|v| if v.contains(&s) { v.retain(|x| *x != s) } else { v.push(s) })>
                                    <div class="font-medium">{s.name()}</div>
                                </button>
                            }).collect_view()}
                        </div>
                    </div>
                    <div>
                        <label class="text-sm font-medium text-hast-secondary mb-2 block">"Test Message"</label>
                        <div class="p-3 bg-hast-elevated/50 border border-hast-border rounded-lg"><code class="text-sm text-hast-secondary">{message}</code></div>
                    </div>
                    <div class="flex gap-3">
                        <button class=format!("{BTN} {BTN_DEFAULT} flex-1") disabled=move || running.get() || selected.get().is_empty() on:click=move |_| run()>
                            <Icon name="play" class="w-4 h-4 mr-2" />{move || if running.get() { "Running Benchmarks..." } else { "Run Benchmarks" }}
                        </button>
                        {move || (!results.get().is_empty()).then(|| view! {
                            <button class=format!("{BTN} {BTN_OUTLINE} border-hast-border") on:click=move |_| export()><Icon name="download" class="w-4 h-4 mr-2" />"Export"</button>
                        })}
                    </div>
                    {move || running.get().then(|| view! {
                        <div class="space-y-2">
                            <div class="relative h-2 w-full overflow-hidden rounded-full bg-hast-elevated"><div class="h-full w-full flex-1 bg-hast-primary transition-all" style=move || format!("transform:translateX(-{}%)", 100.0 - progress.get())></div></div>
                            <p class="text-sm text-hast-secondary text-center">{move || format!("Benchmarking schemes... {:.0}%", progress.get())}</p>
                        </div>
                    })}
                </div>
            </div>

            {move || if results.get().is_empty() {
                (!running.get()).then(|| view! {
                    <div class=CARD_LAB><div class="py-12 text-center">
                        <Icon name="cpu" class="w-16 h-16 mx-auto mb-4 text-hast-muted" />
                        <p class="text-hast-secondary mb-4">"No benchmarks run yet"</p>
                        <p class="text-sm text-hast-muted">"Select schemes and click \"Run Benchmarks\" to start"</p>
                    </div></div>
                }.into_any())
            } else {
                let rows = results.get();
                let totals: Vec<f64> = rows.iter().map(|(_, m)| m.keygen_ms + m.sign_ms + m.verify_ms).collect();
                let max = totals.iter().cloned().fold(0.0, f64::max);
                Some(view! {
                    <div class=CARD_LAB>
                        <div class=CARD_HEADER><h3 class=HEADER><Icon name="zap" class="w-5 h-5 text-hast-muted" />"Timing Comparison"</h3></div>
                        <div class=CARD_CONTENT><div class="overflow-x-auto"><table class="w-full">
                            <thead><tr class="border-b border-hast-border">
                                <th class=format!("text-left {th}")>"Scheme"</th><th class=format!("text-right {th}")>"Key Gen"</th><th class=format!("text-right {th}")>"Sign"</th><th class=format!("text-right {th}")>"Verify"</th><th class=format!("text-right {th}")>"Total"</th>
                            </tr></thead>
                            <tbody>{rows.iter().zip(&totals).map(|((s, m), total)| view! {
                                <tr class="border-b border-hast-border hover:bg-hast-elevated/30">
                                    <td class="py-3 px-4 font-medium text-hast-text">{s.name()}</td>
                                    <td class=format!("py-3 px-4 text-right {}", speed_color(m.keygen_ms))>{format_time(m.keygen_ms)}</td>
                                    <td class=format!("py-3 px-4 text-right {}", speed_color(m.sign_ms))>{format_time(m.sign_ms)}</td>
                                    <td class=format!("py-3 px-4 text-right {}", speed_color(m.verify_ms))>{format_time(m.verify_ms)}</td>
                                    <td class="py-3 px-4 text-right font-medium font-mono text-hast-text">{format_time(*total)}</td>
                                </tr>
                            }).collect_view()}</tbody>
                        </table></div></div>
                    </div>
                    <div class=CARD_LAB>
                        <div class=CARD_HEADER><h3 class=HEADER>"Size Comparison"</h3></div>
                        <div class=CARD_CONTENT><div class="overflow-x-auto"><table class="w-full">
                            <thead><tr class="border-b border-hast-border">
                                <th class=format!("text-left {th}")>"Scheme"</th><th class=format!("text-right {th}")>"Public Key"</th><th class=format!("text-right {th}")>"Private Key"</th><th class=format!("text-right {th}")>"Signature"</th><th class=format!("text-right {th}")>"Memory"</th>
                            </tr></thead>
                            <tbody>{rows.iter().map(|(s, m)| view! {
                                <tr class="border-b border-hast-border hover:bg-hast-elevated/30">
                                    <td class="py-3 px-4 font-medium text-hast-text">{s.name()}</td>
                                    <td class="py-3 px-4 text-right font-mono text-hast-text">{format_bytes(m.public_key_size)}</td>
                                    <td class="py-3 px-4 text-right font-mono text-hast-text">{format_bytes(m.private_key_size)}</td>
                                    <td class="py-3 px-4 text-right font-mono text-hast-text">{format_bytes(m.signature_size)}</td>
                                    <td class="py-3 px-4 text-right font-mono text-hast-text">{format_bytes(m.memory_footprint)}</td>
                                </tr>
                            }).collect_view()}</tbody>
                        </table></div></div>
                    </div>
                    <div class=CARD_LAB>
                        <div class=CARD_HEADER><h3 class=HEADER>"Visual Performance"</h3></div>
                        <div class=format!("{CARD_CONTENT} space-y-6")>{rows.iter().zip(&totals).map(|((s, _), total)| { let pct = total / max * 100.0; view! {
                            <div class="space-y-2">
                                <div class="flex items-center justify-between"><span class="text-sm font-medium text-hast-text">{s.name()}</span><span class="text-sm text-hast-secondary">{format_time(*total)}</span></div>
                                <div class="h-8 bg-hast-elevated rounded-lg overflow-hidden">
                                    <div class="h-full bg-hast-primary flex items-center justify-end px-3 transition-all duration-500" style=format!("width:{pct}%")>
                                        <span class="text-xs font-medium text-hast-text">{format!("{pct:.1}%")}</span>
                                    </div>
                                </div>
                            </div>
                        } }).collect_view()}</div>
                    </div>
                }.into_any())
            }}
        </div>
    }
}

fn speed_badge(speed: &str) -> &'static str {
    match speed {
        // performance, not a security state: neutral, brighter when faster
        "Very Fast" | "Fast" => "bg-hast-elevated border border-hast-border text-hast-text",
        _ => "bg-hast-elevated border border-hast-border text-hast-muted",
    }
}

fn yes_icon() -> impl IntoView {
    view! { <Icon name="check" class="w-5 h-5 text-hast-verified mx-auto" /> }
}

#[component]
fn SchemeComparison() -> impl IntoView {
    let schemes = multi::comparisons();
    let th = "py-3 px-4 text-sm font-medium text-hast-secondary";
    let yes = |label: &'static str| view! { <div class="flex items-center justify-between text-sm"><span class="text-hast-secondary">{label}</span><span class="text-hast-verified flex items-center gap-1"><Icon name="check" class="w-4 h-4" />" Yes"</span></div> };
    let cards = schemes.iter().map(|s| view! {
        <div class=CARD_LAB>
            <div class=CARD_HEADER>
                <h3 class="font-semibold leading-none tracking-tight text-hast-text flex items-center justify-between text-2xl"><span>{s.scheme.name()}</span><span class=format!("px-2 py-1 rounded text-xs font-medium {}", speed_badge(s.speed))>{s.speed}</span></h3>
                <p class="text-sm text-hast-muted">{s.description}</p>
            </div>
            <div class=format!("{CARD_CONTENT} space-y-4")>
                <div class="grid grid-cols-2 gap-3">
                    <div class="p-3 bg-hast-elevated/50 rounded-lg"><div class="text-xs text-hast-secondary mb-1">"Key Size"</div><div class="text-sm font-mono text-hast-text">{s.key_size}</div></div>
                    <div class="p-3 bg-hast-elevated/50 rounded-lg"><div class="text-xs text-hast-secondary mb-1">"Signature Size"</div><div class="text-sm font-mono text-hast-text">{s.sig_size}</div></div>
                </div>
                <div class="space-y-2">
                    {yes("Stateless")}{yes("Post-Quantum")}
                    <div class="flex items-center justify-between text-sm"><span class="text-hast-secondary">"Security Level"</span><span class="font-mono text-hast-text">{format!("{}-bit", s.security_level)}</span></div>
                </div>
            </div>
        </div>
    }).collect_view();
    let explain = |t: &'static str, d: &'static str| view! { <div><h4 class="font-medium text-hast-text mb-2">{t}</h4><p class="text-hast-secondary">{d}</p></div> };
    view! {
        <div class="space-y-6">
            <div class=CARD_LAB>
                <div class=CARD_HEADER>
                    <h3 class=HEADER><Icon name="shield" class="w-5 h-5 text-hast-muted" />"Post-Quantum Signature Schemes"</h3>
                    <p class="text-sm text-hast-muted">"Comprehensive comparison of quantum-resistant digital signature algorithms"</p>
                </div>
                <div class=CARD_CONTENT><div class="overflow-x-auto"><table class="w-full">
                    <thead><tr class="border-b border-hast-border">
                        <th class=format!("text-left {th}")>"Scheme"</th><th class=format!("text-center {th}")>"Stateless"</th><th class=format!("text-center {th}")>"PQ-Safe"</th>
                        <th class=format!("text-right {th}")>"Key Size"</th><th class=format!("text-right {th}")>"Sig Size"</th><th class=format!("text-center {th}")>"Speed"</th><th class=format!("text-right {th}")>"Security"</th>
                    </tr></thead>
                    <tbody>{schemes.iter().map(|s| view! {
                        <tr class="border-b border-hast-border hover:bg-hast-elevated/30">
                            <td class="py-3 px-4"><div class="font-medium text-hast-text">{s.scheme.name()}</div><div class="text-xs text-hast-muted mt-1">{s.description}</div></td>
                            <td class="py-3 px-4 text-center">{yes_icon()}</td><td class="py-3 px-4 text-center">{yes_icon()}</td>
                            <td class="py-3 px-4 text-right font-mono text-hast-text">{s.key_size}</td><td class="py-3 px-4 text-right font-mono text-hast-text">{s.sig_size}</td>
                            <td class="py-3 px-4 text-center"><span class=format!("px-2 py-1 rounded text-xs font-medium {}", speed_badge(s.speed))>{s.speed}</span></td>
                            <td class="py-3 px-4 text-right font-mono text-hast-text">{format!("{}-bit", s.security_level)}</td>
                        </tr>
                    }).collect_view()}</tbody>
                </table></div></div>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">{cards}</div>
            <div class=CARD_LAB>
                <div class=CARD_HEADER><h3 class=HEADER><Icon name="info" class="w-5 h-5 text-hast-muted" />"Understanding the Differences"</h3></div>
                <div class=format!("{CARD_CONTENT} space-y-4 text-sm text-hast-secondary")>
                    {explain("HBSS (Base)", "Uses full commitment array for fast verification. Larger public keys but excellent performance. Ideal for applications where public key size is not a constraint.")}
                    {explain("HBSS* (Seed-Based)", "Generates keys deterministically from a seed. Dramatically reduces private key storage to just 32 bytes. Perfect for resource-constrained devices and backup scenarios.")}
                    {explain("HBSS** (Merkle-Enhanced)", "Uses Merkle tree to compress public key to just 64 bytes. Signatures include Merkle proofs. Best for applications requiring minimal public key distribution overhead.")}
                    {explain("SPHINCS+", "NIST-standardized hash-based signature scheme. Larger signatures but very small keys. Industry standard for post-quantum signatures with extensive security analysis.")}
                </div>
            </div>
        </div>
    }
}

#[component]
fn HashPlayground() -> impl IntoView {
    let input = RwSignal::new("Hello, World!".to_string());
    let algo = RwSignal::new(Algo::Sha512);
    let hash = RwSignal::new(String::new());
    let previous = RwSignal::new(String::new());
    let bit_diff = RwSignal::new(0u32);
    let copied = RwSignal::new(false);

    // Same (lagging) bookkeeping as the original effect: it compares against the hash from two computations ago.
    Effect::new(move |_| {
        let new = hashlab::hash(algo.get(), &input.get());
        let prev = previous.get_untracked();
        if !prev.is_empty() && prev != new {
            bit_diff.set(hashlab::bit_difference(&prev, &new));
        }
        previous.set(hash.get_untracked());
        hash.set(new);
    });

    let avalanche = move || {
        const CASES: [&str; 4] = ["Hello, World!", "Hello, World", "hello, World!", "Hello, World!!"];
        input.set(CASES[(random() * 4.0) as usize % 4].to_string());
    };
    let info = move || algo.get().info();
    let alive = alive_flag();
    let copy = move || {
        copy_text(&hash.get_untracked());
        copied.set(true);
        let alive = alive.clone();
        spawn_local(async move {
            TimeoutFuture::new(2000).await;
            if is_alive(&alive) {
                copied.set(false);
            }
        });
    };
    let prop = |label: &'static str, v: Box<dyn Fn() -> String + Send + Sync>, color: &'static str| {
        view! {
            <div class="p-3 bg-hast-elevated/50 rounded-lg border border-hast-border"><div class="text-xs text-hast-secondary mb-1">{label}</div><div class=format!("text-sm font-medium {color}")>{move || v()}</div></div>
        }
    };
    let check = |t: &'static str, d: &'static str| view! { <div class="flex items-start gap-2"><span class="text-hast-verified mt-0.5">"✓"</span><span><strong>{t}</strong>{d}</span></div> };

    view! {
        <div class="space-y-6">
            <div class=CARD_LAB>
                <div class=CARD_HEADER>
                    <h3 class=HEADER><Icon name="hash" class="w-5 h-5 text-hast-muted" />"Hash Playground"</h3>
                    <p class="text-sm text-hast-muted">"Explore cryptographic hash functions and their properties"</p>
                </div>
                <div class=format!("{CARD_CONTENT} space-y-4")>
                    <div class="flex gap-2">
                        {Algo::ALL.iter().map(|&a| view! {
                            <button class=move || format!("px-4 py-2 rounded-lg text-sm font-medium transition-all {}", if algo.get() == a { "bg-hast-primary text-white" } else { "bg-hast-elevated/50 text-hast-secondary hover:bg-hast-elevated" }) on:click=move |_| algo.set(a)>{a.name()}</button>
                        }).collect_view()}
                    </div>
                    <div>
                        <label class="text-sm font-medium text-hast-secondary mb-2 block">"Input Message"</label>
                        <textarea placeholder="Enter text to hash..." prop:value=move || input.get() on:input=move |e| input.set(event_target_value(&e))
                            class="w-full h-24 px-4 py-3 bg-hast-elevated/50 border border-hast-border rounded-lg text-hast-text placeholder-hast-muted focus:border-hast-primary/60 focus:outline-none resize-none"></textarea>
                        <div class="flex items-center justify-between mt-2">
                            <span class="text-xs text-hast-muted">{move || { let i = input.get(); format!("{} characters, {} bytes", utf16_len(&i), i.len()) }}</span>
                            <button class=format!("{BTN} {BTN_OUTLINE} {SZ_SM} text-xs") on:click=move |_| avalanche()><Icon name="zap" class="w-3 h-3 mr-1" />"Test Avalanche"</button>
                        </div>
                    </div>
                    <div>
                        <div class="flex items-center justify-between mb-2">
                            <label class="text-sm font-medium text-hast-secondary">{move || format!("Hash Output ({}-bit)", info().0)}</label>
                            <button class=format!("{BTN_BASE} {BTN_GHOST} {SZ_SM} text-xs") on:click=move |_| copy()>
                                {move || if copied.get() { view! { <Icon name="check" class="w-3 h-3 mr-1" />"Copied!" }.into_any() } else { view! { <Icon name="copy" class="w-3 h-3 mr-1" />"Copy" }.into_any() }}
                            </button>
                        </div>
                        <div class="p-4 bg-hast-bg border border-hast-border rounded-lg"><code class="hast-mono">{move || hash.get()}</code></div>
                    </div>
                    {move || (bit_diff.get() > 0).then(|| { let pct = bit_diff.get() as f64 / info().0 as f64 * 100.0; view! {
                        <div class="relative w-full rounded-lg border p-4 bg-hast-elevated border-hast-border text-hast-secondary">
                            <strong>"Avalanche Effect:"</strong>{format!(" {} bits changed ({:.1}% of total bits)", bit_diff.get(), pct)}
                            <div class="mt-2 h-2 bg-hast-elevated rounded-full overflow-hidden"><div class="h-full bg-hast-primary transition-all" style=format!("width:{pct}%")></div></div>
                        </div>
                    } })}
                    <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
                        {prop("Output Size", Box::new(move || format!("{} bits", info().0)), "text-hast-text")}
                        {prop("Bytes", Box::new(move || format!("{} bytes", info().1)), "text-hast-text")}
                        {prop("Speed", Box::new(move || info().2.to_string()), "text-hast-text")}
                        {prop("Security", Box::new(move || info().3.to_string()), "text-hast-text")}
                    </div>
                    <div class="space-y-2 text-sm text-hast-secondary">
                        {check("Deterministic:", " Same input always produces same output")}
                        {check("Avalanche Effect:", " Small input change drastically changes output")}
                        {check("Preimage Resistance:", " Cannot reverse hash to find input")}
                        {check("Collision Resistance:", " Extremely hard to find two inputs with same hash")}
                    </div>
                </div>
            </div>

            <div class=CARD_LAB>
                <div class=CARD_HEADER>
                    <h3 class=HEADER><Icon name="alert-triangle" class="w-5 h-5 text-hast-warning" />"Collision Resistance Demo"</h3>
                    <p class="text-sm text-hast-muted">"Understanding the difficulty of finding hash collisions"</p>
                </div>
                <div class=format!("{CARD_CONTENT} space-y-4")>
                    <div class="relative w-full rounded-lg border p-4 bg-hast-warning/10 border-hast-warning/30 text-hast-warning">
                        <strong>"Birthday Paradox:"</strong>{move || format!(" For {}, finding a collision requires approximately ", algo.get().name())}
                        <strong>{move || format!("2^{}", info().0 / 2)}</strong>" hash computations. That's "
                        <strong>{move || js_exp(2f64.powi(info().0 as i32 / 2))}</strong>" attempts!"
                    </div>
                    <div class="p-4 bg-hast-bg border border-hast-border rounded-lg">
                        <div class="text-sm text-hast-secondary mb-3"><strong>"Computational Impossibility:"</strong></div>
                        <div class="space-y-2 text-xs text-hast-secondary">
                            <div>{move || format!("• At 1 billion hashes/second: {} years", js_exp(2f64.powi(info().0 as i32 / 2) / 1e9 / 31536000.0))}</div>
                            <div>"• More than the age of the universe (13.8 billion years)"</div>
                            <div>{move || format!("• Even quantum computers need ~2^{} operations (Grover's algorithm)", info().0 / 2)}</div>
                        </div>
                    </div>
                    <div class="text-sm text-hast-secondary">"This is why cryptographic hash functions are considered "<strong class="text-hast-verified">"collision-resistant"</strong>" and safe for digital signatures, blockchain, and password hashing."</div>
                </div>
            </div>
        </div>
    }
}

/// JS `x.toExponential(2)`
fn js_exp(x: f64) -> String {
    let s = format!("{x:.2e}"); // 1.16e77
    match s.split_once('e') {
        Some((m, e)) if e.starts_with('-') => format!("{m}e{e}"),
        Some((m, e)) => format!("{m}e+{e}"),
        None => s,
    }
}

fn build_tree(leaves: &[String]) -> Vec<String> {
    let mut tree = leaves.to_vec();
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = vec![];
        for c in level.chunks(2) {
            if c.len() == 2 {
                let p = sha512(&format!("{}{}", c[0], c[1]));
                next.push(p.clone());
                tree.push(p);
            } else {
                next.push(c[0].clone());
            }
        }
        level = next;
    }
    tree
}

#[component]
fn VisualHashFlow() -> impl IntoView {
    let message = RwSignal::new("Hello, HBSS!".to_string());
    let animating = RwSignal::new(false);
    let step = RwSignal::new(0u32);
    let epoch = RwSignal::new(0u32);
    let alive = alive_flag();
    const MAX: u32 = 5;

    // same tick-per-1500ms behaviour as the original effect
    Effect::new(move |_| {
        epoch.update(|e| *e += 1);
        let my = epoch.get_untracked();
        let (a, s) = (animating.get(), step.get());
        if a && s < MAX {
            let alive = alive.clone();
            spawn_local(async move {
                TimeoutFuture::new(1500).await;
                if is_alive(&alive) && epoch.get_untracked() == my {
                    step.update(|v| *v += 1);
                }
            });
        } else if s >= MAX {
            animating.set(false);
        }
    });

    let digest = Memo::new(move |_| sha512(&message.get()));
    let indices = Memo::new(move |_| {
        let d = digest.get();
        (0..8)
            .map(|i| (u32::from_str_radix(&sha512(&format!("{d}{i}"))[..8], 16).unwrap() % 64) as usize)
            .collect::<Vec<_>>()
    });
    let commitments = Memo::new(move |_| (0..16).map(|i| sha512(&format!("commitment-{i}"))).collect::<Vec<_>>());
    let tree = Memo::new(move |_| build_tree(&commitments.get()));
    let pre = move |n: u32| move || format!("{CARD_LAB} transition-all {}", if step.get() >= n { "opacity-100" } else { "opacity-30" });
    let shown = move |n: u32| move || if step.get() >= n { "scale-100 opacity-100" } else { "scale-0 opacity-0" };
    let pct = move || step.get() as f64 / MAX as f64 * 100.0;

    view! {
        <div class="space-y-6">
            <div class=CARD_LAB>
                <div class=CARD_HEADER>
                    <h3 class=HEADER><Icon name="eye" class="w-5 h-5 text-hast-muted" />"Visual Hash Flow"</h3>
                    <p class="text-sm text-hast-muted">"Watch the HBSS signature process step-by-step"</p>
                </div>
                <div class=format!("{CARD_CONTENT} space-y-4")>
                    <div>
                        <label class="text-sm font-medium text-hast-secondary mb-2 block">"Input Message"</label>
                        <input type="text" prop:value=move || message.get() on:input=move |e| message.set(event_target_value(&e))
                            class="w-full px-4 py-2 bg-hast-elevated/50 border border-hast-border rounded-lg text-hast-text focus:border-hast-primary/60 focus:outline-none" />
                    </div>
                    <div class="flex gap-3">
                        <button class=format!("{BTN} {BTN_DEFAULT} flex-1") disabled=move || animating.get() on:click=move |_| { step.set(0); animating.set(true); }><Icon name="play" class="w-4 h-4 mr-2" />"Start Animation"</button>
                        <button class=format!("{BTN} {BTN_OUTLINE} border-hast-border") disabled=move || !animating.get() on:click=move |_| animating.set(false)><Icon name="pause" class="w-4 h-4" /></button>
                        <button class=format!("{BTN} {BTN_OUTLINE} border-hast-border") on:click=move |_| { step.set(0); animating.set(false); }><Icon name="rotate-ccw" class="w-4 h-4" /></button>
                    </div>
                    <div class="space-y-2">
                        <div class="flex justify-between text-sm text-hast-secondary"><span>{move || format!("Step {} of {MAX}", step.get())}</span><span>{move || format!("{:.0}%", pct())}</span></div>
                        <div class="h-2 bg-hast-elevated rounded-full overflow-hidden"><div class="h-full bg-hast-primary transition-all duration-500" style=move || format!("width:{}%", pct())></div></div>
                    </div>
                </div>
            </div>

            <div class=pre(1)>
                <div class=CARD_HEADER><h3 class="font-semibold leading-none tracking-tight text-hast-text text-lg">"Step 1: Message Input"</h3></div>
                <div class=CARD_CONTENT><div class="p-4 bg-hast-bg border border-hast-border rounded-lg"><div class="text-sm text-hast-secondary mb-2">"Original Message"</div><code class="font-mono text-hast-text">{move || message.get()}</code></div></div>
            </div>
            <div class=pre(2)>
                <div class=CARD_HEADER><h3 class="font-semibold leading-none tracking-tight text-hast-text text-lg">"Step 2: SHA-512 Digest Computation"</h3></div>
                <div class=CARD_CONTENT><div class="p-4 bg-hast-bg border border-hast-border rounded-lg"><div class="text-sm text-hast-secondary mb-2">"Message Digest (512-bit)"</div><code class="hast-mono text-xs break-all">{move || digest.get()}</code></div></div>
            </div>
            <div class=pre(3)>
                <div class=CARD_HEADER><h3 class="font-semibold leading-none tracking-tight text-hast-text text-lg">"Step 3: Bloom Filter Index Mapping"</h3></div>
                <div class=CARD_CONTENT><div class="space-y-3">
                    <div class="text-sm text-hast-secondary">"Indices generated from digest: "<code>"index[j] = SHA-512(digest || j) mod n"</code></div>
                    <div class="grid grid-cols-8 gap-2">
                        {move || indices.get().into_iter().enumerate().map(|(i, idx)| view! {
                            <div class=move || format!("aspect-square bg-hast-elevated border border-hast-primary/50 rounded-md flex items-center justify-center text-hast-text font-mono font-semibold text-sm transition-all {}", shown(3)()) style=format!("transition-delay:{}ms", i * 100)>{idx}</div>
                        }).collect_view()}
                    </div>
                </div></div>
            </div>
            <div class=pre(4)>
                <div class=CARD_HEADER><h3 class="font-semibold leading-none tracking-tight text-hast-text text-lg">"Step 4: Preimage Revelation"</h3></div>
                <div class=CARD_CONTENT><div class="space-y-3">
                    <div class="text-sm text-hast-secondary">"Reveal preimages at computed indices"</div>
                    <div class="space-y-2">
                        {move || { let c = commitments.get(); indices.get().into_iter().take(4).enumerate().map(|(i, idx)| view! {
                            <div class=move || format!("p-3 bg-hast-bg border border-hast-border rounded-lg transition-all {}", if step.get() >= 4 { "opacity-100 translate-x-0" } else { "opacity-0 -translate-x-4" }) style=format!("transition-delay:{}ms", i * 150)>
                                <div class="flex items-center gap-3">
                                    <div class="px-2 py-1 bg-hast-elevated border border-hast-border text-hast-secondary rounded font-mono text-xs">{format!("#{idx}")}</div>
                                    <code class="text-xs text-hast-secondary flex-1 overflow-x-auto">{format!("{}...", &c[idx % c.len()][..48])}</code>
                                </div>
                            </div>
                        }).collect_view() }}
                    </div>
                </div></div>
            </div>
            <div class=pre(5)>
                <div class=CARD_HEADER><h3 class="font-semibold leading-none tracking-tight text-hast-text text-lg">"Step 5: Merkle Tree Verification Path"</h3></div>
                <div class=CARD_CONTENT><div class="space-y-4">
                    <div class="text-sm text-hast-secondary">"Verify preimages hash to commitment root via Merkle proof"</div>
                    <div class="space-y-3">
                        <div class="flex justify-center"><div class=move || format!("px-4 py-2 bg-hast-elevated border border-hast-verified/50 rounded-md text-hast-verified text-xs font-mono transition-all {}", shown(5)())>
                            {move || format!("Root: {}...", tree.get().last().map(|r| r[..16].to_string()).unwrap_or_default())}
                        </div></div>
                        <div class="flex justify-center gap-4">
                            {move || { let t = tree.get(); let n = t.len(); t[n - 3..n - 1].iter().enumerate().map(|(i, node)| view! {
                                <div class=move || format!("px-3 py-2 bg-hast-elevated border border-hast-muted rounded text-hast-secondary text-xs font-mono transition-all {}", shown(5)()) style=format!("transition-delay:{}ms", i * 200)>{format!("{}...", &node[..12])}</div>
                            }).collect_view() }}
                        </div>
                        <div class="grid grid-cols-4 gap-2">
                            {move || commitments.get().into_iter().take(4).enumerate().map(|(i, leaf)| view! {
                                <div class=move || format!("px-2 py-2 bg-hast-bg border border-hast-verified/30 rounded text-hast-verified text-xs font-mono transition-all {}", shown(5)()) style=format!("transition-delay:{}ms", i * 100)>{format!("{}...", &leaf[..10])}</div>
                            }).collect_view()}
                        </div>
                    </div>
                    <div class="p-3 bg-hast-verified/10 border border-hast-verified/30 rounded-lg"><div class="text-sm text-hast-verified font-medium">"✓ Signature Valid: All preimages verified against commitment root"</div></div>
                </div></div>
            </div>
        </div>
    }
}
