//! The signature inspector: key history, safety numbers, and the per-message checks.
use super::*;

/// Safety-number panel: compare the number with the person out of band, then mark it verified.
pub(super) fn safety_panel(m: &ChatMessage, me: String, trust_rev: RwSignal<u32>, on_confirm: Callback<String>) -> impl IntoView {
    let (who, fp) = (m.sender.clone(), m.fingerprint.clone());
    let own = who.eq_ignore_ascii_case(&me);
    let status = {
        let (who, fp, me) = (who.clone(), fp.clone(), me.clone());
        move || {
            trust_rev.track();
            match trust_load(&me).get(&who.to_lowercase()) {
                _ if own => ("This is your own number. Others compare it with what they see for you.", "text-hast-secondary", false),
                Some(t) if t.fp != fp => (
                    "Changed since you last saw it. Their keys were replaced (recovery). Check with them.",
                    "text-hast-danger",
                    true,
                ),
                Some(t) if t.verified => ("Verified by you ✓", "text-hast-verified", false),
                _ => ("Not verified yet. Compare it with them in person or over another channel.", "text-hast-warning", true),
            }
        }
    };
    let (status2, status3) = (status.clone(), status.clone());
    let mark = move |_| {
        trust_set(&me, &who, Trust { fp: fp.clone(), verified: true });
        trust_rev.update(|r| *r += 1);
        on_confirm.run(who.clone());
    };
    (!m.fingerprint.is_empty()).then(|| {
        view! {
            <div class="space-y-2">
                <div class="flex items-center gap-2"><Icon name="shield" class="w-3.5 h-3.5 text-hast-muted" /><span class="hast-label">{format!("Safety number for {}", m.sender)}</span></div>
                <div class="rounded-md border border-hast-border bg-hast-bg/60 p-3">
                    <div class="font-mono text-sm tracking-wider text-hast-text select-all">{m.fingerprint.clone()}</div>
                </div>
                <div class="flex items-center justify-between gap-3 text-xs">
                    <p class=move || status().1>{move || status2().0}</p>
                    {move || status3().2.then(|| view! {
                        <button class=format!("{BTN_BASE} {BTN_OUTLINE} {SZ_SM} text-xs") on:click=mark.clone()><Icon name="check" class="w-3.5 h-3.5" />"Mark as verified"</button>
                    })}
                </div>
            </div>
        }
    })
}

/// A file in a message: an inline preview for plain image types only, and a download for everything. The download is
/// always saved as `application/octet-stream`, so nothing a sender attaches can run in this page.
pub(super) fn attachment(name: String, mime: String, data: String) -> impl IntoView {
    let bytes = data.len() / 4 * 3;
    let size = if bytes < 1024 {
        format!("{bytes} B")
    } else {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    };
    let preview = content::inline_image(&mime).then(|| format!("data:{mime};base64,{data}"));
    let save_as = name.clone();
    view! {
        <div class="space-y-2">
            {preview.map(|src| view! { <img src=src alt=name.clone() class="max-h-56 max-w-full rounded-md border border-hast-border" /> })}
            <div class="flex items-center gap-3">
                <Icon name="file-text" class="w-5 h-5 shrink-0 text-hast-muted" />
                <div class="min-w-0">
                    <div class="truncate text-sm">{name.clone()}</div>
                    <div class="font-mono text-[11px] text-hast-muted">{size}</div>
                </div>
                <button class="rounded-md border border-hast-border p-1.5 text-hast-secondary hover:border-hast-muted hover:text-hast-text" title="Download" aria-label="Download file"
                    on:click=move |e| {
                        e.stop_propagation();
                        if let Some(b) = content::file_bytes(&data) {
                            download_bytes(&save_as, &b);
                        }
                    }>
                    <Icon name="download" class="w-4 h-4" />
                </button>
            </div>
        </div>
    }
}

/// A labelled technical value: fine border, monospace, selectable.
pub(super) fn field(label: String, icon: &'static str, value: String, foot: String) -> impl IntoView {
    view! {
        <div class="space-y-1.5">
            <div class="flex items-center gap-2"><Icon name=icon class="w-3.5 h-3.5 text-hast-muted" /><span class="hast-label">{label}</span></div>
            <div class="rounded-md border border-hast-border bg-hast-bg/60 p-3"><div class="hast-mono leading-relaxed select-all">{value}</div></div>
            {(!foot.is_empty()).then(|| view! { <p class="text-[11px] text-hast-muted">{foot}</p> })}
        </div>
    }
}

/// The sender's key chain as this browser verified it, newest link first: how each link was vouched for, where the
/// safety number changed, which keys a later recovery replaced, and which key signed the message (`root`).
pub(super) fn key_history(me: String, sender: String, device: String, root: String, chains: RwSignal<HashMap<String, Dir>>) -> impl IntoView {
    let dir = RwSignal::new(None::<Dir>);
    let alive = alive_flag();
    let other_device = device != identity::PRIMARY;
    {
        let key = if other_device { format!("{sender}#{device}") } else { sender.clone() };
        spawn_local(async move {
            let d = directory(&me, &key, chains, false).await;
            if is_alive(&alive) {
                dir.set(Some(d));
            }
        });
    }
    let link = move |i: usize, r: &str, slh: &[Option<String>], recoveries: &[usize], at: &[u64]| {
        let recovery = recoveries.contains(&i);
        let replaced = recoveries.iter().any(|&later| later > i);
        let new_cosigner = i > 0 && slh[i].is_some() && slh[i] != slh[i - 1];
        // (dot, text): signed links are verified, a recovery is only vouched for by the server
        const SIGNED: (&str, &str) = ("bg-hast-verified", "text-hast-verified");
        const VOUCHED: (&str, &str) = ("bg-hast-warning", "text-hast-warning");
        let (title, how, (dot, tone)) = if i == 0 && other_device {
            (
                "Browser linked",
                "Vouched for by the account's identity key, and signed by this browser's own new key",
                SIGNED,
            )
        } else if i == 0 {
            ("Registered", "Signed by its own new keys", SIGNED)
        } else if recovery {
            ("Recovery", "Vouched for by the server only: not signed by the previous keys", VOUCHED)
        } else {
            ("Rotation", "Signed by the previous key and the co-signing key", SIGNED)
        };
        let signed_this = r == root;
        let when = at.get(i).filter(|t| **t > 0).map(|t| date_string(*t as f64 * 1000.0));
        view! {
            <li class="relative ml-4 pb-4 last:pb-0">
                <span class=format!("absolute -left-[22px] top-1 h-3 w-3 rounded-full border-2 border-hast-surface {dot}")></span>
                <div class="flex flex-wrap items-center gap-2 text-sm">
                    <span class="font-medium text-hast-text">{title}</span>
                    <span class="font-mono text-[11px] text-hast-muted">{format!("#{i} · {}…", r.get(..12).unwrap_or(r))}</span>
                    {when.map(|d| view! { <span class="text-[11px] text-hast-muted">{d}</span> })}
                    {signed_this.then(|| view! { <span class=format!("{BADGE} border-hast-primary/50 bg-hast-primary/10 text-hast-text")>"Signed this message"</span> })}
                </div>
                <div class=format!("text-xs {tone}")>{how}</div>
                {new_cosigner.then(|| view! { <div class="text-xs text-hast-warning">"New co-signing key: the safety number changed here"</div> })}
                {slh[i].is_none().then(|| view! { <div class="text-xs text-hast-muted">"No co-signing key (from before long-term keys)"</div> })}
                {replaced.then(|| view! { <div class="text-xs text-hast-danger">"Replaced by a later recovery: messages signed with this key are no longer trusted"</div> })}
            </li>
        }
    };
    view! {
        <div class="space-y-1.5">
            <div class="flex items-center gap-2"><Icon name="layers" class="w-3.5 h-3.5 text-hast-muted" /><span class="hast-label">{if other_device { format!("Key history for {sender} · another browser of theirs") } else { format!("Key history for {sender}") }}</span></div>
            {move || match dir.get() {
                None => view! { <div class="h-16 rounded-md bg-hast-elevated animate-pulse"></div> }.into_any(),
                Some(Dir::Bad) => view! {
                    <div class="flex items-start gap-2 rounded-md border px-3 py-2 text-sm chip-danger"><Icon name="shield-alert" class="w-4 h-4 mt-0.5 shrink-0" />"This account's key chain did not verify. Don't trust its messages."</div>
                }.into_any(),
                Some(Dir::Ok { roots, slh, recoveries, at, .. }) => view! {
                    <div class="rounded-md border border-hast-border bg-hast-bg/60 p-4 max-h-80 overflow-y-auto">
                        <div class="mb-3 flex items-center gap-1.5 text-xs text-hast-verified"><Icon name="check-circle" class="w-3.5 h-3.5" />
                            {format!("Chain verified in this browser · {} key{}{}", roots.len(), if roots.len() == 1 { "" } else { "s" },
                                match recoveries.len() { 0 => String::new(), 1 => " · 1 recovery".into(), n => format!(" · {n} recoveries") })}
                        </div>
                        <ol class="border-l border-hast-border">
                            {roots.iter().enumerate().rev().map(|(i, r)| link(i, r, &slh, &recoveries, &at)).collect_view()}
                        </ol>
                    </div>
                }.into_any(),
            }}
            <p class="text-[11px] text-hast-muted">"Newest first. Checked here from the account's public key chain; the dates are recorded by the server and are not signed."</p>
        </div>
    }
}

pub(super) fn inspector(m: ChatMessage, me: String, trust_rev: RwSignal<u32>, chains: RwSignal<HashMap<String, Dir>>, on_confirm: Callback<String>) -> impl IntoView {
    let history = key_history(me.clone(), m.sender.clone(), m.device.clone(), m.commitment.clone(), chains);
    let safety = safety_panel(&m, me, trust_rev, on_confirm);
    let unconfirmed = m.verified && m.unconfirmed;
    let total = m.signature.revealed_preimages.len();
    let shown: Vec<_> = m.signature.revealed_preimages.iter().take(10).cloned().enumerate().collect();
    let ok = m.verified;
    let check = |done: bool, text: String| {
        view! {
            <li class="flex items-start gap-2">
                <Icon name=if done { "check" } else { "info" } class=format!("w-4 h-4 mt-0.5 shrink-0 {}", if done { "text-hast-verified" } else { "text-hast-muted" }) />
                <span>{text}</span>
            </li>
        }
    };
    view! {
        <div class="p-6 space-y-6 max-w-4xl mx-auto">
            <div class="flex flex-wrap items-center justify-between gap-3">
                <div>
                    <h2 class="hast-title text-xl">"Signature inspector"</h2>
                    <p class="text-sm text-hast-secondary">"Message from "<span class="font-mono text-hast-text">{m.sender.clone()}</span></p>
                </div>
                {if unconfirmed {
                    view! { <span data-status="unconfirmed" class=format!("{BADGE} chip-warning text-sm px-3 py-1")><Icon name="shield-alert" class="w-4 h-4 mr-1.5" />"Keys not confirmed"</span> }.into_any()
                } else if ok {
                    view! { <span class=format!("{BADGE} chip-verified text-sm px-3 py-1")><Icon name="shield-check" class="w-4 h-4 mr-1.5" />"Signature verified"</span> }.into_any()
                } else {
                    view! { <span class=format!("{BADGE} chip-danger text-sm px-3 py-1")><Icon name="shield-alert" class="w-4 h-4 mr-1.5" />"Verification failed"</span> }.into_any()
                }}
            </div>

            <div class=format!("rounded-lg border p-5 {}", if unconfirmed { "border-hast-warning/40 bg-hast-warning/5" } else if ok { "border-hast-verified/40 bg-hast-verified/5" } else { "border-hast-danger/50 bg-hast-danger/10" })>
                {unconfirmed.then(|| view! {
                    <p class="mb-3 flex items-start gap-2 text-sm text-hast-warning"><Icon name="shield-alert" class="w-4 h-4 mt-0.5 shrink-0" />
                        "The signatures check out, but the keys behind them were vouched for by the server alone (an account recovery), or the safety number changed. Compare the safety number below with them in person or over another channel, then mark it verified."
                    </p>
                })}
                <ul class="space-y-1.5 text-sm text-hast-secondary">
                    {if ok {
                        view! {
                            {check(true, "All preimages hash correctly to the commitment root".into())}
                            {check(true, "Message digest matches the signature".into())}
                            {check(true, "Merkle tree verification passed".into())}
                            {check(m.cosigned, if m.cosigned { "SLH-DSA-SHAKE-128f co-signature verified".into() } else { "No SLH-DSA co-signature (sent before co-signing)".into() })}
                            {check(m.group || m.recipients > 0, if m.group { "End-to-end encrypted with the sender's group key (XChaCha20-Poly1305; the key reached members sealed with ML-KEM-768)".to_string() } else if m.recipients > 0 { format!("End-to-end encrypted to {} key(s): ML-KEM-768 + XChaCha20-Poly1305", m.recipients) } else { "Sent in the clear (before end-to-end encryption)".to_string() })}
                        }.into_any()
                    } else {
                        view! { <li class="flex items-start gap-2 text-hast-danger"><Icon name="x-circle" class="w-4 h-4 mt-0.5 shrink-0" /><span>"The signature does not check out: the message may have been tampered with"</span></li> }.into_any()
                    }}
                </ul>
                {(!m.note.is_empty()).then(|| view! {
                    <p class=format!("mt-3 flex items-start gap-2 text-sm {}", if ok { "text-hast-warning" } else { "text-hast-danger" })>
                        <Icon name="alert-triangle" class="w-4 h-4 mt-0.5 shrink-0" />
                        {format!("{}: {}", if ok { "Notice" } else { "Reason" }, m.note)}
                    </p>
                })}
            </div>

            <div class="hast-panel p-5 space-y-5">
                <div class="space-y-1.5">
                    <span class="hast-label">"Decrypted message"</span>
                    <div class="rounded-md border border-hast-border bg-hast-bg/60 p-3 text-hast-text">{m.message.clone()}</div>
                </div>
                {safety}
                {history}
                {field("Message digest · SHA-512".into(), "hash", m.signature.digest.clone(), format!("512-bit hash · {} hex characters", m.signature.digest.len()))}
                <div class="space-y-1.5">
                    <div class="flex items-center gap-2"><Icon name="key" class="w-3.5 h-3.5 text-hast-muted" /><span class="hast-label">{format!("Revealed preimages · {total} of {}", hbss::N)}</span></div>
                    <div class="space-y-1.5 max-h-96 overflow-y-auto pr-1">
                        {shown.into_iter().map(|(i, p)| view! {
                            <div class="grid grid-cols-[auto_1fr] gap-3 rounded-md border border-hast-border bg-hast-bg/60 p-2.5">
                                <span class="font-mono text-[11px] text-hast-muted">{format!("#{:04}", m.signature.indices.get(i).copied().unwrap_or(0))}</span>
                                <span class="hast-mono select-all">{p}</span>
                            </div>
                        }).collect_view()}
                        {(total > 10).then(|| view! {
                            <p class="py-2 text-center text-xs text-hast-muted">{format!("... and {} more", total - 10)}</p>
                        })}
                    </div>
                    <p class="text-[11px] text-hast-muted">"These secret values prove ownership of the private key"</p>
                </div>
                {field("Public key · commitment root".into(), "fingerprint", m.commitment.clone(), format!("Merkle tree root · {} hex characters", m.commitment.len()))}
            </div>
        </div>
    }
}
