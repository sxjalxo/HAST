//! Port of src/pages/HBSSIllustration.tsx
use crate::ui::*;
use crate::util::Icon;
use leptos::prelude::*;

struct Step {
    title: &'static str,
    description: &'static str,
    visual: &'static str,
    detail: &'static str,
}

const KEYGEN: [Step; 4] = [
    Step {
        title: "Generate Random Preimages",
        description: "Create 1024 random 256-bit values",
        visual: "🎲 → [P₁, P₂, P₃, ..., P₁₀₂₄]",
        detail: "Each preimage is a cryptographically secure random number",
    },
    Step {
        title: "Hash Preimages Multiple Times",
        description: "Hash each preimage 512 times using SHA-512",
        visual: "P₁ → H(P₁) → H(H(P₁)) → ... → C₁",
        detail: "Creates a one-way chain: easy to compute forward, impossible to reverse",
    },
    Step {
        title: "Build Merkle Tree",
        description: "Organize commitments into a binary tree",
        visual: "C₁ C₂ → H(C₁||C₂) → Root",
        detail: "Allows efficient verification of any commitment",
    },
    Step {
        title: "Store Keys",
        description: "Private key = preimages, Public key = root",
        visual: "Private: [P₁...P₁₀₂₄] | 🔓 Public: Root",
        detail: "Public key is just 64 bytes, private key is ~32KB",
    },
];

const SIGNING: [Step; 3] = [
    Step {
        title: "Hash the Message",
        description: "Create SHA-512 digest of the message",
        visual: "\"Hello\" → SHA-512 → digest",
        detail: "Produces a 512-bit fingerprint of the message",
    },
    Step {
        title: "Select Preimages",
        description: "Use digest bits to choose which preimages to reveal",
        visual: "digest[0]=1 → reveal P₁, digest[1]=0 → skip P₂",
        detail: "Each bit determines if we reveal that preimage",
    },
    Step {
        title: "Create Signature",
        description: "Package digest, indices, and revealed preimages",
        visual: "σ = {digest, [1,3,5...], [P₁,P₃,P₅...]}",
        detail: "Signature size: ~16KB (half the preimages on average)",
    },
];

const VERIFY: [Step; 4] = [
    Step {
        title: "Hash the Message",
        description: "Recompute the message digest",
        visual: "\"Hello\" → SHA-512 → digest'",
        detail: "Must match the digest in the signature",
    },
    Step {
        title: "Hash Revealed Preimages",
        description: "Hash each preimage 512 times",
        visual: "P₁ → H⁵¹²(P₁) → C₁'",
        detail: "Recreate the commitments from preimages",
    },
    Step {
        title: "Verify Commitments",
        description: "Check if commitments match public key",
        visual: "C₁' == C₁ (from public key)",
        detail: "Uses Merkle tree to verify efficiently",
    },
    Step {
        title: "Signature Valid!",
        description: "All checks passed",
        visual: "Message is authentic",
        detail: "Quantum computers can't forge this signature",
    },
];

const VISUAL_TITLES: [&str; 5] = [
    "Step 1: Original Message",
    "Step 2: Hash the Message",
    "Step 3: Select Preimages",
    "Step 4: Create Signature",
    "Step 5: Verify Signature",
];
const VISUAL_TEXT: [&str; 5] = [
    "Start with any message you want to sign. This could be a chat message, document, or any data.",
    "Hash the message using SHA-512 to create a 512-bit digest. This is a unique fingerprint of the message.",
    "Use each bit of the digest to decide which preimages to reveal. Bit=1 means reveal, bit=0 means skip.",
    "Package the digest, indices, and revealed preimages into the final signature. This proves you have the private key.",
    "Anyone can verify by hashing the message, hashing the preimages, and checking against the public key. Quantum computers can't forge this!",
];

fn tab_class(active: bool, color: &'static str) -> String {
    format!("{TAB} {}", if active { color } else { "" })
}

#[component]
fn Arrow(show: bool) -> impl IntoView {
    show.then(|| view! { <div class="flex justify-center mb-8 animate-pulse"><Icon name="arrow-right" class="w-6 h-6 text-hast-muted rotate-90" /></div> })
}

#[component]
pub fn HBSSIllustration() -> impl IntoView {
    let tab = RwSignal::new("keygen");
    let active_step = RwSignal::new(0usize);
    let vs = RwSignal::new(0usize);
    let op = move |n: usize| if vs.get() >= n { "opacity-100" } else { "opacity-30" };
    let card = |_accent: &'static str| CARD.to_string();

    view! {
        <div>
            <PageHeader icon="book-open" title="HBSS Explained" subtitle="Hash-based stateless signatures, behind the scenes" />
            <div class="max-w-6xl mx-auto p-6 space-y-6">
                <div class=card("border-hast-primary/30")>
                    <div class=CARD_HEADER><h3 class="hast-title text-lg flex items-center gap-2"><Icon name="info" class="w-5 h-5 text-hast-muted" />"What is HBSS?"</h3></div>
                    <div class=format!("{CARD_CONTENT} space-y-4")>
                        <p class="text-hast-secondary">
                            "HBSS (Hash-Based Stateless Signatures) is a "<span class="text-hast-text font-semibold">"quantum-resistant"</span>" digital signature scheme. Unlike RSA or ECDSA which can be broken by quantum computers, HBSS relies only on hash functions (SHA-512), which remain secure even against quantum attacks."
                        </p>
                        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
                            <div class="p-4 bg-hast-elevated border border-hast-border rounded-lg"><Icon name="shield" class="w-6 h-6 text-hast-secondary mb-3" /><h3 class="text-hast-text font-semibold mb-1">"Quantum-Safe"</h3><p class="text-sm text-hast-secondary">"Secure against quantum computers"</p></div>
                            <div class="p-4 bg-hast-elevated border border-hast-border rounded-lg"><Icon name="hash" class="w-6 h-6 text-hast-secondary mb-3" /><h3 class="text-hast-text font-semibold mb-1">"Hash-Based"</h3><p class="text-sm text-hast-secondary">"Uses only SHA-512 hashing"</p></div>
                            <div class="p-4 bg-hast-elevated border border-hast-border rounded-lg"><Icon name="zap" class="w-6 h-6 text-hast-secondary mb-3" /><h3 class="text-hast-text font-semibold mb-1">"Stateless"</h3><p class="text-sm text-hast-secondary">"No state tracking required"</p></div>
                        </div>
                    </div>
                </div>

                <div class="space-y-4">
                    <div class=format!("{TABS_LIST_MUTED} flex-wrap h-auto")>
                        <button class=move || tab_class(tab.get() == "visual", TAB_ACTIVE) on:click=move |_| tab.set("visual")><Icon name="zap" class="w-4 h-4 mr-2" />"Live Demo"</button>
                        <button class=move || tab_class(tab.get() == "keygen", TAB_ACTIVE) on:click=move |_| tab.set("keygen")><Icon name="key" class="w-4 h-4 mr-2" />"Key Generation"</button>
                        <button class=move || tab_class(tab.get() == "signing", TAB_ACTIVE) on:click=move |_| tab.set("signing")><Icon name="lock" class="w-4 h-4 mr-2" />"Signing"</button>
                        <button class=move || tab_class(tab.get() == "verify", TAB_ACTIVE) on:click=move |_| tab.set("verify")><Icon name="check-circle" class="w-4 h-4 mr-2" />"Verification"</button>
                        <button class=move || tab_class(tab.get() == "security", TAB_ACTIVE) on:click=move |_| tab.set("security")><Icon name="alert-triangle" class="w-4 h-4 mr-2" />"Security"</button>
                    </div>

                    // ---- Live demo ----
                    <div class="space-y-4" class:hidden=move || tab.get() != "visual">
                        <div class=card("border-hast-primary/30")>
                            <div class=CARD_HEADER>
                                <h3 class="hast-title text-lg">"Interactive HBSS Signing Visualization"</h3>
                                <p class="text-sm text-hast-muted">"Watch the signing process step-by-step"</p>
                            </div>
                            <div class=format!("{CARD_CONTENT} space-y-6")>
                                <div class="relative p-8 bg-hast-bg rounded-lg border border-hast-border">
                                    <div class=move || format!("transition-all duration-500 {}", op(0))>
                                        <div class="flex items-center justify-center mb-8"><div class="p-6 bg-hast-elevated border border-hast-border rounded-lg"><div class="text-hast-text text-center">
                                            <div class="text-sm font-semibold mb-2">"Original Message"</div><div class="text-2xl font-mono">"\"Hello, World!\""</div></div></div></div>
                                    </div>
                                    {move || view! { <Arrow show={vs.get() >= 1} /> }}
                                    <div class=move || format!("transition-all duration-500 {}", op(1))>
                                        <div class="flex items-center justify-center mb-8"><div class="p-6 bg-hast-elevated border border-hast-border rounded-lg"><div class="text-hast-text text-center">
                                            <div class="text-sm font-semibold mb-2">"SHA-512 Hash"</div>
                                            <div class="text-xs font-mono break-all max-w-md">"a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e..."</div>
                                            <div class="text-xs text-hast-secondary mt-2">"512 bits (64 bytes)"</div></div></div></div>
                                    </div>
                                    {move || view! { <Arrow show={vs.get() >= 2} /> }}
                                    <div class=move || format!("transition-all duration-500 {}", op(2))>
                                        <div class="flex items-center justify-center mb-8"><div class="p-6 bg-hast-elevated border border-hast-border rounded-lg"><div class="text-hast-text text-center">
                                            <div class="text-sm font-semibold mb-3">"Select Preimages"</div>
                                            <div class="flex gap-2 justify-center flex-wrap max-w-md">
                                                <div class="px-3 py-1 border border-hast-primary/60 bg-hast-primary/10 rounded font-mono text-xs">"P₁ ✓"</div>
                                                <div class="px-3 py-1 border border-hast-border rounded font-mono text-xs text-hast-muted">"P₂ ✗"</div>
                                                <div class="px-3 py-1 border border-hast-primary/60 bg-hast-primary/10 rounded font-mono text-xs">"P₃ ✓"</div>
                                                <div class="px-3 py-1 border border-hast-primary/60 bg-hast-primary/10 rounded font-mono text-xs">"P₄ ✓"</div>
                                                <div class="px-3 py-1 border border-hast-border rounded font-mono text-xs text-hast-muted">"P₅ ✗"</div>
                                                <div class="px-3 py-1 border border-hast-primary/60 bg-hast-primary/10 rounded font-mono text-xs">"P₆ ✓"</div>
                                                <div class="text-hast-text">"..."</div>
                                            </div>
                                            <div class="text-xs font-mono text-hast-muted mt-2">"Based on hash bits: 1,0,1,1,0,1..."</div></div></div></div>
                                    </div>
                                    {move || view! { <Arrow show={vs.get() >= 3} /> }}
                                    <div class=move || format!("transition-all duration-500 {}", op(3))>
                                        <div class="flex items-center justify-center mb-8"><div class="p-6 bg-hast-elevated border border-hast-primary/60 rounded-lg"><div class="text-hast-text text-center">
                                            <div class="text-sm font-semibold mb-3">"HBSS Signature"</div>
                                            <div class="space-y-2 text-xs">
                                                <div class="p-2 bg-hast-surface rounded"><span class="text-hast-secondary">"Digest:"</span>" a591a6d40bf4..."</div>
                                                <div class="p-2 bg-hast-surface rounded"><span class="text-hast-secondary">"Indices:"</span>" [1, 3, 4, 6, ...]"</div>
                                                <div class="p-2 bg-hast-surface rounded"><span class="text-hast-secondary">"Preimages:"</span>" [P₁, P₃, P₄, P₆, ...]"</div>
                                            </div>
                                            <div class="text-xs text-hast-secondary mt-2">"~16 KB signature size"</div></div></div></div>
                                    </div>
                                    {move || view! { <Arrow show={vs.get() >= 4} /> }}
                                    <div class=move || format!("transition-all duration-500 {}", op(4))>
                                        <div class="flex items-center justify-center"><div class="p-6 bg-hast-verified/5 border border-hast-verified/50 rounded-lg"><div class="text-hast-text text-center">
                                            <div class="text-sm font-semibold mb-3">"Verification"</div>
                                            <div class="space-y-2 text-xs">
                                                <div class="flex items-center gap-2 justify-center"><Icon name="check-circle" class="w-4 h-4 text-hast-verified" /><span>"Hash message → matches digest"</span></div>
                                                <div class="flex items-center gap-2 justify-center"><Icon name="check-circle" class="w-4 h-4 text-hast-verified" /><span>"Hash preimages → matches commitments"</span></div>
                                                <div class="flex items-center gap-2 justify-center"><Icon name="check-circle" class="w-4 h-4 text-hast-verified" /><span>"Verify Merkle tree → matches public key"</span></div>
                                            </div>
                                            <div class="text-lg font-bold text-hast-verified mt-3">"Signature valid"</div></div></div></div>
                                    </div>
                                </div>
                                <div class="flex items-center justify-center gap-4">
                                    <button class=format!("{BTN} {BTN_OUTLINE}") disabled=move || vs.get() == 0 on:click=move |_| vs.update(|v| *v = v.saturating_sub(1))>"Previous Step"</button>
                                    <div class="px-3 py-1.5 border border-hast-border rounded-md"><span class="font-mono text-sm text-hast-secondary">{move || format!("Step {} of 5", vs.get() + 1)}</span></div>
                                    <button class=format!("{BTN} {BTN_DEFAULT}") disabled=move || vs.get() == 4 on:click=move |_| vs.update(|v| *v = (*v + 1).min(4))>"Next Step"</button>
                                </div>
                                <div class="p-4 bg-hast-elevated rounded-lg border border-hast-border">
                                    <h3 class="text-hast-text font-semibold mb-2">{move || VISUAL_TITLES[vs.get()]}</h3>
                                    <p class="text-hast-secondary text-sm">{move || VISUAL_TEXT[vs.get()]}</p>
                                </div>
                                <div class="flex justify-center"><button class=format!("{BTN} {BTN_OUTLINE}") on:click=move |_| vs.set(0)>"Reset Animation"</button></div>
                            </div>
                        </div>
                    </div>

                    // ---- Key generation ----
                    <div class="space-y-4" class:hidden=move || tab.get() != "keygen">
                        <div class=card("border-hast-link/30")>
                            <div class=CARD_HEADER>
                                <h3 class="hast-title text-lg">"Key Generation Process"</h3>
                                <p class="text-sm text-hast-muted">"How HBSS creates quantum-resistant key pairs"</p>
                            </div>
                            <div class=format!("{CARD_CONTENT} space-y-6")>
                                {KEYGEN.iter().enumerate().map(|(i, s)| view! {
                                    <div class=move || format!("p-4 rounded-lg border transition-all cursor-pointer {}", if active_step.get() == i { "bg-hast-primary/10 border-hast-primary/50" } else { "bg-hast-elevated/50 border-hast-border hover:border-hast-link/50" })
                                        on:click=move |_| active_step.set(i)>
                                        <div class="flex items-start gap-4">
                                            <div class=move || format!("w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 {}", if active_step.get() == i { "bg-hast-primary" } else { "bg-hast-border" })>
                                                <span class="text-hast-text font-bold">{i + 1}</span>
                                            </div>
                                            <div class="flex-1">
                                                <h3 class="text-hast-text font-semibold mb-1">{s.title}</h3>
                                                <p class="text-hast-secondary text-sm mb-2">{s.description}</p>
                                                <div class="p-3 bg-hast-bg rounded border border-hast-border font-mono text-sm text-hast-secondary">{s.visual}</div>
                                                {move || (active_step.get() == i).then(|| view! { <p class="text-hast-secondary text-sm mt-3 italic">"💡 "{s.detail}</p> })}
                                            </div>
                                        </div>
                                    </div>
                                }).collect_view()}
                                <div class="relative w-full rounded-lg border p-4 bg-hast-elevated border-hast-border text-hast-secondary">
                                    <strong>"Time:"</strong>" Key generation takes 2-5 seconds for 512 commitments. This is a one-time operation per user."
                                </div>
                            </div>
                        </div>
                    </div>

                    // ---- Signing ----
                    <div class="space-y-4" class:hidden=move || tab.get() != "signing">
                        <div class=card("border-hast-primary/30")>
                            <div class=CARD_HEADER>
                                <h3 class="hast-title text-lg">"Message Signing Process"</h3>
                                <p class="text-sm text-hast-muted">"How HBSS creates quantum-resistant signatures"</p>
                            </div>
                            <div class=format!("{CARD_CONTENT} space-y-6")>
                                {SIGNING.iter().enumerate().map(|(i, s)| view! {
                                    <div class="p-4 rounded-lg bg-hast-elevated/50 border border-hast-border">
                                        <div class="flex items-start gap-4">
                                            <div class="w-8 h-8 rounded-md border border-hast-border bg-hast-elevated flex items-center justify-center flex-shrink-0"><span class="font-mono text-sm text-hast-text">{i + 1}</span></div>
                                            <div class="flex-1">
                                                <h3 class="text-hast-text font-semibold mb-1">{s.title}</h3>
                                                <p class="text-hast-secondary text-sm mb-2">{s.description}</p>
                                                <div class="p-3 bg-hast-bg rounded border border-hast-border font-mono text-sm text-hast-secondary">{s.visual}</div>
                                                <p class="text-hast-secondary text-sm mt-3 italic">"💡 "{s.detail}</p>
                                            </div>
                                        </div>
                                        {(i < SIGNING.len() - 1).then(|| view! { <div class="flex justify-center mt-4"><Icon name="arrow-right" class="w-5 h-5 text-hast-muted rotate-90" /></div> })}
                                    </div>
                                }).collect_view()}
                                <div class="relative w-full rounded-lg border p-4 bg-hast-elevated border-hast-border text-hast-secondary">
                                    <strong>"Performance:"</strong>" Signing takes 30-100ms per message. Signature size is approximately 16KB."
                                </div>
                            </div>
                        </div>
                    </div>

                    // ---- Verification ----
                    <div class="space-y-4" class:hidden=move || tab.get() != "verify">
                        <div class=card("border-hast-verified/30")>
                            <div class=CARD_HEADER>
                                <h3 class="hast-title text-lg">"Signature Verification Process"</h3>
                                <p class="text-sm text-hast-muted">"How HBSS verifies message authenticity"</p>
                            </div>
                            <div class=format!("{CARD_CONTENT} space-y-6")>
                                {VERIFY.iter().enumerate().map(|(i, s)| {
                                    let last = i == VERIFY.len() - 1;
                                    view! {
                                        <div class="p-4 rounded-lg bg-hast-elevated/50 border border-hast-border">
                                            <div class="flex items-start gap-4">
                                                <div class=format!("w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 {}", if last { "bg-hast-verified" } else { "bg-hast-border" })>
                                                    {if last { view! { <Icon name="check-circle" class="w-5 h-5 text-hast-text" /> }.into_any() } else { view! { <span class="text-hast-text font-bold">{i + 1}</span> }.into_any() }}
                                                </div>
                                                <div class="flex-1">
                                                    <h3 class="text-hast-text font-semibold mb-1">{s.title}</h3>
                                                    <p class="text-hast-secondary text-sm mb-2">{s.description}</p>
                                                    <div class=format!("p-3 bg-hast-bg rounded border font-mono text-sm {}", if last { "border-hast-verified text-hast-verified" } else { "border-hast-border text-hast-secondary" })>{s.visual}</div>
                                                    <p class="text-hast-secondary text-sm mt-3 italic">"💡 "{s.detail}</p>
                                                </div>
                                            </div>
                                            {(!last).then(|| view! { <div class="flex justify-center mt-4"><Icon name="arrow-right" class="w-6 h-6 text-hast-verified" /></div> })}
                                        </div>
                                    }
                                }).collect_view()}
                                <div class="relative w-full rounded-lg border p-4 bg-hast-verified/10 border-hast-verified/30 text-hast-verified">
                                    <strong>"Speed:"</strong>" Verification takes 30-100ms per message. Anyone with the public key can verify signatures."
                                </div>
                            </div>
                        </div>
                    </div>

                    // ---- Security ----
                    <div class="space-y-4" class:hidden=move || tab.get() != "security">
                        <div class=card("border-hast-warning/30")>
                            <div class=CARD_HEADER>
                                <h3 class="hast-title text-lg">"Security Analysis"</h3>
                                <p class="text-sm text-hast-muted">"Why HBSS is quantum-resistant"</p>
                            </div>
                            <div class=format!("{CARD_CONTENT} space-y-6")>
                                <div class="space-y-4">
                                    <div class="p-4 bg-hast-verified/10 border border-hast-verified/30 rounded-lg">
                                        <h3 class="text-hast-verified font-semibold mb-2 flex items-center gap-2"><Icon name="shield" class="w-5 h-5" />"Quantum Resistance"</h3>
                                        <p class="text-hast-secondary text-sm mb-2">"HBSS is secure against quantum computers because it only uses hash functions. Grover's algorithm (the best quantum attack on hash functions) only provides a quadratic speedup, which can be countered by using longer hash outputs."</p>
                                        <div class="p-3 bg-hast-bg rounded border border-hast-verified text-sm">
                                            <div class="text-hast-verified font-mono">"Classical Security: 2²⁵⁶ operations"</div>
                                            <div class="text-hast-verified font-mono">"Quantum Security: 2¹²⁸ operations (still secure!)"</div>
                                        </div>
                                    </div>
                                    <div class="p-4 bg-hast-elevated border border-hast-border rounded-lg">
                                        <h3 class="text-hast-text font-semibold mb-2 flex items-center gap-2"><Icon name="hash" class="w-5 h-5" />"One-Way Functions"</h3>
                                        <p class="text-hast-secondary text-sm mb-2">"The security relies on the one-way property of hash functions. Given a commitment C = H⁵¹²(P), it's computationally infeasible to find P, even with a quantum computer."</p>
                                        <div class="p-3 bg-hast-bg rounded border border-hast-border text-sm text-hast-secondary font-mono">"Easy: P → H⁵¹²(P) = C"<br />"Impossible: C → ??? = P"</div>
                                    </div>
                                    <div class="p-4 bg-hast-elevated border border-hast-border rounded-lg">
                                        <h3 class="text-hast-text font-semibold mb-2 flex items-center gap-2"><Icon name="layers" class="w-5 h-5" />"Merkle Tree Efficiency"</h3>
                                        <p class="text-hast-secondary text-sm mb-2">"Using a Merkle tree allows efficient verification without revealing all commitments. The verifier only needs the root (public key) and the revealed preimages."</p>
                                        <div class="p-3 bg-hast-bg rounded border border-hast-border text-sm text-hast-secondary font-mono">"Public Key Size: 64 bytes"<br />"Signature Size: ~16 KB"<br />"Verification: O(log n) operations"</div>
                                    </div>
                                    <div class="p-4 bg-hast-warning/10 border border-hast-warning/30 rounded-lg">
                                        <h3 class="text-hast-warning font-semibold mb-2 flex items-center gap-2"><Icon name="alert-triangle" class="w-5 h-5" />"Limitations"</h3>
                                        <ul class="text-hast-secondary text-sm space-y-2">
                                            <li>"• "<strong>"Large signatures:"</strong>" ~16KB vs ~64 bytes for ECDSA"</li>
                                            <li>"• "<strong>"Slower:"</strong>" 30-100ms vs <1ms for ECDSA"</li>
                                            <li>"• "<strong>"One-time use:"</strong>" Each preimage should only be revealed once (stateless variant mitigates this)"</li>
                                            <li>"• "<strong>"Key generation:"</strong>" Takes 2-5 seconds vs instant for ECDSA"</li>
                                        </ul>
                                    </div>
                                </div>
                                <div class="relative w-full rounded-lg border p-4 bg-hast-warning/10 border-hast-warning/30 text-hast-warning">
                                    <strong>"Trade-off:"</strong>" HBSS sacrifices speed and size for quantum resistance. This is acceptable for applications where long-term security is critical."
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class=card("border-hast-primary/30")>
                    <div class=CARD_HEADER><h3 class="hast-title text-lg">"HBSS vs Traditional Signatures"</h3></div>
                    <div class=CARD_CONTENT>
                        <div class="overflow-x-auto">
                            <table class="w-full text-sm">
                                <thead><tr class="border-b border-hast-border">
                                    <th class="text-left p-3 text-hast-secondary">"Feature"</th><th class="text-left p-3 text-hast-text">"HBSS"</th><th class="text-left p-3 text-hast-text">"RSA/ECDSA"</th>
                                </tr></thead>
                                <tbody class="text-hast-secondary">
                                    <tr class="border-b border-hast-border"><td class="p-3">"Quantum Resistant"</td><td class="p-3 text-hast-verified">"Yes"</td><td class="p-3 text-hast-danger">"No"</td></tr>
                                    <tr class="border-b border-hast-border"><td class="p-3">"Signature Size"</td><td class="p-3 font-mono text-hast-text">"~16 KB"</td><td class="p-3 font-mono text-hast-text">"~64 bytes"</td></tr>
                                    <tr class="border-b border-hast-border"><td class="p-3">"Signing Speed"</td><td class="p-3 font-mono text-hast-text">"30-100ms"</td><td class="p-3 font-mono text-hast-text">"<1ms"</td></tr>
                                    <tr class="border-b border-hast-border"><td class="p-3">"Verification Speed"</td><td class="p-3 font-mono text-hast-text">"30-100ms"</td><td class="p-3 font-mono text-hast-text">"<1ms"</td></tr>
                                    <tr class="border-b border-hast-border"><td class="p-3">"Key Generation"</td><td class="p-3 font-mono text-hast-text">"2-5 seconds"</td><td class="p-3 font-mono text-hast-text">"Instant"</td></tr>
                                    <tr class="border-b border-hast-border"><td class="p-3">"Security Basis"</td><td class="p-3 text-hast-verified">"Hash functions"</td><td class="p-3 text-hast-danger">"Number theory"</td></tr>
                                    <tr><td class="p-3">"Future-Proof"</td><td class="p-3 text-hast-verified">"Yes"</td><td class="p-3 text-hast-danger">"Vulnerable to quantum"</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <div class="flex justify-center">
                    <a href="/chat" class=format!("{BTN} {BTN_DEFAULT}")>"Open LiveChat"<Icon name="arrow-right" class="w-4 h-4" /></a>
                </div>
            </div>
        </div>
    }
}
