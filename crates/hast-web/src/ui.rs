//! Shared component classes (shadcn/ui shapes on the HAST tokens), the HAST mark and the app shell.
use crate::util::Icon;
use leptos::prelude::*;
use leptos_router::hooks::use_location;

pub const BTN: &str = "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 h-10 px-4 py-2";
pub const BTN_DEFAULT: &str = "bg-hast-primary text-white hover:bg-hast-primary-hover";
pub const BTN_OUTLINE: &str = "border border-hast-border bg-hast-elevated text-hast-text hover:border-hast-muted";
pub const BTN_GHOST: &str = "text-hast-secondary hover:bg-hast-elevated hover:text-hast-text";
pub const CARD: &str = "rounded-lg border border-hast-border bg-hast-surface text-hast-text";
pub const CARD_HEADER: &str = "flex flex-col space-y-1.5 p-6";
pub const CARD_CONTENT: &str = "p-6 pt-0";
pub const BADGE: &str =
    "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2";
pub const INPUT: &str = "flex h-10 w-full rounded-md border border-hast-border bg-hast-elevated px-3 py-2 text-base text-hast-text ring-offset-background placeholder:text-hast-muted focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-hast-primary/60 focus-visible:border-hast-primary/60 disabled:cursor-not-allowed disabled:opacity-50 md:text-sm";
pub const TABS_LIST: &str =
    "flex w-full shrink-0 overflow-x-auto h-11 items-center justify-start gap-1 text-hast-muted bg-hast-surface border-b border-hast-border rounded-none px-6";
pub const TAB: &str =
    "inline-flex items-center justify-center whitespace-nowrap rounded-md px-3 py-1.5 text-sm font-medium transition-colors hover:text-hast-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";
pub const TAB_ACTIVE: &str = "bg-hast-elevated text-hast-text shadow-[inset_0_-2px_0_0_theme(colors.hast.primary)]";

/// Faint neutral grid behind the chat screens.
pub const GRID_BG: &str =
    "background-image:linear-gradient(rgba(43,51,64,0.25) 1px,transparent 1px),linear-gradient(90deg,rgba(43,51,64,0.25) 1px,transparent 1px);background-size:40px 40px";

// Sizes are separate so variants can be combined without conflicting h-* / px-* classes.
pub const BTN_BASE: &str = "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50";
pub const SZ_MD: &str = "h-10 px-4 py-2";
pub const SZ_SM: &str = "h-9 rounded-md px-3";
pub const BADGE_OUTLINE: &str = "inline-flex items-center rounded-md border border-hast-border px-2 py-0.5 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 text-hast-secondary";
pub const TABS_LIST_MUTED: &str = "inline-flex h-10 items-center justify-center rounded-md bg-hast-elevated p-1 text-hast-muted";
pub const TAB_SM: &str =
    "inline-flex items-center justify-center whitespace-nowrap rounded-md px-3 py-1.5 text-sm font-medium transition-colors hover:text-hast-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

/// shadcn Switch.
#[component]
pub fn Switch(#[prop(into)] checked: Signal<bool>, on_change: Callback<bool>) -> impl IntoView {
    view! {
        <button type="button" role="switch" aria-checked=move || checked.get().to_string()
            class=move || format!("peer inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background {}", if checked.get() { "bg-hast-primary" } else { "bg-hast-border" })
            on:click=move |_| on_change.run(!checked.get_untracked())>
            <span class=move || format!("pointer-events-none block h-5 w-5 rounded-full bg-hast-text shadow-lg ring-0 transition-transform {}", if checked.get() { "translate-x-5" } else { "translate-x-0" })></span>
        </button>
    }
}

pub const CARD_LAB: &str = "rounded-lg border border-hast-border bg-hast-surface text-hast-text";

/// The HAST mark (logo.png, cropped from the spider emblem). `loading` pulses it.
#[component]
pub fn Logo(#[prop(optional, into)] class: String, #[prop(optional)] loading: bool) -> impl IntoView {
    let class = format!("{class} object-contain {}", if loading { "animate-pulse" } else { "" });
    view! { <img src="/logo.png" alt="" aria-hidden="true" class=class /> }
}

/// The mark with the wordmark.
#[component]
pub fn Brand(#[prop(optional)] large: bool) -> impl IntoView {
    let (mark, word) = if large { ("w-11 h-11", "text-2xl") } else { ("w-7 h-7", "text-base") };
    view! {
        <div class="flex items-center gap-2.5">
            <Logo class=mark />
            <div class="leading-none">
                <div class=format!("{word} font-semibold tracking-[0.28em] text-hast-text")>"HAST"</div>
                <div class="mt-1 text-[10px] uppercase tracking-[0.18em] text-hast-muted">"Post-quantum toolkit"</div>
            </div>
        </div>
    }
}

/// (path, label, icon, demo): a demo runs on sample data and is labelled so everywhere it appears
pub type Module = (&'static str, &'static str, &'static str, bool);

/// What a demo label means, for its tooltip.
pub const DEMO_NOTE: &str = "Sample data for illustration: nothing on this page is sent, stored or verified";

/// Every module, grouped as the sidebar shows them.
pub const MODULES: &[(&str, &[Module])] = &[
    (
        "Workspace",
        &[
            ("/", "Overview", "layout-grid", false),
            ("/chat", "LiveChat", "message-square", false),
            ("/messaging", "Secure Messaging", "mail", false),
            ("/account", "Account", "settings", false),
        ],
    ),
    (
        "Labs",
        &[
            ("/hbss-lab", "HBSS Lab", "fingerprint", false),
            ("/hbss-explained", "HBSS Explained", "book-open", false),
            ("/quantum-playground", "Quantum Playground", "atom", false),
            ("/cipher-lab", "Cipher Lab", "flask-conical", false),
        ],
    ),
    (
        "Tools",
        &[
            ("/cipher-chat", "Cipher Chat", "message-circle", true),
            ("/securecomm", "SecureComm", "shield-check", true),
            ("/network", "Network Simulator", "network", true),
            ("/blackberry", "BlackBerry SecureChat", "smartphone", true),
            ("/blackberry/settings", "BB Dynamics", "sliders", true),
        ],
    ),
];

/// Sidebar navigation around every signed-in page; a drawer on small screens.
#[component]
pub fn AppShell(children: Children) -> impl IntoView {
    let auth = crate::auth::use_auth();
    let path = use_location().pathname;
    let open = RwSignal::new(false);
    let nav = MODULES
        .iter()
        .map(|(group, items)| {
            let links = items
                .iter()
                .map(|&(href, label, icon, demo)| {
                    view! {
                        <a href=href class="nav-item" aria-current=move || (path.get() == href).then_some("page") on:click=move |_| open.set(false)>
                            <Icon name=icon class="w-4 h-4 shrink-0" />
                            <span class="truncate">{label}</span>
                            {demo.then(|| view! { <DemoTag /> })}
                        </a>
                    }
                })
                .collect_view();
            view! {
                <div class="space-y-1">
                    <div class="hast-label px-3 pb-1">{*group}</div>
                    {links}
                </div>
            }
        })
        .collect_view();
    view! {
        <div class="flex h-screen bg-hast-bg text-hast-text">
            // moves focus itself: the router would treat `#main` as a navigation
            <a href="#main" class="skip-link" on:click=move |e| {
                e.prevent_default();
                use wasm_bindgen::JsCast;
                if let Some(main) = document().get_element_by_id("main").and_then(|m| m.dyn_into::<web_sys::HtmlElement>().ok()) {
                    let _ = main.focus();
                }
            }>"Skip to content"</a>
            {move || open.get().then(|| view! { <div class="fixed inset-0 z-30 bg-hast-bg/70 md:hidden" on:click=move |_| open.set(false)></div> })}
            // on small screens a drawer: Escape closes it
            <aside id="sidebar" class=move || format!("{} fixed inset-y-0 left-0 z-40 w-64 shrink-0 flex-col border-r border-hast-border bg-hast-surface md:static md:flex",
                if open.get() { "flex" } else { "hidden" })
                on:keydown=move |e| if e.key() == "Escape" { open.set(false) }>
                <div class="flex h-16 items-center justify-between border-b border-hast-border px-5">
                    <a href="/" on:click=move |_| open.set(false)><Brand /></a>
                    <button class="md:hidden text-hast-muted hover:text-hast-text" aria-label="Close menu" on:click=move |_| open.set(false)><Icon name="x" class="w-5 h-5" /></button>
                </div>
                <nav class="flex-1 space-y-6 overflow-y-auto px-3 py-5" aria-label="Modules">{nav}</nav>
                <div class="flex items-center gap-3 border-t border-hast-border px-4 py-3">
                    <div class="flex h-8 w-8 items-center justify-center rounded-md bg-hast-elevated text-xs font-semibold uppercase text-hast-text">
                        {move || auth.username().unwrap_or_default().chars().take(2).collect::<String>()}
                    </div>
                    <div class="min-w-0 flex-1">
                        <div class="truncate text-sm text-hast-text">{move || auth.username().unwrap_or_default()}</div>
                        <div class="flex items-center gap-1 text-[11px] text-hast-verified"><span class="h-1.5 w-1.5 rounded-full bg-hast-verified"></span>"Keys unlocked"</div>
                    </div>
                    <button class="rounded-md p-2 text-hast-muted hover:bg-hast-elevated hover:text-hast-text" title="Sign out" aria-label="Sign out"
                        on:click=move |_| { leptos::task::spawn_local(crate::auth::logout(auth)); }>
                        <Icon name="log-out" class="w-4 h-4" />
                    </button>
                </div>
            </aside>
            <div class="flex min-w-0 flex-1 flex-col">
                <header class="flex h-14 shrink-0 items-center gap-3 border-b border-hast-border bg-hast-surface px-4 md:hidden">
                    <button class="text-hast-secondary hover:text-hast-text" aria-label="Open menu" aria-controls="sidebar" aria-expanded=move || open.get().to_string()
                        on:click=move |_| open.set(true)><Icon name="menu" class="w-5 h-5" /></button>
                    <Brand />
                </header>
                <main id="main" tabindex="-1" class="min-h-0 flex-1 overflow-y-auto focus:outline-none">{children()}</main>
            </div>
        </div>
    }
}

/// Small "Demo" marker for modules that run on sample data.
#[component]
pub fn DemoTag() -> impl IntoView {
    view! { <span class="ml-auto shrink-0 rounded border border-hast-border px-1.5 text-[10px] font-medium uppercase tracking-wide text-hast-muted" title=DEMO_NOTE>"Demo"</span> }
}

/// Page header used by every module: icon, title, one-line description, optional actions on the right. `demo`
/// adds the sample-data label next to the title.
#[component]
pub fn PageHeader(
    icon: &'static str,
    title: &'static str,
    #[prop(optional)] subtitle: &'static str,
    #[prop(optional)] demo: bool,
    #[prop(optional)] children: Option<Children>,
) -> impl IntoView {
    view! {
        <div class="flex flex-wrap items-center justify-between gap-4 border-b border-hast-border bg-hast-surface/60 px-6 py-4">
            <div class="flex items-center gap-3">
                <div class="flex h-9 w-9 items-center justify-center rounded-md border border-hast-border bg-hast-elevated"><Icon name=icon class="w-4 h-4 text-hast-text" /></div>
                <div>
                    <h1 class="hast-title text-lg leading-tight flex items-center gap-2">
                        {title}
                        {demo.then(|| view! { <span class=format!("{BADGE} chip-warning font-normal") title=DEMO_NOTE>"Demo · sample data"</span> })}
                    </h1>
                    {(!subtitle.is_empty()).then(|| view! { <p class="text-xs text-hast-muted">{subtitle}</p> })}
                </div>
            </div>
            {children.map(|c| view! { <div class="flex flex-wrap items-center gap-2">{c()}</div> })}
        </div>
    }
}
