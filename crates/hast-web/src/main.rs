mod auth;
mod contacts;
mod history;
mod pages;
mod sealed;
mod ui;
mod util;
mod webauthn;
mod worker;

use auth::AuthGate;
use leptos::prelude::*;
use leptos_router::components::{Route, Router, Routes};
use leptos_router::path;
use pages::*;

#[component]
fn App() -> impl IntoView {
    view! {
        <Router>
            <AuthGate>
                <ui::AppShell>
                    <Routes fallback=NotFound>
                        <Route path=path!("/") view=Index />
                        <Route path=path!("/account") view=Account />
                        <Route path=path!("/chat") view=LiveChat />
                        <Route path=path!("/messaging") view=Messaging />
                        <Route path=path!("/hbss-lab") view=HBSSLab />
                        <Route path=path!("/hbss-explained") view=HBSSIllustration />
                        <Route path=path!("/quantum-playground") view=QuantumCryptographyPlayground />
                        <Route path=path!("/cipher-lab") view=CipherBuilder />
                        <Route path=path!("/cipher-chat") view=CipherChat />
                        <Route path=path!("/securecomm") view=SecureMessenger />
                        <Route path=path!("/network") view=NetworkSimulatorExtended />
                        <Route path=path!("/blackberry") view=BlackBerrySecureChat />
                        <Route path=path!("/blackberry/settings") view=BlackBerrySettingsPanel />
                    </Routes>
                </ui::AppShell>
            </AuthGate>
        </Router>
    }
}

fn main() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(App);
}
