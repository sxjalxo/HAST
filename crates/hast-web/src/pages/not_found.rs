use leptos::prelude::*;

#[component]
pub fn NotFound() -> impl IntoView {
    view! {
        <div class="min-h-screen flex items-center justify-center bg-hast-text">
            <div class="text-center">
                <h1 class="text-4xl font-bold mb-4">"404"</h1>
                <p class="text-xl text-hast-muted mb-4">"Oops! Page not found"</p>
                <a href="/" class="text-hast-link hover:text-hast-link underline">"Return to Home"</a>
            </div>
        </div>
    }
}
