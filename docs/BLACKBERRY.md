# BlackBerry Dynamics in HAST

HAST's messaging pages are modelled on BlackBerry Dynamics (GD), BlackBerry's container for enterprise apps. The
real SDK can't run in a browser or on the server, so HAST ships a mock with the SDK's real shapes. This page
explains what is mocked, how it maps to the SDK, and what a real BlackBerry client would take.

## Why a mock

The BlackBerry Dynamics SDK for React Native is a set of native iOS/Android modules. An app built with it must be
activated against a BlackBerry UEM server before any of them work. HAST is a web app, so it has no native layer and
no UEM activation. The mock lets the UI and server behave the way they would inside a container, without
pretending to give the container's protections.

## SDK modules and their HAST counterparts

| SDK module (`BlackBerry-Dynamics-for-React-Native-*`) | what it provides | in HAST |
|---|---|---|
| `Application` | `getApplicationConfig()`, `getApplicationPolicy()` | `hast_core::bbd::ApplicationConfig`, field for field; policy is a free-form JSON object |
| `Async-Storage` | key/value storage inside the encrypted container | `localStorage` in the UI; the `messages` table in the server's SQLite database |
| `Networking` | `fetch`, `XMLHttpRequest` and `WebSocket` routed through the GD proxy | plain `fetch` and WebSocket to the HAST server |
| `Clipboard` | clipboard that respects DLP policy | the `copyPasteOn` and `preventPasteFromNonGDApps` switches |
| `Base`, `Launcher`, `AppKinetics`, `FileSystem`, `SQLite-Storage`, `Camera` | runtime, launcher UI, inter-app calls, container files and DB, camera | not used |

## The mock (`hast_core::bbd`)

* `ApplicationConfig` copies the SDK type: `appHost`, `appPort`, `appServers`, `communicationProtocols`,
  `containerId`, `copyPasteOn`, `detailedLogsOn`, `enterpriseId`, the dictation and keyboard restrictions,
  `preventPasteFromNonGDApps`, `preventScreenCapture`, `preventScreenRecording` and the rest. JSON produced by the
  mock deserialises as the SDK's type and the other way round.
* `BlackBerryDynamics` is a small service object with `initialize`, `encrypt_message` and `decrypt_message`.
  `initialize` creates a random 256-bit container key (the real SDK keeps such a key inside its container), and
  messages are sealed with XChaCha20-Poly1305 under it. The key lives only in memory for the page's lifetime; it is
  not a substitute for the container's managed, policy-bound storage.
* `ApplicationConfig::mock()` gives sample values and `with_settings` applies the settings page;
  `Settings::to_policy` produces the policy object.
* The **BB Dynamics** page (`/blackberry/settings`) edits the config. Its DLP switches drive `copyPasteOn`,
  `preventPasteFromNonGDApps`, `preventScreenCapture` and `preventScreenRecording`.
* The **messaging** channel's `GD` mode stands for "sent over the GD transport". Messages (end-to-end encrypted, so
  ciphertext only) go to the HAST server and are stored in its database, standing in for container storage.

A browser can't block screenshots or other apps' paste, so the DLP switches only change the config and policy the
mock reports. Inside a real container, the GD runtime would enforce them.

## Building a real BlackBerry client

A real client would be a separate React Native (or native Android/iOS) app that talks to the existing HAST server:

1. Start from one of the SDK's `SampleApplications` and add the `Application`, `Networking` and `Async-Storage`
   modules.
2. Register the app in your BlackBerry UEM console, entitle test users, and activate the app on a device.
3. Use the SDK's `fetch`/`WebSocket` for `/api/*`, `/ws` and `/ws/messaging`. The protocols are in
   [ARCHITECTURE.md](../ARCHITECTURE.md).
4. Sign, co-sign and seal on the device. `hast-core` has no I/O, so it can be compiled for Android/iOS (or to WASM
   inside React Native) and reused unchanged. Store the private keys with `Async-Storage`, which keeps them inside the
   container.
5. The server needs no change, except possibly `HAST_ALLOWED_ORIGINS` if the client sends an `Origin` header.

The SDK itself requires a BlackBerry developer account and the UEM entitlements described in BlackBerry's
documentation. It isn't distributed with HAST.
