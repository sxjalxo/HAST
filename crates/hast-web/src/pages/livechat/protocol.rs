//! The LiveChat websocket protocol: what each server frame does to the page, and local history on load.
use super::*;

/// What this browser kept of earlier conversations (see `history`): checked again (signatures, keys, trust) but not
/// decrypted again, since those keys are gone.
pub(super) async fn load_local(me: &str, messages: RwSignal<Vec<ChatMessage>>, chains: RwSignal<HashMap<String, Dir>>, seen: RwSignal<HashSet<String>>) {
    // ponytail: every kept message is checked on each load; keep only the newest per room if that gets slow
    let mut shown = vec![];
    for (key, rec) in history::all(me).await {
        let Some(k) = key.strip_prefix("chat:") else { continue };
        let c = check(&rec["frame"], me, chains, None, rec["text"].as_str()).await;
        seen.try_update(|s| s.insert(k.to_string()));
        shown.push(to_message(&rec["frame"], me, c));
    }
    shown.sort_by(|a, b| a.timestamp.total_cmp(&b.timestamp));
    messages.try_set(shown);
}

/// Everyone with an account, from the directory.
pub(super) async fn load_members(members: RwSignal<Vec<String>>, alive: std::sync::Arc<std::sync::atomic::AtomicBool>) {
    let Ok(v) = auth::call("GET", "/api/directory", None).await else { return };
    if is_alive(&alive) {
        members.try_set(
            v["accounts"]
                .as_array()
                .map(|a| a.iter().filter_map(|x| x["username"].as_str().map(String::from)).collect())
                .unwrap_or_default(),
        );
    }
}

pub(super) fn request_scroll() {
    spawn_local(async {
        TimeoutFuture::new(0).await;
        scroll_to_bottom("msgs");
    });
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_incoming(
    data: Value,
    me: &str,
    key_pair: RwSignal<Option<KeyPair>>,
    lt: RwSignal<Option<LongTermKeys>>,
    rotate_due: RwSignal<bool>,
    messages: RwSignal<Vec<ChatMessage>>,
    online: RwSignal<Vec<String>>,
    stats: RwSignal<Stats>,
    chains: RwSignal<HashMap<String, Dir>>,
    seen: RwSignal<HashSet<String>>,
    older_done: RwSignal<HashSet<String>>,
    notice: RwSignal<String>,
) {
    // the same message twice (by sender and id) is a replay, whoever delivers it
    let first_time = |m: &Value| {
        let key = format!("{}:{}", m["sender"].as_str().unwrap_or_default().to_lowercase(), m["id"].as_str().unwrap_or_default());
        seen.try_update(|s| s.insert(key)).unwrap_or(true)
    };
    match data["type"].as_str() {
        Some("system") => return,
        Some("welcome") => {
            // every active device's current key: ours must be one of them
            let mine = key_pair.get_untracked().map(|k| k.public_key.commitment_root).unwrap_or_default();
            if !data["heads"].as_array().is_some_and(|h| h.iter().any(|r| r == mine.as_str())) {
                notice.set("Your account's key was changed from another session. Reload the page to sync.".into());
            }
            let stale = lt.get_untracked().is_none_or(|k| now_ms() - k.kem_since > KEM_MAX_AGE_MS);
            // keys imported from another browser are marked used up: hand over before signing anything
            let used_up = auth::key_uses(me) >= ROTATE_AFTER;
            rotate_due.try_set(data["slh"].is_null() || stale || used_up);
            return;
        }
        Some("error") => {
            notice.set(format!("Server rejected a message: {}", data["reason"].as_str().unwrap_or("unknown reason")));
            return;
        }
        Some("history") => {
            let mut shown = vec![];
            for m in data["messages"].as_array().cloned().unwrap_or_default() {
                if m["type"] == "rotate" {
                    continue; // the directory already has the whole chain
                }
                if !first_time(&m) {
                    continue; // already here: kept in this browser, or shown before a reconnect
                }
                let c = check(&m, me, chains, lt.get_untracked().as_ref(), None).await;
                keep(me, &m, &c).await;
                shown.push(to_message(&m, me, c));
            }
            messages.try_update(|all| {
                all.extend(shown);
                all.sort_by(|a, b| a.timestamp.total_cmp(&b.timestamp));
            });
            return;
        }
        Some("older") => {
            let mut shown = vec![];
            for m in data["messages"].as_array().cloned().unwrap_or_default() {
                if m["type"] == "rotate" {
                    continue;
                }
                if !first_time(&m) {
                    continue; // already on screen
                }
                let c = check(&m, me, chains, lt.get_untracked().as_ref(), None).await;
                keep(me, &m, &c).await;
                shown.push(to_message(&m, me, c));
            }
            messages.try_update(|all| {
                all.splice(0..0, shown);
            });
            if data["more"] == false {
                older_done.try_update(|d| {
                    d.insert(data["room"].as_str().unwrap_or(identity::LOBBY).to_string());
                });
            }
            return;
        }
        Some("senderkeys") => {
            for f in data["frames"].as_array().cloned().unwrap_or_default() {
                take_sender_key(&f, me, chains, lt.get_untracked().as_ref()).await;
            }
            return;
        }
        Some("senderkey") => {
            take_sender_key(&data, me, chains, lt.get_untracked().as_ref()).await;
            return;
        }
        Some("rotate") => {
            if let Some(sender) = data["sender"].as_str() {
                let key = match data["device"].as_str() {
                    Some(d) if d != identity::PRIMARY => format!("{sender}#{d}"),
                    _ => sender.to_string(),
                };
                chains.try_update(|c| {
                    c.remove(&key);
                });
            }
            return;
        }
        Some("users") => {
            online.try_set(
                data["users"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|u| u.as_str().map(String::from)).collect())
                    .unwrap_or_default(),
            );
            return;
        }
        _ => {}
    }
    // the server never echoes a connection's own messages; another tab of ours is checked like anyone else
    let t0 = perf_now();
    let mut c = check(&data, me, chains, lt.get_untracked().as_ref(), None).await;
    let dt = perf_now() - t0;
    keep(me, &data, &c).await;
    if !first_time(&data) {
        (c.verified, c.note) = (false, "Duplicate of an earlier message (replayed)");
    } else if data["sentAt"].as_f64().is_some_and(|t| (now_ms() - t).abs() > MAX_SKEW_MS) {
        (c.verified, c.note) = (false, "Delivered long after it was signed (possible replay)");
    }
    stats.try_update(|st| {
        st.avg_verify = (st.avg_verify * st.verified as f64 + dt) / (st.verified as f64 + 1.0);
        st.verified += 1;
    });
    messages.try_update(|m| m.push(to_message(&data, me, c)));
}
