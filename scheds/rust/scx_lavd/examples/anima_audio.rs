//! Native PipeWire playback-stream discovery.
//!
//! Subscribes to the PipeWire registry and reports the PID of every
//! process currently playing audio through a playback stream. No `pactl`,
//! no subprocess, no polling: streams arrive as events and their PIDs are
//! resolved through the registry, so a stream stopping is observed
//! directly rather than inferred from a stall.
//!
//! ## How a PID is resolved
//!
//! A stream node does not carry its own PID. It only carries `client.id`;
//! the PID lives on the matching `PipeWire:Interface:Client` object as
//! `pipewire.sec.pid`. So we watch both object types and join them:
//!
//! ```text
//!   Node (media.class = Stream/Output/Audio)
//!     └─ client.id ──▶ Client (pipewire.sec.pid)
//! ```
//!
//! PipeWire guarantees no ordering between a stream and the client that
//! owns it, so a stream whose client has not been seen yet is held in a
//! pending list and resolved when the client arrives (and vice versa:
//! a client arriving first resolves streams already waiting on it).
//!
//! The `global` callback delivers the registry announcement plus a
//! complete-enough property set to classify the object; no `bind()` is
//! needed, because we only ever read `media.class` and `client.id`.
//!
//! ## Tracing
//!
//! The classifier boundary is silent by design, which makes failures hard
//! to see: a rejected node is indistinguishable from "nothing is playing".
//! Set `ANIMA_AUDIO_TRACE` to `1`, `true` or `on` to narrate on stderr
//! every decision — why each node was rejected, and how each PID was
//! resolved. The variable is read once at daemon start, never per event.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::mpsc::Sender;
use std::sync::LazyLock;
use std::thread;

use pipewire::context::ContextBox;
use pipewire::core::CoreBox;
use pipewire::main_loop::MainLoopBox;
use pipewire::properties::properties;
use pipewire::registry::GlobalObject;
use pipewire::spa::utils::dict::DictRef;
use pipewire::types::ObjectType;

/// A change in which processes are playing audio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioEvent {
    /// A playback stream is now owned by this PID.
    Started(u32),
    /// A playback stream owned by this PID went away.
    Stopped(u32),
}

/// Property key holding a node's media class.
const PROP_MEDIA_CLASS: &str = "media.class";

/// Value of `media.class` marking a playback stream, as opposed to capture
/// (`Stream/Input/Audio`) or a sink (`Audio/Sink`).
const MEDIA_CLASS_AUDIO_OUT: &str = "Stream/Output/Audio";

/// Node property pointing at the owning Client object's registry id.
const PROP_NODE_CLIENT_ID: &str = "client.id";

/// Client property holding the owning process's PID.
const PROP_CLIENT_PID: &str = "pipewire.sec.pid";

/// Parse a decimal property. Absent, unparseable, or 0 mean "unknown";
/// such streams are dropped rather than guessed at.
fn prop_pid(text: Option<&str>) -> Option<u32> {
    let pid: u32 = text?.trim().parse().ok()?;
    (pid >= 1).then_some(pid)
}

/* ── tracing ──────────────────────────────────────────────────────── */

/// Name of the environment variable enabling trace output.
const ENV_AUDIO_TRACE: &str = "ANIMA_AUDIO_TRACE";

/// Values, other than unset, that count as enabling tracing.
const TRACE_ENABLE_VALUES: [&str; 3] = ["1", "true", "on"];

/// Whether the classifier boundary narrates its decisions on stderr.
///
/// Sampling the environment once keeps the cost off the event path: the
/// `global` callback fires for every registry object the server
/// announces — every node, link and port — and a per-event
/// `std::env::var` would put a lookup and an allocation in that path
/// while re-deciding a value that cannot change while the process is
/// alive. `LazyLock` moves the read to exactly one access and keeps it
/// read-only afterwards.
///
/// Anything other than `1`, `true` or `on` (case-insensitive) is off,
/// including unset: a silent default keeps ordinary runs quiet, which is
/// what makes the traces trustworthy as a debugging tool.
static TRACE: LazyLock<bool> = LazyLock::new(read_env_trace);

/// The one-time initializer behind [`TRACE`].
fn read_env_trace() -> bool {
    std::env::var(ENV_AUDIO_TRACE).ok().is_some_and(|raw| {
        TRACE_ENABLE_VALUES
            .iter()
            .any(|v| v.eq_ignore_ascii_case(&raw))
    })
}

/// Resolve [`TRACE`] now, before any callback can observe it.
///
/// This MUST be called from the daemon start path
/// (`spawn_audio_watcher`) and never from inside a callback: a registry
/// announcement arriving mid-initialization would otherwise pay for the
/// one-time read as a side effect of instead of before the subscription.
pub fn init_trace_from_env() {
    let _ = *TRACE;
}

/// Print one trace line when tracing is on, and otherwise do nothing at
/// all — the `trace!` call site must not allocate or touch stderr when
/// tracing is off.
macro_rules! trace {
    ($($arg:tt)*) => {
        if *TRACE {
            eprintln!("[anima] pipewire: {}", format_args!($($arg)*));
        }
    };
}

/// Report why a Node global is not a playback stream, if tracing is on.
///
/// Takes the value the caller already looked up rather than the props
/// again, so the reject path costs one match when tracing is off.
///
/// The single most valuable line in this module: an empty result from
/// [`Tracker::node_seen`] otherwise looks exactly like "nothing is
/// playing", which is what kept the key-vs-value bug invisible for as
/// long as it lasted.
fn trace_node_skipped(media_class: Option<&str>) {
    match media_class {
        None => trace!("node skipped: {PROP_MEDIA_CLASS} absent"),
        Some(class) => trace!("node skipped: {PROP_MEDIA_CLASS}={class} is not playback"),
    }
}

/// Report that a playback stream's PID is now known, either because the
/// client was already in the map when the stream arrived or because the
/// client's own announcement resolved it.
fn trace_pid_resolved(node: u32, client: u32, pid: u32) {
    trace!("node {node}: client {client} resolves to pid {pid}");
}

/// Report that a Client global was seen and joined to its PID.
fn trace_client_seen(client: u32, pid: u32) {
    trace!("client {client}: pid {pid}");
}

/// Registry state: the Client→PID map and the audio streams waiting on it.
struct Tracker {
    /// Client registry id → owning PID.
    clients: HashMap<u32, u32>,
    /// Audio stream node registry id → (client id, PID once resolved).
    streams: HashMap<u32, (u32, Option<u32>)>,
}

impl Tracker {
    fn new() -> Self {
        Self {
            clients: HashMap::with_capacity(16),
            streams: HashMap::with_capacity(8),
        }
    }

    /// A Client global appeared. Resolves any streams already waiting on it.
    fn client_seen(&mut self, id: u32, props: &DictRef) -> Vec<AudioEvent> {
        let pairs: Vec<(&str, &str)> = props.iter().collect();
        let find = |key: &str| pairs.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);
        let Some(pid) = prop_pid(find(PROP_CLIENT_PID)) else {
            return Vec::new();
        };
        if self.clients.insert(id, pid).is_some() {
            return Vec::new();
        }
        trace_client_seen(id, pid);
        self.streams
            .iter_mut()
            .filter(|(_, (client, known))| *client == id && known.is_none())
            .map(|(node, (_, known))| {
                *known = Some(pid);
                trace_pid_resolved(*node, id, pid);
                AudioEvent::Started(pid)
            })
            .collect()
    }

    /// A node global appeared: classify it now that its props are readable.
    fn node_seen(&mut self, id: u32, props: &DictRef) -> Vec<AudioEvent> {
        // Only playback streams are of interest. Anything else — sinks,
        // sources, capture streams, devices, links — is ignored, keeping
        // the tracked set small.
        //
        // Note the two-step lookup: `media.class` is the *key*, and its
        // value must match a playback stream. Passing the value as a key
        // silently matches nothing, which is how every stream used to be
        // dropped.
        let media_class = props.get(PROP_MEDIA_CLASS);
        let is_playback = media_class == Some(MEDIA_CLASS_AUDIO_OUT);
        if !is_playback {
            trace_node_skipped(media_class);
            return Vec::new();
        }
        let Some(client) = prop_pid(props.get(PROP_NODE_CLIENT_ID)) else {
            return Vec::new();
        };
        if self.streams.insert(id, (client, None)).is_some() {
            return Vec::new(); // re-announce of a known node
        }
        match self.clients.get(&client) {
            Some(pid) => {
                self.streams.get_mut(&id).unwrap().1 = Some(*pid);
                trace_pid_resolved(id, client, *pid);
                vec![AudioEvent::Started(*pid)]
            }
            // Client not seen yet — resolved when it arrives.
            None => Vec::new(),
        }
    }

    /// A node went away: it is no longer playing.
    fn node_removed(&mut self, id: u32) -> Vec<AudioEvent> {
        let Some((_, pid)) = self.streams.remove(&id) else {
            return Vec::new();
        };
        pid.map(AudioEvent::Stopped).into_iter().collect()
    }

    /// A Client went away: every stream it owned is now stopped.
    fn client_removed(&mut self, id: u32) -> Vec<AudioEvent> {
        self.clients.remove(&id);
        let owned: Vec<u32> = self
            .streams
            .iter()
            .filter(|(_, (client, _))| *client == id)
            .map(|(node, _)| *node)
            .collect();
        owned
            .into_iter()
            .flat_map(|node| self.node_removed(node))
            .collect()
    }

    /// Any registry object disappeared: a node, or a client. A client's
    /// disappearance cascades to the streams it owned.
    fn global_removed(&mut self, id: u32) -> Vec<AudioEvent> {
        let mut out = self.node_removed(id);
        out.extend(self.client_removed(id));
        out
    }
}

/// Subscribe to PipeWire on a dedicated thread and report playback-stream
/// lifecycle events over the channel.
///
/// Reads `ANIMA_AUDIO_TRACE` once, before the listener exists: set it to
/// `1`, `true` or `on` to narrate the classifier boundary on stderr, which
/// is the only way to tell "nothing is playing" from "every node was
/// silently rejected".
///
/// Prints and returns if PipeWire is unavailable (no session bus, daemon
/// not running) — audio boosting is an enhancement, not a precondition for
/// focus tracking. The thread ends once the receiving end is dropped.
pub fn spawn_audio_watcher(tx: Sender<AudioEvent>) -> thread::JoinHandle<()> {
    init_trace_from_env();
    thread::spawn(move || {
        let Ok(main_loop) = MainLoopBox::new(None) else {
            eprintln!("[anima] pipewire: cannot create main loop");
            return;
        };
        let Ok(context) = ContextBox::new(main_loop.loop_(), None) else {
            eprintln!("[anima] pipewire: cannot create context");
            return;
        };
        let core = match connect(&context) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[anima] pipewire: cannot connect to server: {e}");
                return;
            }
        };
        let Ok(registry) = core.get_registry() else {
            eprintln!("[anima] pipewire: server exposed no registry");
            return;
        };

        /* A registry sync tells the server to flush the initial object set
         * before we start receiving change notifications. Without it, the
         * listener can be attached while the server is still walking
         * globals, and depending on timing the initial set arrives with
         * only partial properties — which is how a playback stream that
         * was already running gets misclassified and silently dropped. */
        if let Err(e) = core.sync(0) {
            eprintln!("[anima] pipewire: initial registry sync failed: {e}");
        }
        eprintln!("[anima] pipewire: watching playback streams");

        /* Callbacks are required to be `'static`, and they need both the
         * registry (to reach the callbacks' owner) and mutable state.
         *
         * The registry is borrowed by the listener, and the listener must
         * stay alive for as long as `main_loop.run()` executes. Everything
         * the callbacks touch is held in this one `Rc<RefCell<Tracker>>`,
         * cloned into each callback — `move`-captured, so the closures own
         * their share and nothing is leaked. PipeWire drives all callbacks
         * from this single thread, so a non-atomic refcount is sufficient
         * and no locking happens on the event path. */
        let tracker = Rc::new(RefCell::new(Tracker::new()));

        let tx_global = tx.clone();
        let tx_remove = tx;
        let tracker_global = Rc::clone(&tracker);
        let tracker_remove = tracker;

        let _listener = registry
            .add_listener_local()
            .global(move |global: &GlobalObject<&_>| match global.type_ {
                ObjectType::Client => {
                    let Some(props) = global.props else {
                        return;
                    };
                    for ev in tracker_global.borrow_mut().client_seen(global.id, props) {
                        let _ = tx_global.send(ev);
                    }
                }
                ObjectType::Node => {
                    let Some(props) = global.props else {
                        return;
                    };
                    for ev in tracker_global.borrow_mut().node_seen(global.id, props) {
                        let _ = tx_global.send(ev);
                    }
                }
                _ => {}
            })
            .global_remove(move |id| {
                for ev in tracker_remove.borrow_mut().global_removed(id) {
                    let _ = tx_remove.send(ev);
                }
            })
            .register();

        main_loop.run();
    })
}

/// Connect a context to the server, with application properties so this
/// shows up sensibly in `pw-cli ls Client` and in graph managers.
fn connect<'a>(context: &'a ContextBox<'a>) -> Result<CoreBox<'a>, pipewire::Error> {
    let props = properties! {
        *pipewire::keys::APP_NAME => "anima-hypr-daemon",
        *pipewire::keys::APP_ID => "anima",
    };
    context.connect(Some(props))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::CString;

    /// Build a `DictRef` the way the registry does: NUL-terminated
    /// `key`/`value` pairs in a raw `spa_dict`. Without this the
    /// classification logic cannot be tested without a live server.
    struct RawDict {
        raw: pipewire::spa::sys::spa_dict,
        items: Vec<pipewire::spa::sys::spa_dict_item>,
        // Owned strings, kept alive so the pointers above stay valid.
        _pairs: Vec<(CString, CString)>,
    }

    impl RawDict {
        fn new(pairs: &[(&str, &str)]) -> Self {
            let owned: Vec<(CString, CString)> = pairs
                .iter()
                .map(|(k, v)| (CString::new(*k).unwrap(), CString::new(*v).unwrap()))
                .collect();
            let items = owned
                .iter()
                .map(|(k, v)| pipewire::spa::sys::spa_dict_item {
                    key: k.as_ptr(),
                    value: v.as_ptr(),
                })
                .collect();
            let items = items;
            Self {
                raw: pipewire::spa::sys::spa_dict {
                    flags: 0,
                    n_items: 0,
                    items: std::ptr::null(),
                },
                items,
                _pairs: owned,
            }
            .patched()
        }

        /// Point `raw.items` at the now-stable `items` Vec. Doing this in
        /// two steps is what keeps the pointer valid: `items` has already
        /// moved into the struct, so it will not move again.
        fn patched(mut self) -> Self {
            self.raw.n_items = self.items.len() as u32;
            self.raw.items = self.items.as_ptr();
            self
        }

        fn as_ref(&self) -> &DictRef {
            // Safety: `DictRef` is `#[repr(transparent)]` over `spa_dict`,
            // and `self` outlives every borrow returned here.
            unsafe { &*(&self.raw as *const pipewire::spa::sys::spa_dict as *const DictRef) }
        }
    }

    /// The failure mode that hides every stream: looking up the *value*
    /// (`Stream/Output/Audio`) as if it were the *key* (`media.class`).
    /// `DictRef::get` returns `None` for that, so every node is
    /// discarded and the daemon silently boosts nothing.
    #[test]
    fn playback_streams_are_matched_on_the_media_class_value() {
        let mut t = Tracker::new();

        assert_eq!(
            t.client_seen(1, &RawDict::new(&[(PROP_CLIENT_PID, "4242")]).as_ref()),
            Vec::new(),
        );
        assert_eq!(
            t.node_seen(
                2,
                &RawDict::new(&[
                    (PROP_MEDIA_CLASS, MEDIA_CLASS_AUDIO_OUT),
                    (PROP_NODE_CLIENT_ID, "1"),
                ])
                .as_ref(),
            ),
            vec![AudioEvent::Started(4242)],
        );
    }

    /// A node can arrive before its client; the PID resolves when the
    /// client announcement follows.
    #[test]
    fn a_stream_arriving_before_its_client_is_resolved() {
        let mut t = Tracker::new();

        assert_eq!(
            t.node_seen(
                2,
                &RawDict::new(&[
                    (PROP_MEDIA_CLASS, MEDIA_CLASS_AUDIO_OUT),
                    (PROP_NODE_CLIENT_ID, "1"),
                ])
                .as_ref(),
            ),
            Vec::new(),
            "must hold the stream until the client is known"
        );
        assert_eq!(
            t.client_seen(1, &RawDict::new(&[(PROP_CLIENT_PID, "4242")]).as_ref()),
            vec![AudioEvent::Started(4242)],
        );
    }

    #[test]
    fn non_playback_nodes_are_ignored() {
        let mut t = Tracker::new();

        for class in [
            "Stream/Input/Audio", // capture
            "Audio/Sink",
            "Audio/Source",
            "Video/Source",
            // The key name itself must never match: it is a key, not a value.
            "media.class",
        ] {
            assert_eq!(
                t.node_seen(
                    2,
                    &RawDict::new(&[(PROP_MEDIA_CLASS, class), (PROP_NODE_CLIENT_ID, "1"),])
                        .as_ref(),
                ),
                Vec::new(),
                "{class} must not be treated as a playback stream"
            );
        }
    }

    /// A node missing `media.class` is dropped for the same reason one with
    /// a non-playback value is dropped — empty props out of `node_seen` —
    /// but the two are different failures and must not be conflated. An
    /// absent `media.class` is an early-arriving node with partial
    /// properties; a present-but-wrong value is a genuine non-playback
    /// object (a link, a port, a device). Neither is tracked as a stream:
    /// the client that later announces itself resolves nothing, because
    /// the node was never held pending.
    #[test]
    fn a_missing_media_class_is_ignored_like_a_wrong_value() {
        let mut absent = Tracker::new();
        let mut wrong_value = Tracker::new();

        assert_eq!(
            absent.node_seen(
                2,
                // Partial props: only the client pointer is there.
                &RawDict::new(&[(PROP_NODE_CLIENT_ID, "1")]).as_ref(),
            ),
            Vec::new(),
            "a node without media.class cannot be identified as playback"
        );
        assert_eq!(
            wrong_value.node_seen(
                2,
                &RawDict::new(&[
                    (PROP_MEDIA_CLASS, "Stream/Input/Audio"),
                    (PROP_NODE_CLIENT_ID, "1")
                ])
                .as_ref(),
            ),
            Vec::new(),
        );

        for (label, tracker) in [("absent", &mut absent), ("wrong value", &mut wrong_value)] {
            assert_eq!(
                tracker.client_seen(1, &RawDict::new(&[(PROP_CLIENT_PID, "4242")]).as_ref()),
                Vec::new(),
                "{label}: node 2 must not be buffered as a pending stream"
            );
        }
    }
}
