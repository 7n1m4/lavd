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
//! The registry `global` callback announces a node with a *partial*
//! property set — for a PulseAudio-backed stream the seven keys it carries
//! are `object.serial`, `factory.id`, `client.id`, `client.api`,
//! `application.name`, `node.name` and `media.class` — and
//! `application.process.id` is not among them. The Node object itself does
//! hold it (`pw-cli info <id>` shows it), so the property is reachable
//! through a bound `Node`'s info event, which delivers the complete dict:
//!
//! ```text
//!   global callback ──▶ media.class, client.id   (partial, enough to classify)
//!   registry.bind(Node) ──▶ info event ──▶ application.process.id
//! ```
//!
//! So classification happens from the announcement, and the PID is read
//! from the bound Node's info event, which arrives immediately after
//! binding. One fallback remains, for a node that carries no process id of
//! its own: the `client.id` join against the owning Client's
//! `pipewire.sec.pid`.
//!
//! That join is deliberately last: a PulseAudio-backed client reaches
//! PipeWire through `pipewire-pulse`, so the Client object it creates is
//! the bridge, and `pipewire.sec.pid` there is the bridge's PID rather
//! than the application's. Firefox playing a tab looked exactly like this
//! — node 123 resolving to pid 2098 (`pipewire-pulse`) instead of 217300
//! — and the only reliable cure is the node's own process id, which the
//! bound info event does deliver for exactly that node.
//!
//! PipeWire guarantees no ordering between a stream and the client that
//! owns it, so a stream whose client has not been seen yet is held in a
//! pending list and resolved when the client arrives (and vice versa:
//! a client arriving first resolves streams already waiting on it).
//!
//! The `global` callback delivers the registry announcement plus a
//! complete-enough property set to classify the object; a `bind()` on the
//! registry is what uncovers the rest.
//!
//! ## Bound proxies
//!
//! Every playback stream keeps a bound `Node` proxy alive until the stream
//! disappears, so the info event that carries its PID is not dropped on the
//! floor and the proxy is not destroyed underneath the listener. Nothing
//! else in the graph is bound: a registry may announce hundreds of nodes,
//! and binding them all would create a proxy per object.
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

use pipewire::context::ContextRc;
use pipewire::core::CoreRc;
use pipewire::main_loop::MainLoopRc;
use pipewire::node::Node;
use pipewire::properties::properties;
use pipewire::proxy::Proxy;
use pipewire::proxy::ProxyT;
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

/// Node property naming the protocol the owning client speaks.
///
/// A value other than `protocol-native` means the client reached PipeWire
/// through a bridge, so the Client behind `client.id` is the bridge and its
/// `pipewire.sec.pid` is not the playing application's PID. Present in the
/// registry announcement's partial property set, so a bridge is
/// detectable before the node's own process id arrives.
const PROP_NODE_CLIENT_API: &str = "client.api";

/// Node property naming the owning process directly.
///
/// Not delivered by the registry `global` callback, which announces a node
/// with a partial property set only: it is reachable through a bound
/// `Node`'s info event instead (see [`bind_for_node_props`]).
const PROP_NODE_PROCESS_ID: &str = "application.process.id";

/// Client property holding the owning process's PID.
const PROP_CLIENT_PID: &str = "pipewire.sec.pid";

/// The protocol a client that talks to PipeWire directly speaks.
const CLIENT_API_NATIVE: &str = "protocol-native";

/// The path that produced a playback stream's owner PID.
///
/// Carried through the pipeline purely so tracing can report *how* the PID
/// was found: the daemon only ever sees the resolved PID, which makes a
/// fallback path indistinguishable from the preferred one — exactly the
/// sort of ambiguity that hid the bridge-PID bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PidSource {
    /// The node's own `application.process.id`, read from its bound info.
    Node,
    /// The `client.id` join against `pipewire.sec.pid`. Only trustworthy
    /// for a client that is not a protocol bridge.
    ClientJoin,
}

/// Whether a node's owning client reached PipeWire through a protocol
/// bridge rather than natively.
///
/// `client.api` is absent for a native client and set to the name of the
/// bridge's protocol for a bridged one — on this machine `pipewire-pulse`
/// for every PulseAudio-backed stream, Firefox included. Absence of the
/// property therefore means "native", which is the only case where the
/// `client.id` join can be believed.
fn is_bridge_props(props: &DictRef) -> bool {
    match props.get(PROP_NODE_CLIENT_API) {
        Some(api) => api != CLIENT_API_NATIVE,
        None => false,
    }
}

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
/// node itself named it or because the client join resolved it.
fn trace_pid_resolved(node: u32, client: u32, pid: u32, source: PidSource) {
    match source {
        PidSource::Node => {
            trace!("node {node}: {PROP_NODE_PROCESS_ID}={pid} (own process id)")
        }
        PidSource::ClientJoin => {
            trace!("node {node}: client {client} resolves to pid {pid} (client join)")
        }
    }
}

/// Report that a playback stream's PID was deliberately left unresolved:
/// the only remaining path names a bridge, and a bridge PID is worse than
/// no PID at all.
fn trace_no_pid(node: u32, client: u32, api: &str) {
    trace!(
        "node {node}: no usable pid (client {client} is a {api} bridge; \
         node carries no {PROP_NODE_PROCESS_ID})"
    );
}

/// Report that a Client global was seen and joined to its PID.
fn trace_client_seen(client: u32, pid: u32) {
    trace!("client {client}: pid {pid}");
}

/// A playback stream's bookkeeping.
struct Stream {
    /// The registry id of the Client that owns the stream.
    client: u32,
    /// The stream's owner PID, once a path has found it. `None` while the
    /// node's own process id is still outstanding, or forever if no path
    /// can produce a trustworthy one.
    pid: Option<u32>,
    /// Whether the client behind `client.id` is a protocol bridge. A
    /// PulseAudio-backed stream is reached through `pipewire-pulse`, whose
    /// Client object owns the bridge's PID, so the join is disabled.
    bridged: bool,
    /// Whether the bound Node's info event has already been applied, so a
    /// repeat is not resolved twice.
    info_seen: bool,
}

/// Registry state: the Client→PID map and the playback streams, each with
/// the paths that may still resolve it.
struct Tracker {
    /// Client registry id → owning PID.
    clients: HashMap<u32, u32>,
    /// Audio stream node registry id → its bookkeeping.
    streams: HashMap<u32, Stream>,
    /// Nodes bound for their info event: the proxy is kept alive until the
    /// stream goes away, so its listener cannot be dropped underneath a
    /// pending callback and the server cannot talk to a destroyed proxy.
    /// Also the reason binding is limited to playback streams: a registry
    /// holds every node, link and port, and a proxy apiece would be waste.
    bound: HashMap<u32, BoundNode>,
}

impl Tracker {
    fn new() -> Self {
        Self {
            clients: HashMap::with_capacity(16),
            streams: HashMap::with_capacity(8),
            bound: HashMap::with_capacity(8),
        }
    }

    /// A Client global appeared. Resolves any streams still waiting on it.
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
        let mut out = Vec::new();
        for node in self.streams_owned_by(id) {
            if !self.streams[&node].bridged {
                out.extend(self.set_pid(node, pid, PidSource::ClientJoin));
            }
        }
        out
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

        /* The announcement's property set is partial and never carries
         * `application.process.id`, which is why the PID is not read here:
         * it arrives on the bound node's info event instead, and that path
         * wins. What is left for the announcement is to arm the client
         * join for the non-bridge case and to record the bridge case.
         * `client.api` is present in this partial set, so a bridge is
         * detectable right now. */
        let bridged = is_bridge_props(props);
        match self.streams.get_mut(&id) {
            // Re-announce of a stream that has already been fully handled.
            Some(stream) if stream.pid.is_some() || stream.info_seen => {
                return Vec::new();
            }
            Some(stream) => stream.bridged = bridged,
            None => {
                self.streams.insert(
                    id,
                    Stream {
                        client,
                        pid: None,
                        bridged,
                        info_seen: false,
                    },
                );
            }
        }
        self.try_client_join(id)
    }

    /// A bound Node's info event delivered the complete property set: this
    /// is where the node's own `application.process.id` becomes readable,
    /// and the only reason the daemon reports Firefox's PID rather than
    /// `pipewire-pulse`'s.
    ///
    /// Not idempotent by itself: the server re-emits this event whenever the
    /// node's state or properties change — a live playback stream can be
    /// reported dozens of times. [`set_pid`] absorbs the repeats, so only
    /// the first successful resolution reaches the daemon; the "no usable
    /// pid" trace is likewise reported once per stream, not once per event.
    fn node_info_seen(&mut self, id: u32, props: &DictRef) -> Vec<AudioEvent> {
        let Some(stream) = self.streams.get_mut(&id) else {
            return Vec::new();
        };
        if stream.pid.is_some() {
            return Vec::new(); // already resolved by this path
        }
        match prop_pid(props.get(PROP_NODE_PROCESS_ID)) {
            Some(pid) => self.set_pid(id, pid, PidSource::Node),
            None => {
                /* No process id of its own: fall back to the join, but
                 * only if the client is not a bridge. For a Pulse-backed
                 * stream that join names the bridge, and reporting it
                 * would be worse than reporting nothing — the daemon
                 * reference-counts PIDs, so a bridge PID would leak into
                 * its map and keep boosting `pipewire-pulse` forever. */
                let report = !stream.info_seen;
                stream.info_seen = true;
                let bridged = stream.bridged;
                let client = stream.client;
                if bridged {
                    if report {
                        trace_no_pid(id, client, props.get(PROP_NODE_CLIENT_API).unwrap_or(""));
                    }
                    return Vec::new();
                }
                // Client not seen yet — resolved when it arrives.
                self.try_client_join(id)
            }
        }
    }

    /// Apply the client join if the stream may use it and its client's PID
    /// is already known. A no-op for a bridged stream, a stream that has
    /// already been resolved, or one whose client has not arrived yet.
    fn try_client_join(&mut self, node: u32) -> Vec<AudioEvent> {
        let Some(stream) = self.streams.get(&node) else {
            return Vec::new();
        };
        if stream.pid.is_some() || stream.bridged {
            return Vec::new();
        }
        let Some(pid) = self.clients.get(&stream.client).copied() else {
            return Vec::new(); // Client not seen yet — resolved when it arrives.
        };
        self.set_pid(node, pid, PidSource::ClientJoin)
    }

    /// Record a resolved PID, emitting `Started` only the first time a
    /// stream gets one. The node's own process id outranks the join, so it
    /// is the caller's job to attempt that path first; once a PID has been
    /// reported it is the one the stream is owned by, and it cannot be
    /// revoked — which is exactly why the bridge case must never reach
    /// this function.
    fn set_pid(&mut self, node: u32, pid: u32, source: PidSource) -> Vec<AudioEvent> {
        let Some(stream) = self.streams.get_mut(&node) else {
            return Vec::new();
        };
        if stream.pid.is_some() {
            return Vec::new();
        }
        trace_pid_resolved(node, stream.client, pid, source);
        stream.pid = Some(pid);
        vec![AudioEvent::Started(pid)]
    }

    /// The registry ids of every stream owned by this client.
    fn streams_owned_by(&self, client: u32) -> Vec<u32> {
        self.streams
            .iter()
            .filter(|(_, stream)| stream.client == client && stream.pid.is_none())
            .map(|(node, _)| *node)
            .collect()
    }

    /// Whether this node should now be bound for its info event: it is a
    /// playback stream, and no proxy has been bound for it yet.
    ///
    /// Kept inside the tracker so the re-announcement case is handled by the
    /// same state that records the bind: the registry callback cannot tell
    /// a first announcement of a stream from one of its repeats, and binding
    /// a repeat would create a second proxy and listener for a node that
    /// already has one.
    fn needs_bind(&self, id: u32) -> bool {
        self.streams.contains_key(&id) && !self.bound.contains_key(&id)
    }

    /// Hold the bound proxy of a stream so its info event stays live.
    fn bind(&mut self, id: u32, bound: BoundNode) {
        self.bound.insert(id, bound);
    }

    /// A node went away: it is no longer playing, and its proxy is free.
    fn node_removed(&mut self, id: u32) -> Vec<AudioEvent> {
        self.bound.remove(&id);
        let Some(stream) = self.streams.remove(&id) else {
            return Vec::new();
        };
        stream.pid.map(AudioEvent::Stopped).into_iter().collect()
    }

    /// A Client went away: every stream it owned is now stopped.
    fn client_removed(&mut self, id: u32) -> Vec<AudioEvent> {
        self.clients.remove(&id);
        let owned: Vec<u32> = self
            .streams
            .iter()
            .filter(|(_, stream)| stream.client == id)
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
        let Ok(main_loop) = MainLoopRc::new(None) else {
            eprintln!("[anima] pipewire: cannot create main loop");
            return;
        };
        let Ok(context) = ContextRc::new(&main_loop, None) else {
            eprintln!("[anima] pipewire: cannot create context");
            return;
        };
        let Ok(core) = connect_rc(&context) else {
            eprintln!("[anima] pipewire: cannot connect to server");
            return;
        };
        let Ok(registry) = core.get_registry_rc() else {
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

        /* Callbacks are required to be `'static`, and the `global` one needs
         * the registry in order to bind a playback node's proxy. The shared
         * `Rc` handles are `'static`, so they can be captured directly:
         * the refcounted context, core and registry live as long as any
         * callback holds a clone, and each links its own owner so the
         * underlying object outlives the proxies built on it.
         *
         * The registry itself is only borrowed for the duration of the
         * callback, through a weak reference: taking another strong one
         * would keep it alive past `main_loop.run()`. The listener must
         * stay alive for as long as `main_loop.run()` executes.
         *
         * Everything else the callbacks touch is held in this one
         * `Rc<RefCell<Tracker>>`, cloned into each callback — `move`
         * captured, so the closures own their share and nothing is leaked.
         * PipeWire drives all callbacks from this single thread, so a
         * non-atomic refcount is sufficient and no locking happens on the
         * event path. */
        let tracker = Rc::new(RefCell::new(Tracker::new()));
        let registry_cb = registry.downgrade();

        let tx_global = tx.clone();
        let tx_remove = tx;
        let tx_bind = tx_global.clone();
        let tracker_global = Rc::clone(&tracker);
        let tracker_bind = Rc::clone(&tracker);
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
                    let node_id = global.id;
                    /* The server re-announces a node whenever its
                     * properties change — a live playback stream can be
                     * announced three times in a few seconds — so the
                     * decision to bind is taken inside the tracker and is
                     * not handed to the callback, which cannot tell a first
                     * announcement from a repeat. */
                    let (events, needs_bind) = {
                        let mut t = tracker_global.borrow_mut();
                        let events = t.node_seen(node_id, props);
                        let needs_bind = t.needs_bind(node_id);
                        (events, needs_bind)
                    };
                    for ev in events {
                        let _ = tx_global.send(ev);
                    }
                    if needs_bind {
                        let Some(registry) = registry_cb.upgrade() else {
                            return; // the registry is gone; nothing left to bind
                        };
                        if let Some(bound) =
                            bind_for_node_props(&registry, global, node_id, &tracker_bind, &tx_bind)
                        {
                            tracker_bind.borrow_mut().bind(node_id, bound);
                        }
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

/// Connect a core to the server, with application properties so this
/// shows up sensibly in `pw-cli ls Client` and in graph managers.
///
/// The shared [`CoreRc`] is what the registry listener can capture: a
/// [`CoreBox`] borrows the context and would not outlive the closure it is
/// moved into.
fn connect_rc(context: &ContextRc) -> Result<CoreRc, pipewire::Error> {
    let props = properties! {
        *pipewire::keys::APP_NAME => "anima-hypr-daemon",
        *pipewire::keys::APP_ID => "anima",
    };
    context.connect_rc(Some(props))
}

/// A node bound for its complete property set: the proxy is kept alive
/// until the stream goes away, so the info event it delivers cannot fire
/// into a destroyed proxy, and so the server keeps honouring a bind whose
/// listener is still registered.
struct BoundNode {
    _proxy: Proxy,
    // Unhooks on drop. Both fields must outlive the stream: dropping the
    // proxy alone would tear the bind down from under the listener, and
    // dropping either one early leaves the node silent.
    _listener: pipewire::node::NodeListener,
}

/// Bind a playback stream's node, if the bindings allow it.
///
/// This is the only place a proxy is created, and only for a stream that
/// the announcement has already classified as playback: the registry
/// callback's property set is partial, so the node's own
/// `application.process.id` is only reachable through the bound proxy's
/// info event. The returned value must be kept alive by the caller for as
/// long as the stream exists, or the server may talk to a destroyed proxy
/// and the PID would never arrive.
///
/// A failure to bind is not fatal: the stream simply falls back to the
/// `client.id` join, which is correct for a native PipeWire client.
fn bind_for_node_props(
    registry: &pipewire::registry::Registry,
    global: &GlobalObject<&DictRef>,
    node_id: u32,
    tracker: &Rc<RefCell<Tracker>>,
    tx: &Sender<AudioEvent>,
) -> Option<BoundNode> {
    let node = match registry.bind::<Node, _>(global) {
        Ok(node) => node,
        Err(e) => {
            trace!("node {node_id}: bind failed: {e}");
            return None;
        }
    };

    let tracker_info = Rc::clone(tracker);
    let tx_info = tx.clone();
    let listener = node
        .add_listener_local()
        .info(move |info| {
            if let Some(props) = info.props() {
                for ev in tracker_info.borrow_mut().node_info_seen(node_id, props) {
                    let _ = tx_info.send(ev);
                }
            }
        })
        .register();
    // `NodeListener` is `'static`: its callbacks and the hook are owned,
    // and dropping it unhooks cleanly. So it is stored in the returned
    // `BoundNode` and released with the stream, rather than leaked.
    let proxy = node.upcast();
    Some(BoundNode {
        _proxy: proxy,
        _listener: listener,
    })
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

    /// A PulseAudio-backed client reaches PipeWire through `pipewire-pulse`,
    /// so the Client object behind `client.id` is the bridge. Firefox
    /// playing a tab looked exactly like this and was boosted by the
    /// bridge's PID instead of its own: the node must name its own process.
    #[test]
    fn a_pulse_backed_stream_boosts_the_app_not_the_bridge() {
        let mut t = Tracker::new();

        // pipewire-pulse has its own client in the registry.
        assert_eq!(
            t.client_seen(99, &RawDict::new(&[(PROP_CLIENT_PID, "2098")]).as_ref()),
            Vec::new(),
        );
        /* The announcement carries the bridge marker but no process id, and
         * must resolve nothing: binding has not delivered the node's own
         * `application.process.id` yet. */
        assert_eq!(
            t.node_seen(
                123,
                &RawDict::new(&[
                    (PROP_MEDIA_CLASS, MEDIA_CLASS_AUDIO_OUT),
                    (PROP_NODE_CLIENT_ID, "99"),
                    (PROP_NODE_CLIENT_API, "pipewire-pulse"),
                ])
                .as_ref(),
            ),
            Vec::new(),
            "the bridge's PID must not be reported as the stream's owner"
        );
        // The bound node's info event carries the real process id.
        assert_eq!(
            t.node_info_seen(
                123,
                &RawDict::new(&[
                    (PROP_MEDIA_CLASS, MEDIA_CLASS_AUDIO_OUT),
                    (PROP_NODE_CLIENT_ID, "99"),
                    (PROP_NODE_PROCESS_ID, "217300"),
                ])
                .as_ref(),
            ),
            vec![AudioEvent::Started(217300)],
        );

        // And it stops on the same PID, not the bridge's.
        assert_eq!(t.global_removed(123), vec![AudioEvent::Stopped(217300)],);
    }

    /// With no `application.process.id` and no bridge in between, the
    /// `client.id` join is still correct, so the fallback must keep
    /// working — for a native PipeWire client the join was always right.
    #[test]
    fn the_client_join_still_resolves_a_node_without_a_process_id() {
        let mut t = Tracker::new();

        assert_eq!(
            t.client_seen(99, &RawDict::new(&[(PROP_CLIENT_PID, "2098")]).as_ref()),
            Vec::new(),
        );
        assert_eq!(
            t.node_seen(
                123,
                &RawDict::new(&[
                    (PROP_MEDIA_CLASS, MEDIA_CLASS_AUDIO_OUT),
                    (PROP_NODE_CLIENT_ID, "99"),
                    (PROP_NODE_CLIENT_API, CLIENT_API_NATIVE),
                ])
                .as_ref(),
            ),
            vec![AudioEvent::Started(2098)],
            "a native client's pid is authoritative for its own stream"
        );
    }

    /// The regression this module exists for: a playback node whose
    /// `client.id` points at a bridge, and a Client announcing the bridge's
    /// PID, in the order the live server actually delivers them — the
    /// client first, then the node's announcement, then its bound info.
    ///
    /// Every path except the last must yield nothing. Reporting the bridge
    /// PID would not merely boost the wrong process: the daemon
    /// reference-counts PIDs, so a bridge PID reported and then replaced
    /// would stay in its map forever, because the `Stopped` for this stream
    /// carries the node's own PID instead.
    #[test]
    fn a_bridged_stream_never_yields_the_bridge_pid() {
        let mut t = Tracker::new();
        let node_props = &[
            (PROP_MEDIA_CLASS, MEDIA_CLASS_AUDIO_OUT),
            (PROP_NODE_CLIENT_ID, "99"),
            (PROP_NODE_CLIENT_API, "pipewire-pulse"),
        ];

        // The bridge announces itself before the stream does.
        assert_eq!(
            t.client_seen(99, &RawDict::new(&[(PROP_CLIENT_PID, "2098")]).as_ref()),
            Vec::new(),
        );
        // The announcement alone must not resolve anything.
        assert_eq!(
            t.node_seen(123, &RawDict::new(node_props).as_ref()),
            Vec::new()
        );
        /* An info event that for some reason carries no process id must not
         * fall back to the join: the join is what is wrong here. */
        assert_eq!(
            t.node_info_seen(
                123,
                &RawDict::new(&[
                    (PROP_MEDIA_CLASS, MEDIA_CLASS_AUDIO_OUT),
                    (PROP_NODE_CLIENT_ID, "99"),
                    (PROP_NODE_CLIENT_API, "pipewire-pulse"),
                ])
                .as_ref(),
            ),
            Vec::new(),
            "a bridged stream must be left unresolved, not resolved to the bridge"
        );
        // Nor may a later re-announcement of the same node resolve it.
        assert_eq!(
            t.node_seen(123, &RawDict::new(node_props).as_ref()),
            Vec::new()
        );

        /* The node's own process id is the only thing that resolves it. A
         * second info event (the server may re-emit one when the node's
         * props change) supersedes the empty first one. */
        assert_eq!(
            t.node_info_seen(
                123,
                &RawDict::new(&[
                    (PROP_MEDIA_CLASS, MEDIA_CLASS_AUDIO_OUT),
                    (PROP_NODE_CLIENT_ID, "99"),
                    (PROP_NODE_PROCESS_ID, "217300"),
                ])
                .as_ref(),
            ),
            vec![AudioEvent::Started(217300)],
        );
        // Removal stops exactly the PID that was started.
        assert_eq!(t.global_removed(123), vec![AudioEvent::Stopped(217300)]);
    }
}
