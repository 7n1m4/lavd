use std::path::PathBuf;

/// Resolve the path for the browser tab-pid UNIX socket.
///
/// Prefers `$XDG_RUNTIME_DIR/anima/tab.sock` (per the XDG Base Directory
/// Specification §2) so the daemon works as an unprivileged `systemctl --user`
/// service without touching `/run/`, which is root-owned.
/// Falls back to `~/.cache/anima/tab.sock` when `XDG_RUNTIME_DIR` is unset
/// (non-systemd login shells, older distros).
pub fn anima_tab_sock() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("anima").join("tab.sock");
        }
    }
    #[allow(clippy::disallowed_methods)]
    let cache = std::env::var_os("HOME")
        .map_or_else(|| PathBuf::from("/tmp"), |h| PathBuf::from(h).join(".cache"));
    cache.join("anima").join("tab.sock")
}