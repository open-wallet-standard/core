//! Process-level security hardening for key material protection.
//!
//! Applies OS primitives to reduce the risk of key material leaking via
//! core dumps, debugger attachment, or memory swapping.
//!
//! Also provides signal-based cleanup hooks so that cached key material
//! is zeroized on SIGTERM, SIGINT, or SIGHUP before the process exits.

use std::sync::{Mutex, OnceLock};

/// Global registry of cleanup functions to run on termination signals.
static CLEANUP_HOOKS: OnceLock<Mutex<Vec<Box<dyn Fn() + Send>>>> = OnceLock::new();

fn hooks() -> &'static Mutex<Vec<Box<dyn Fn() + Send>>> {
    CLEANUP_HOOKS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Register a cleanup function to run when a termination signal is received.
///
/// Typical usage: register a closure that clears a [`KeyCache`](crate::key_cache::KeyCache):
///
/// ```rust,ignore
/// use std::sync::Arc;
/// use lws_signer::key_cache::KeyCache;
/// use lws_signer::process_hardening::register_cleanup;
///
/// let cache = Arc::new(KeyCache::new(std::time::Duration::from_secs(300), 16));
/// register_cleanup({
///     let cache = Arc::clone(&cache);
///     move || cache.clear()
/// });
/// ```
pub fn register_cleanup(f: impl Fn() + Send + 'static) {
    hooks().lock().unwrap().push(Box::new(f));
}

/// Run all registered cleanup hooks. Called by the signal handler thread.
fn run_cleanup_hooks() {
    if let Some(hooks) = CLEANUP_HOOKS.get() {
        if let Ok(hooks) = hooks.lock() {
            for hook in hooks.iter() {
                hook();
            }
        }
    }
}

/// Install signal handlers for SIGTERM, SIGINT, and SIGHUP.
///
/// Spawns a background thread that waits for any of these signals,
/// runs all registered cleanup hooks (zeroizing cached keys), then exits.
/// Must be called at most once; subsequent calls are no-ops.
#[cfg(unix)]
pub fn install_signal_handlers() {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
    use signal_hook::iterator::Signals;
    use std::sync::atomic::{AtomicBool, Ordering};

    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut signals =
        Signals::new([SIGTERM, SIGINT, SIGHUP]).expect("failed to register signal handlers");

    std::thread::Builder::new()
        .name("lws-signal-handler".into())
        .spawn(move || {
            if let Some(sig) = signals.forever().next() {
                eprintln!("lws: received signal {sig}, zeroizing key material and exiting");
                run_cleanup_hooks();
                std::process::exit(128 + sig);
            }
        })
        .expect("failed to spawn signal handler thread");
}

#[cfg(not(unix))]
pub fn install_signal_handlers() {
    // Signal handling is Unix-only; no-op on other platforms.
}

/// Report of which hardening measures succeeded.
#[derive(Debug)]
pub struct HardeningReport {
    pub core_dumps_disabled: bool,
    pub ptrace_disabled: bool,
}

/// Apply all available process hardening measures.
#[cfg(unix)]
pub fn harden_process() -> HardeningReport {
    let core_dumps_disabled = disable_core_dumps();
    let ptrace_disabled = disable_ptrace();

    if !core_dumps_disabled {
        eprintln!("warning: failed to disable core dumps");
    }
    if !ptrace_disabled {
        eprintln!("warning: failed to disable ptrace attachment");
    }

    HardeningReport {
        core_dumps_disabled,
        ptrace_disabled,
    }
}

#[cfg(not(unix))]
pub fn harden_process() -> HardeningReport {
    HardeningReport {
        core_dumps_disabled: false,
        ptrace_disabled: false,
    }
}

#[cfg(target_os = "linux")]
fn disable_core_dumps() -> bool {
    unsafe {
        // PR_SET_DUMPABLE = 4, setting to 0 disables core dumps and ptrace
        let prctl_ok = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0;

        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let rlimit_ok = libc::setrlimit(libc::RLIMIT_CORE, &rlim) == 0;

        prctl_ok && rlimit_ok
    }
}

#[cfg(target_os = "macos")]
fn disable_core_dumps() -> bool {
    unsafe {
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &rlim) == 0
    }
}

#[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
fn disable_core_dumps() -> bool {
    unsafe {
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &rlim) == 0
    }
}

// On Linux, PR_SET_DUMPABLE already prevents ptrace.
#[cfg(target_os = "linux")]
fn disable_ptrace() -> bool {
    true
}

#[cfg(target_os = "macos")]
fn disable_ptrace() -> bool {
    #[cfg(not(debug_assertions))]
    {
        const PT_DENY_ATTACH: libc::c_int = 31;
        unsafe { libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) == 0 }
    }
    #[cfg(debug_assertions)]
    {
        true // Allow debuggers in dev builds
    }
}

#[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
fn disable_ptrace() -> bool {
    false
}

/// Lock a memory region to prevent it from being swapped to disk.
/// Returns false on failure (e.g. ENOMEM from mlock budget).
#[cfg(unix)]
pub fn mlock_slice(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    let ret = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
    if ret != 0 {
        eprintln!(
            "warning: mlock failed ({}), key material may be swapped to disk",
            std::io::Error::last_os_error()
        );
        return false;
    }
    true
}

#[cfg(not(unix))]
pub fn mlock_slice(_ptr: *const u8, _len: usize) -> bool {
    false
}

/// Unlock a previously mlocked memory region.
#[cfg(unix)]
pub fn munlock_slice(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    unsafe {
        libc::munlock(ptr as *const libc::c_void, len);
    }
}

#[cfg(not(unix))]
pub fn munlock_slice(_ptr: *const u8, _len: usize) {}

/// Read an environment variable and remove it from the process environment.
/// Returns the value if it was set. Note: this does not guarantee zeroing
/// of the C runtime's internal environment buffer.
pub fn clear_env_var(name: &str) -> Option<String> {
    let value = std::env::var(name).ok();
    std::env::remove_var(name);
    value
}
