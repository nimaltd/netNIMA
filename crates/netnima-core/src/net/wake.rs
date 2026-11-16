//! Waking a session's thread the moment the app gives it something to do.
//!
//! A session's thread waits on its sockets, with a timeout so it can look at
//! its timers now and then. What the app asks of it waits in a queue, and a
//! wait that only times out would keep it there: on Windows, waits time out
//! in steps of about 16 ms, so an answer an engine sends at once would leave
//! up to 16 ms later. So each session has a wake-up socket as well, a UDP
//! socket on the loopback that its thread waits on with its own sockets, and
//! each command put in the queue sends it one byte.
//!
//! A wake-up sent while the thread is busy stays in the socket until its
//! next wait, which then returns at once: none is lost.

use std::io;
use std::net::{Ipv4Addr, UdpSocket};
use std::thread;
use std::time::Duration;

/// A socket to wait on, as the OS names it.
#[cfg(windows)]
pub(crate) type Raw = std::os::windows::io::RawSocket;
#[cfg(unix)]
pub(crate) type Raw = std::os::fd::RawFd;

/// The OS's name for a socket, to wait on it.
#[cfg(windows)]
pub(crate) fn raw(socket: &impl std::os::windows::io::AsRawSocket) -> Raw {
    socket.as_raw_socket()
}

/// The OS's name for a socket, to wait on it.
#[cfg(unix)]
pub(crate) fn raw(socket: &impl std::os::fd::AsRawFd) -> Raw {
    socket.as_raw_fd()
}

/// The app's end: wakes the session's thread.
pub(crate) struct Waker(Option<UdpSocket>);

/// The thread's end, which it waits on with its own sockets.
pub(crate) struct Wake(Option<UdpSocket>);

/// A wake-up pair. Without one, which the OS seldom refuses, the thread
/// still sees what it was asked when its wait times out, only later.
pub(crate) fn pair() -> (Waker, Wake) {
    match sockets() {
        Ok((waker, wake)) => (Waker(Some(waker)), Wake(Some(wake))),
        Err(_) => (Waker(None), Wake(None)),
    }
}

fn sockets() -> io::Result<(UdpSocket, UdpSocket)> {
    let wake = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let waker = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    waker.connect(wake.local_addr()?)?;
    // Only the waker's bytes wake the thread.
    wake.connect(waker.local_addr()?)?;
    wake.set_nonblocking(true)?;
    // Waking never keeps the app waiting.
    waker.set_nonblocking(true)?;
    Ok((waker, wake))
}

impl Waker {
    /// Wakes the thread from its wait, or makes its next wait return at once.
    pub(crate) fn wake(&self) {
        if let Some(socket) = &self.0 {
            // When it cannot be sent, the socket is full of wake-ups already.
            let _ = socket.send(&[1]);
        }
    }
}

impl Wake {
    /// Waits up to `timeout` for one of `sockets` to have something to read,
    /// or to have closed or failed, or for a wake-up. True when a socket
    /// has; a wake-up, which is taken here, gives false, as does the time
    /// running out.
    pub(crate) fn wait(&self, sockets: &[Raw], timeout: Duration) -> io::Result<bool> {
        let wake = self.0.as_ref().map(raw);
        if sockets.is_empty() && wake.is_none() {
            thread::sleep(timeout);
            return Ok(false);
        }
        let (ready, woken) = poll(sockets, wake, timeout)?;
        if woken {
            self.clear();
        }
        Ok(ready)
    }

    /// Takes every wake-up waiting: one wait woken is enough for all the
    /// commands queued before it.
    fn clear(&self) {
        if let Some(socket) = &self.0 {
            let mut buf = [0u8; 64];
            while socket.recv(&mut buf).is_ok() {}
        }
    }
}

/// A timeout in whole milliseconds, rounded up, so a short wait still waits.
fn millis(timeout: Duration) -> i32 {
    timeout.as_micros().div_ceil(1000).min(i32::MAX as u128) as i32
}

/// Waits on the sockets and the wake-up socket together: whether a socket
/// is ready, and whether the wake-up came.
#[cfg(windows)]
fn poll(sockets: &[Raw], wake: Option<Raw>, timeout: Duration) -> io::Result<(bool, bool)> {
    use windows_sys::Win32::Networking::WinSock::{POLLRDNORM, SOCKET_ERROR, WSAPOLLFD, WSAPoll};

    let mut entries: Vec<WSAPOLLFD> = sockets
        .iter()
        .chain(wake.as_ref())
        .map(|&fd| WSAPOLLFD {
            fd: fd as usize,
            // Closes and errors are told in `revents` without being asked for.
            events: POLLRDNORM,
            revents: 0,
        })
        .collect();
    // Safe: the entries live through the call, and the count is theirs.
    let ready = unsafe { WSAPoll(entries.as_mut_ptr(), entries.len() as u32, millis(timeout)) };
    if ready == SOCKET_ERROR {
        return Err(io::Error::last_os_error());
    }
    let (own, woken) = entries.split_at(sockets.len());
    Ok((
        own.iter().any(|entry| entry.revents != 0),
        woken.iter().any(|entry| entry.revents != 0),
    ))
}

/// Waits on the sockets and the wake-up socket together: whether a socket
/// is ready, and whether the wake-up came.
#[cfg(unix)]
fn poll(sockets: &[Raw], wake: Option<Raw>, timeout: Duration) -> io::Result<(bool, bool)> {
    let mut entries: Vec<libc::pollfd> = sockets
        .iter()
        .chain(wake.as_ref())
        .map(|&fd| libc::pollfd {
            fd,
            // Closes and errors are told in `revents` without being asked for.
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    // Safe: the entries live through the call, and the count is theirs.
    let ready = unsafe {
        libc::poll(
            entries.as_mut_ptr(),
            entries.len() as libc::nfds_t,
            millis(timeout),
        )
    };
    if ready < 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::Interrupted {
            Ok((false, false))
        } else {
            Err(error)
        };
    }
    let (own, woken) = entries.split_at(sockets.len());
    Ok((
        own.iter().any(|entry| entry.revents != 0),
        woken.iter().any(|entry| entry.revents != 0),
    ))
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    const LONG: Duration = Duration::from_secs(5);

    fn socket() -> UdpSocket {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        socket
    }

    #[test]
    fn a_wake_up_ends_a_wait_at_once() {
        let (waker, wake) = pair();
        let quiet = socket();
        let thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            waker.wake();
        });
        let start = Instant::now();
        // Woken, not readable.
        assert!(!wake.wait(&[raw(&quiet)], LONG).unwrap());
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "{:?}",
            start.elapsed()
        );
        thread.join().unwrap();
    }

    #[test]
    fn a_wake_up_sent_before_the_wait_is_kept_and_taken_once() {
        let (waker, wake) = pair();
        let quiet = socket();
        waker.wake();
        waker.wake();
        let start = Instant::now();
        assert!(!wake.wait(&[raw(&quiet)], LONG).unwrap());
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "{:?}",
            start.elapsed()
        );
        // Both were taken: the next wait waits its time out.
        let start = Instant::now();
        assert!(
            !wake
                .wait(&[raw(&quiet)], Duration::from_millis(100))
                .unwrap()
        );
        assert!(
            start.elapsed() >= Duration::from_millis(50),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn a_socket_with_data_is_ready() {
        let (_waker, wake) = pair();
        let quiet = socket();
        let busy = socket();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"hi", busy.local_addr().unwrap()).unwrap();
        let start = Instant::now();
        assert!(wake.wait(&[raw(&quiet), raw(&busy)], LONG).unwrap());
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn a_wait_without_a_wake_up_socket_still_waits() {
        let wake = Wake(None);
        let quiet = socket();
        let start = Instant::now();
        assert!(
            !wake
                .wait(&[raw(&quiet)], Duration::from_millis(50))
                .unwrap()
        );
        assert!(start.elapsed() >= Duration::from_millis(40));
        Waker(None).wake();
    }
}
