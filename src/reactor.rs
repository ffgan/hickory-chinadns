//! One io_uring for the DNS data plane.
//!
//! The ring is single-issuer with cooperative, deferred task work, so submit
//! and completion share one syscall. Client UDP uses multishot `recvmsg` into a
//! provided buffer ring (the io_uring form of a standing `recvmmsg`). Upstream
//! TCP connections are pooled, opened with `TCP_FASTOPEN_CONNECT` and
//! `IP_BIND_ADDRESS_NO_PORT`, and read with multishot `recv`. Upstream UDP
//! shares one socket per family instead of binding a new one per query.

use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::RawFd;
use std::sync::mpsc::{SyncSender, TryRecvError, sync_channel};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use io_uring::types::Timespec;
use io_uring::{IoUring, cqueue, opcode, squeue, types};

use crate::config::{Error, Transport};

const BGID: u16 = 1;
const BUFS: usize = 32;
const BUF_LEN: usize = 8192;
const SLOTS: u32 = 128;
const TCP_POOL: usize = 4;

const KIND_WAKE: u64 = 1;
const KIND_TICK: u64 = 2;
const KIND_UDP_RECV: u64 = 3;
const KIND_UDP_SEND: u64 = 4;
const KIND_CONNECT: u64 = 5;
const KIND_UP_SEND: u64 = 6;
const KIND_UP_RECV: u64 = 7;
const KIND_UP_UDP_RECV: u64 = 8;
const KIND_UP_UDP_SEND: u64 = 9;

fn pack(kind: u64, id: u64) -> u64 {
    (kind << 56) | (id & ((1 << 56) - 1))
}

fn unpack(user: u64) -> (u64, u64) {
    (user >> 56, user & ((1 << 56) - 1))
}

#[derive(Clone)]
pub struct Handle {
    tx: SyncSender<Cmd>,
    wake_fd: RawFd,
}

pub struct InboundUdp {
    pub slot: u32,
    pub peer: SocketAddr,
    pub bytes: Vec<u8>,
}

enum Cmd {
    Dispatch(tokio::sync::mpsc::UnboundedSender<InboundUdp>),
    ListenUdp(RawFd),
    Exchange {
        transport: Transport,
        addr: SocketAddr,
        packet: Vec<u8>,
        limit: Duration,
        reply: tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>,
    },
    UdpReply {
        slot: u32,
        peer: SocketAddr,
        packet: Vec<u8>,
    },
}

static REACTOR: OnceLock<Option<Handle>> = OnceLock::new();

pub fn handle() -> Option<Handle> {
    REACTOR.get_or_init(spawn).clone()
}

fn spawn() -> Option<Handle> {
    let (tx, rx) = sync_channel(1024);
    let wake_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if wake_fd < 0 {
        tracing::warn!("eventfd failed; using the tokio sockets");
        return None;
    }
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let wake = wake_fd;
    if let Err(err) = std::thread::Builder::new()
        .name("io-uring".into())
        .spawn(move || match Reactor::new(rx, wake) {
            Ok(mut reactor) => {
                let _ = ready_tx.send(None);
                reactor.run();
            }
            Err(err) => {
                let _ = ready_tx.send(Some(err));
            }
        })
    {
        tracing::warn!(%err, "io_uring thread failed to start");
        unsafe { libc::close(wake_fd) };
        return None;
    }
    match ready_rx.recv() {
        Ok(None) => Some(Handle { tx, wake_fd }),
        Ok(Some(err)) => {
            tracing::warn!(%err, "io_uring setup failed; queries use the tokio path");
            None
        }
        Err(_) => None,
    }
}

impl Handle {
    fn send(&self, cmd: Cmd) {
        if self.tx.try_send(cmd).is_ok() {
            wake(self.wake_fd);
        }
    }

    pub fn set_dispatch(&self, tx: tokio::sync::mpsc::UnboundedSender<InboundUdp>) {
        self.send(Cmd::Dispatch(tx));
    }

    pub fn listen_udp(&self, fd: RawFd) {
        self.send(Cmd::ListenUdp(fd));
    }

    pub fn udp_reply(&self, slot: u32, peer: SocketAddr, packet: Vec<u8>) {
        self.send(Cmd::UdpReply { slot, peer, packet });
    }

    pub async fn exchange(
        &self,
        transport: Transport,
        addr: SocketAddr,
        packet: &[u8],
        limit: Duration,
    ) -> Result<Vec<u8>, Error> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        if self
            .tx
            .try_send(Cmd::Exchange {
                transport,
                addr,
                packet: packet.to_vec(),
                limit,
                reply,
            })
            .is_err()
        {
            return Err(Error::msg("io_uring queue full"));
        }
        wake(self.wake_fd);
        rx.await
            .map_err(|_| Error::msg("io_uring dropped the query"))?
            .map_err(Error::msg)
    }
}

fn wake(fd: RawFd) {
    let one = 1u64;
    unsafe {
        libc::write(fd, (&raw const one).cast(), 8);
    }
}

struct Reactor {
    ring: IoUring,
    rx: std::sync::mpsc::Receiver<Cmd>,
    wake_fd: RawFd,
    wake_buf: [u8; 8],
    wake_armed: bool,
    tick: Timespec,
    tick_armed: bool,
    bufs: BufPool,
    free_slots: Vec<u32>,
    next_id: u64,
    dispatch: Option<tokio::sync::mpsc::UnboundedSender<InboundUdp>>,
    listeners: HashMap<u64, Box<UdpSock>>,
    slot_listener: HashMap<u32, u64>,
    sends: HashMap<u64, Box<PendingSend>>,
    udp_up: HashMap<i32, Box<UdpSock>>,
    udp_waiters: HashMap<u16, UdpWaiter>,
    next_dns_id: u16,
    conns: HashMap<u64, Box<TcpConn>>,
}

struct UdpSock {
    id: u64,
    slot: u32,
    hdr: libc::msghdr,
    armed: bool,
}

struct PendingSend {
    buf: Vec<u8>,
    storage: libc::sockaddr_storage,
    addr_len: libc::socklen_t,
}

struct UdpWaiter {
    reply: tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>,
    deadline: Instant,
}

struct Job {
    packet: Vec<u8>,
    reply: tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>,
    limit: Duration,
    started: Instant,
}

struct TcpConn {
    id: u64,
    slot: u32,
    addr: SocketAddr,
    storage: libc::sockaddr_storage,
    addr_len: libc::socklen_t,
    queue: VecDeque<Job>,
    sending: Option<Job>,
    sent: Option<Job>,
    tx: Option<Vec<u8>>,
    tx_off: usize,
    rx: Vec<u8>,
    ops: u32,
    recv_live: bool,
    connecting: bool,
    closing: bool,
}

impl Reactor {
    fn new(rx: std::sync::mpsc::Receiver<Cmd>, wake_fd: RawFd) -> std::io::Result<Self> {
        let ring = match IoUring::builder()
            .setup_cqsize(1024)
            .setup_single_issuer()
            .setup_coop_taskrun()
            .setup_defer_taskrun()
            .build(256)
        {
            Ok(ring) => ring,
            Err(err) => {
                tracing::debug!(%err, "defer-taskrun ring unavailable");
                IoUring::builder().setup_cqsize(1024).build(256)?
            }
        };
        ring.submitter().register_files_sparse(SLOTS)?;
        let bufs = BufPool::register(&ring)?;
        tracing::info!(
            "io_uring ready: single issuer, multishot recv, provided buffers, tcp fastopen"
        );
        Ok(Self {
            ring,
            rx,
            wake_fd,
            wake_buf: [0; 8],
            wake_armed: false,
            tick: Timespec::new().sec(1),
            tick_armed: false,
            bufs,
            free_slots: (0..SLOTS).rev().collect(),
            next_id: 1,
            dispatch: None,
            listeners: HashMap::new(),
            slot_listener: HashMap::new(),
            sends: HashMap::new(),
            udp_up: HashMap::new(),
            udp_waiters: HashMap::new(),
            next_dns_id: 1,
            conns: HashMap::new(),
        })
    }

    fn run(&mut self) {
        loop {
            self.drain_cmds();
            self.arm_wake();
            self.arm_tick();
            self.bufs.advance();
            if let Err(err) = self.ring.submit_and_wait(1) {
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                tracing::error!(%err, "io_uring submit failed");
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            self.reap();
        }
    }

    fn drain_cmds(&mut self) {
        loop {
            match self.rx.try_recv() {
                Ok(cmd) => self.command(cmd),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }
    }

    fn command(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Dispatch(tx) => self.dispatch = Some(tx),
            Cmd::ListenUdp(fd) => self.attach_listener(fd),
            Cmd::Exchange {
                transport,
                addr,
                packet,
                limit,
                reply,
            } => self.exchange(transport, addr, packet, limit, reply),
            Cmd::UdpReply { slot, peer, packet } => self.send_udp(slot, peer, packet, None),
        }
    }

    fn attach_listener(&mut self, fd: RawFd) {
        tune_udp(fd);
        let Ok(slot) = self.install_fd(fd) else {
            tracing::warn!("udp listener did not fit in the fixed file table");
            return;
        };
        let id = self.alloc_id();
        let sock = Box::new(UdpSock {
            id,
            slot,
            hdr: recv_hdr(),
            armed: false,
        });
        self.slot_listener.insert(slot, id);
        self.listeners.insert(id, sock);
        self.arm_udp_recv(id, KIND_UDP_RECV);
    }

    fn exchange(
        &mut self,
        transport: Transport,
        addr: SocketAddr,
        packet: Vec<u8>,
        limit: Duration,
        reply: tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>,
    ) {
        let job = Job {
            packet,
            reply,
            limit,
            started: Instant::now(),
        };
        match transport {
            Transport::Tcp => self.enqueue_tcp(addr, job),
            Transport::Udp => self.enqueue_udp(addr, job),
        }
    }

    fn enqueue_udp(&mut self, addr: SocketAddr, mut job: Job) {
        let family = if addr.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        if !self.udp_up.contains_key(&family) {
            let Ok(fd) = udp_socket(addr.is_ipv4()) else {
                let _ = job.reply.send(Err("udp socket failed".to_string()));
                return;
            };
            let Ok(slot) = self.install_fd(fd) else {
                let _ = job.reply.send(Err("udp socket slot failed".to_string()));
                return;
            };
            let id = self.alloc_id();
            self.udp_up.insert(
                family,
                Box::new(UdpSock {
                    id,
                    slot,
                    hdr: recv_hdr(),
                    armed: false,
                }),
            );
            self.arm_udp_recv(id, KIND_UP_UDP_RECV);
        }
        let slot = self.udp_up[&family].slot;
        let dns_id = self.alloc_dns_id();
        if job.packet.len() >= 2 {
            job.packet[..2].copy_from_slice(&dns_id.to_be_bytes());
        }
        self.udp_waiters.insert(
            dns_id,
            UdpWaiter {
                reply: job.reply,
                deadline: Instant::now() + job.limit,
            },
        );
        self.send_udp(slot, addr, job.packet, Some(dns_id));
    }

    fn enqueue_tcp(&mut self, addr: SocketAddr, job: Job) {
        let reusable = self.conns.values().find(|conn| {
            conn.addr == addr
                && !conn.closing
                && !conn.connecting
                && conn.sending.is_none()
                && conn.sent.is_none()
                && conn.queue.is_empty()
        });
        if let Some(id) = reusable.map(|conn| conn.id) {
            self.conns.get_mut(&id).unwrap().queue.push_back(job);
            self.flush_tcp(id);
            return;
        }
        let active = self
            .conns
            .values()
            .filter(|conn| conn.addr == addr && !conn.closing)
            .count();
        if active < TCP_POOL {
            self.open_tcp(addr, job);
            return;
        }
        let id = self
            .conns
            .values()
            .filter(|conn| conn.addr == addr && !conn.closing)
            .min_by_key(|conn| conn.queue.len())
            .map(|conn| conn.id);
        if let Some(id) = id {
            self.conns.get_mut(&id).unwrap().queue.push_back(job);
            self.flush_tcp(id);
        } else {
            let _ = job.reply.send(Err("no tcp connection".to_string()));
        }
    }

    fn open_tcp(&mut self, addr: SocketAddr, job: Job) {
        let fd = match tcp_socket(addr) {
            Ok(fd) => fd,
            Err(err) => {
                let _ = job.reply.send(Err(err.to_string()));
                return;
            }
        };
        let slot = match self.install_fd(fd) {
            Ok(slot) => slot,
            Err(err) => {
                let _ = job.reply.send(Err(err.to_string()));
                return;
            }
        };
        let id = self.alloc_id();
        let (storage, addr_len) = store_addr(addr);
        let mut conn = Box::new(TcpConn {
            id,
            slot,
            addr,
            storage,
            addr_len,
            queue: VecDeque::new(),
            sending: None,
            sent: None,
            tx: None,
            tx_off: 0,
            rx: Vec::new(),
            ops: 0,
            recv_live: false,
            connecting: true,
            closing: false,
        });
        conn.queue.push_back(job);
        let addr_ptr = (&raw const conn.storage).cast();
        let addr_len = conn.addr_len;
        self.conns.insert(id, conn);
        self.begin_op(id);
        let entry = opcode::Connect::new(types::Fixed(slot), addr_ptr, addr_len)
            .build()
            .user_data(pack(KIND_CONNECT, id))
            .flags(squeue::Flags::ASYNC);
        self.push(entry);
    }

    fn flush_tcp(&mut self, id: u64) {
        let Some(conn) = self.conns.get_mut(&id) else {
            return;
        };
        if conn.closing || conn.connecting || conn.sending.is_some() || conn.sent.is_some() {
            return;
        }
        let Some(mut job) = conn.queue.pop_front() else {
            return;
        };
        if job.reply.is_closed() {
            return self.flush_tcp(id);
        }
        let mut frame = Vec::with_capacity(2 + job.packet.len());
        frame.extend_from_slice(&(job.packet.len() as u16).to_be_bytes());
        frame.append(&mut job.packet);
        let slot = conn.slot;
        let ptr = frame.as_ptr();
        let len = frame.len() as u32;
        conn.tx = Some(frame);
        conn.tx_off = 0;
        conn.sending = Some(job);
        self.begin_op(id);
        let entry = opcode::Send::new(types::Fixed(slot), ptr, len)
            .flags(libc::MSG_NOSIGNAL)
            .build()
            .user_data(pack(KIND_UP_SEND, id));
        self.push(entry);
    }

    fn arm_tcp_recv(&mut self, id: u64) {
        let Some(conn) = self.conns.get_mut(&id) else {
            return;
        };
        if conn.recv_live || conn.closing {
            return;
        }
        conn.recv_live = true;
        let slot = conn.slot;
        self.begin_op(id);
        let entry = opcode::RecvMulti::new(types::Fixed(slot), BGID)
            .build()
            .user_data(pack(KIND_UP_RECV, id));
        self.push(entry);
    }

    fn send_udp(
        &mut self,
        slot: u32,
        peer: SocketAddr,
        packet: Vec<u8>,
        dns_id: Option<u16>,
    ) {
        let (storage, addr_len) = store_addr(peer);
        let id = self.alloc_id();
        let pending = Box::new(PendingSend {
            buf: packet,
            storage,
            addr_len,
        });
        let ptr = pending.buf.as_ptr();
        let len = pending.buf.len() as u32;
        let addr_ptr = (&raw const pending.storage).cast();
        let addr_len = pending.addr_len;
        let kind = if dns_id.is_some() {
            KIND_UP_UDP_SEND
        } else {
            KIND_UDP_SEND
        };
        self.sends.insert(id, pending);
        let entry = opcode::Send::new(types::Fixed(slot), ptr, len)
            .dest_addr(addr_ptr)
            .dest_addr_len(addr_len)
            .build()
            .user_data(pack(kind, id));
        let _ = dns_id;
        self.push(entry);
    }

    fn arm_udp_recv(&mut self, id: u64, kind: u64) {
        let sock = if kind == KIND_UDP_RECV {
            self.listeners.get_mut(&id)
        } else {
            self.udp_up.values_mut().find(|sock| sock.id == id)
        };
        let Some(sock) = sock else {
            return;
        };
        if sock.armed {
            return;
        }
        sock.armed = true;
        let slot = sock.slot;
        let hdr = (&raw const sock.hdr).cast();
        let entry = opcode::RecvMsgMulti::new(types::Fixed(slot), hdr, BGID)
            .build()
            .user_data(pack(kind, id));
        self.push(entry);
    }

    fn arm_wake(&mut self) {
        if self.wake_armed {
            return;
        }
        self.wake_armed = true;
        let ptr = self.wake_buf.as_mut_ptr();
        let entry = opcode::Read::new(types::Fd(self.wake_fd), ptr, 8)
            .build()
            .user_data(pack(KIND_WAKE, 0));
        self.push(entry);
    }

    fn arm_tick(&mut self) {
        if self.tick_armed {
            return;
        }
        self.tick_armed = true;
        let ts = (&raw const self.tick).cast();
        let entry = opcode::Timeout::new(ts)
            .count(u32::MAX)
            .flags(types::TimeoutFlags::MULTISHOT)
            .build()
            .user_data(pack(KIND_TICK, 0));
        self.push(entry);
    }

    fn reap(&mut self) {
        let mut batch = Vec::new();
        {
            let cq = self.ring.completion();
            for cqe in cq {
                batch.push((cqe.user_data(), cqe.result(), cqe.flags()));
            }
        }
        for (user, res, flags) in batch {
            self.complete(user, res, flags);
        }
    }

    fn complete(&mut self, user: u64, res: i32, flags: u32) {
        let (kind, id) = unpack(user);
        let bid = cqueue::buffer_select(flags);
        if let Some(bid) = bid {
            self.note_buffer(bid);
        }
        match kind {
            KIND_WAKE => self.wake_armed = false,
            KIND_TICK => {
                if !cqueue::more(flags) {
                    self.tick_armed = false;
                }
                self.sweep();
            }
            KIND_UDP_RECV => self.on_udp_recv(id, res, flags, bid, true),
            KIND_UP_UDP_RECV => self.on_udp_recv(id, res, flags, bid, false),
            KIND_UDP_SEND | KIND_UP_UDP_SEND => {
                if res < 0 {
                    tracing::debug!(res, "udp send failed");
                }
                self.sends.remove(&id);
            }
            KIND_CONNECT => self.on_connect(id, res),
            KIND_UP_SEND => self.on_tcp_send(id, res),
            KIND_UP_RECV => self.on_tcp_recv(id, res, flags, bid),
            _ => {}
        }
    }

    fn note_buffer(&mut self, bid: u16) {
        if (bid as usize) < BUFS {
            self.bufs.recycle(bid);
        }
    }

    fn on_udp_recv(&mut self, id: u64, res: i32, flags: u32, bid: Option<u16>, listener: bool) {
        let armed_again = cqueue::more(flags);
        if res < 0 {
            if !armed_again {
                self.mark_udp_unarmed(id, listener);
                if res != -libc::ECANCELED && res != -libc::ENOBUFS {
                    tracing::debug!(res, listener, "udp recv ended");
                }
                self.arm_udp_recv(id, if listener { KIND_UDP_RECV } else { KIND_UP_UDP_RECV });
            }
            return;
        }
        if let Some(bid) = bid {
            self.consume_udp(id, bid, listener);
        }
        if !armed_again {
            self.mark_udp_unarmed(id, listener);
            self.arm_udp_recv(id, if listener { KIND_UDP_RECV } else { KIND_UP_UDP_RECV });
        }
    }

    fn consume_udp(&mut self, id: u64, bid: u16, listener: bool) {
        let hdr = if listener {
            self.listeners.get(&id).map(|sock| sock.hdr)
        } else {
            self.udp_up
                .values()
                .find(|sock| sock.id == id)
                .map(|sock| sock.hdr)
        };
        let Some(hdr) = hdr else {
            return;
        };
        let bytes = self.bufs.bytes(bid);
        let Ok(out) = types::RecvMsgOut::parse(bytes, &hdr) else {
            return;
        };
        let payload = out.payload_data().to_vec();
        if listener {
            let Some(peer) = peer_from(out.name_data()) else {
                return;
            };
            let Some(sock) = self.listeners.get(&id) else {
                return;
            };
            let slot = sock.slot;
            if let Some(tx) = &self.dispatch {
                let _ = tx.send(InboundUdp {
                    slot,
                    peer,
                    bytes: payload,
                });
            }
        } else if payload.len() >= 2 {
            let dns_id = u16::from_be_bytes([payload[0], payload[1]]);
            if let Some(waiter) = self.udp_waiters.remove(&dns_id) {
                let _ = waiter.reply.send(Ok(payload));
            }
        }
    }

    fn mark_udp_unarmed(&mut self, id: u64, listener: bool) {
        if listener {
            if let Some(sock) = self.listeners.get_mut(&id) {
                sock.armed = false;
            }
        } else if let Some(sock) = self.udp_up.values_mut().find(|sock| sock.id == id) {
            sock.armed = false;
        }
    }

    fn on_connect(&mut self, id: u64, res: i32) {
        self.end_op(id);
        let Some(conn) = self.conns.get_mut(&id) else {
            return;
        };
        conn.connecting = false;
        if res < 0 {
            let err = std::io::Error::from_raw_os_error(-res).to_string();
            self.fail_conn(id, &err);
            return;
        }
        self.arm_tcp_recv(id);
        self.flush_tcp(id);
    }

    fn on_tcp_send(&mut self, id: u64, res: i32) {
        self.end_op(id);
        let Some(conn) = self.conns.get_mut(&id) else {
            return;
        };
        if res < 0 {
            let err = std::io::Error::from_raw_os_error(-res).to_string();
            self.fail_conn(id, &err);
            return;
        }
        let sent = res as usize;
        let off = conn.tx_off + sent;
        let total = conn.tx.as_ref().map(Vec::len).unwrap_or(0);
        if off < total {
            conn.tx_off = off;
            let slot = conn.slot;
            let ptr = unsafe { conn.tx.as_ref().unwrap().as_ptr().add(off) };
            let len = (total - off) as u32;
            self.begin_op(id);
            let entry = opcode::Send::new(types::Fixed(slot), ptr, len)
                .flags(libc::MSG_NOSIGNAL)
                .build()
                .user_data(pack(KIND_UP_SEND, id));
            self.push(entry);
            return;
        }
        let job = conn.sending.take();
        conn.tx = None;
        conn.tx_off = 0;
        if let Some(job) = job {
            conn.sent = Some(job);
        }
        self.pump_tcp(id);
    }

    fn on_tcp_recv(&mut self, id: u64, res: i32, flags: u32, bid: Option<u16>) {
        let more = cqueue::more(flags);
        if res < 0 {
            if let Some(conn) = self.conns.get_mut(&id) {
                if !more {
                    conn.recv_live = false;
                }
            }
            if !more {
                self.end_op(id);
            }
            if res == -libc::ENOBUFS {
                self.arm_tcp_recv(id);
                return;
            }
            if res != -libc::ECANCELED {
                self.fail_conn(id, &std::io::Error::from_raw_os_error(-res).to_string());
            } else {
                self.maybe_destroy(id);
            }
            return;
        }
        if res == 0 {
            if let Some(conn) = self.conns.get_mut(&id) {
                conn.recv_live = false;
            }
            if !more {
                self.end_op(id);
            }
            self.pump_tcp(id);
            self.retire_conn(id, "upstream closed");
            return;
        }
        if let Some(bid) = bid {
            let chunk = self.bufs.bytes(bid)[..res as usize].to_vec();
            if let Some(conn) = self.conns.get_mut(&id) {
                conn.rx.extend_from_slice(&chunk);
            }
        }
        if !more {
            if let Some(conn) = self.conns.get_mut(&id) {
                conn.recv_live = false;
            }
            self.end_op(id);
            self.arm_tcp_recv(id);
        }
        self.pump_tcp(id);
    }

    fn pump_tcp(&mut self, id: u64) {
        let Some(conn) = self.conns.get_mut(&id) else {
            return;
        };
        if conn.sent.is_none() {
            return;
        }
        let Some(frame) = take_frame(&mut conn.rx) else {
            return;
        };
        let job = conn.sent.take();
        if let Some(job) = job {
            let _ = job.reply.send(Ok(frame));
        }
        self.flush_tcp(id);
    }

    fn retire_conn(&mut self, id: u64, err: &str) {
        let Some(conn) = self.conns.get_mut(&id) else {
            return;
        };
        let addr = conn.addr;
        let leftover: Vec<Job> = conn.queue.drain(..).collect();
        self.fail_conn(id, err);
        for job in leftover {
            if !job.reply.is_closed() {
                self.enqueue_tcp(addr, job);
            }
        }
    }

    fn fail_conn(&mut self, id: u64, err: &str) {
        let Some(mut conn) = self.conns.remove(&id) else {
            return;
        };
        conn.closing = true;
        for job in conn.queue.drain(..) {
            let _ = job.reply.send(Err(err.to_string()));
        }
        if let Some(job) = conn.sending.take() {
            let _ = job.reply.send(Err(err.to_string()));
        }
        if let Some(job) = conn.sent.take() {
            let _ = job.reply.send(Err(err.to_string()));
        }
        if conn.recv_live {
            let entry = opcode::AsyncCancel::new(pack(KIND_UP_RECV, id))
                .build()
                .user_data(pack(KIND_WAKE, id));
            self.push(entry);
        }
        if conn.ops == 0 && !conn.recv_live {
            self.release_slot(conn.slot);
        } else {
            conn.closing = true;
            self.conns.insert(id, conn);
        }
    }

    fn maybe_destroy(&mut self, id: u64) {
        let Some(conn) = self.conns.get(&id) else {
            return;
        };
        if conn.closing && conn.ops == 0 && !conn.recv_live {
            let slot = conn.slot;
            self.conns.remove(&id);
            self.release_slot(slot);
        }
    }

    fn begin_op(&mut self, id: u64) {
        if let Some(conn) = self.conns.get_mut(&id) {
            conn.ops += 1;
        }
    }

    fn end_op(&mut self, id: u64) {
        if let Some(conn) = self.conns.get_mut(&id) {
            conn.ops = conn.ops.saturating_sub(1);
        }
        self.maybe_destroy(id);
    }

    fn sweep(&mut self) {
        let now = Instant::now();
        let stale: Vec<u64> = self
            .conns
            .values()
            .filter(|conn| {
                conn.sending
                    .as_ref()
                    .or(conn.sent.as_ref())
                    .or(conn.queue.front())
                    .is_some_and(|job| now.duration_since(job.started) > job.limit)
            })
            .map(|conn| conn.id)
            .collect();
        for id in stale {
            self.fail_conn(id, "upstream timed out");
        }
        let expired: Vec<u16> = self
            .udp_waiters
            .iter()
            .filter(|(_, waiter)| now >= waiter.deadline)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            if let Some(waiter) = self.udp_waiters.remove(&id) {
                let _ = waiter.reply.send(Err("upstream timed out".to_string()));
            }
        }
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        id
    }

    fn alloc_dns_id(&mut self) -> u16 {
        loop {
            self.next_dns_id = self.next_dns_id.wrapping_add(1);
            if self.next_dns_id != 0 && !self.udp_waiters.contains_key(&self.next_dns_id) {
                return self.next_dns_id;
            }
        }
    }

    fn install_fd(&mut self, fd: RawFd) -> std::io::Result<u32> {
        let Some(slot) = self.free_slots.pop() else {
            unsafe { libc::close(fd) };
            return Err(std::io::Error::other("fixed file table full"));
        };
        match self.ring.submitter().register_files_update(slot, &[fd]) {
            Ok(_) => {
                unsafe { libc::close(fd) };
                Ok(slot)
            }
            Err(err) => {
                unsafe { libc::close(fd) };
                self.free_slots.push(slot);
                Err(err)
            }
        }
    }

    fn release_slot(&mut self, slot: u32) {
        let _ = self.ring.submitter().register_files_update(slot, &[-1]);
        self.free_slots.push(slot);
    }

    fn push(&mut self, entry: squeue::Entry) {
        for _ in 0..8 {
            let full = {
                let mut sq = self.ring.submission();
                unsafe { sq.push(&entry).is_err() }
            };
            if !full {
                return;
            }
            let _ = self.ring.submit();
        }
        tracing::warn!("io_uring submission queue stayed full");
    }
}

#[repr(C)]
struct ProvidedBuf {
    addr: u64,
    len: u32,
    bid: u16,
    resv: u16,
}

struct BufPool {
    ring_ptr: *mut ProvidedBuf,
    ring_layout: std::alloc::Layout,
    data: Vec<u8>,
    mask: u16,
    tail: u16,
    pending: u16,
}

unsafe impl Send for BufPool {}

impl BufPool {
    fn register(ring: &IoUring) -> std::io::Result<Self> {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as usize;
        let bytes = page.max(BUFS * std::mem::size_of::<ProvidedBuf>());
        let layout = std::alloc::Layout::from_size_align(bytes, page)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
        let ring_ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        if ring_ptr.is_null() {
            return Err(std::io::Error::other("buffer ring allocation failed"));
        }
        let mut pool = Self {
            ring_ptr: ring_ptr.cast(),
            ring_layout: layout,
            data: vec![0; BUFS * BUF_LEN],
            mask: (BUFS - 1) as u16,
            tail: 0,
            pending: 0,
        };
        for bid in 0..BUFS as u16 {
            pool.recycle(bid);
        }
        pool.advance();
        unsafe {
            ring.submitter().register_buf_ring_with_flags(
                pool.ring_ptr as u64,
                BUFS as u16,
                BGID,
                0,
            )?;
        }
        Ok(pool)
    }

    fn recycle(&mut self, bid: u16) {
        let index = self.tail.wrapping_add(self.pending) & self.mask;
        let addr = self.data.as_mut_ptr() as u64 + bid as u64 * BUF_LEN as u64;
        unsafe {
            let buf = self.ring_ptr.add(index as usize);
            (*buf).addr = addr;
            (*buf).len = BUF_LEN as u32;
            (*buf).bid = bid;
        }
        self.pending = self.pending.wrapping_add(1);
    }

    fn advance(&mut self) {
        if self.pending == 0 {
            return;
        }
        let new_tail = self.tail.wrapping_add(self.pending);
        self.pending = 0;
        self.tail = new_tail;
        unsafe {
            let tail = (self.ring_ptr as *mut u8).add(14) as *mut std::sync::atomic::AtomicU16;
            (*tail).store(new_tail, std::sync::atomic::Ordering::Release);
        }
    }

    fn bytes(&self, bid: u16) -> &[u8] {
        let start = bid as usize * BUF_LEN;
        &self.data[start..start + BUF_LEN]
    }
}

impl Drop for BufPool {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.ring_ptr.cast(), self.ring_layout) };
    }
}

fn take_frame(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buf.len() < 2 {
        return None;
    }
    let n = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + n {
        return None;
    }
    let frame = buf[2..2 + n].to_vec();
    buf.drain(..2 + n);
    Some(frame)
}

fn recv_hdr() -> libc::msghdr {
    let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
    hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as _;
    hdr
}

fn store_addr(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(addr) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as _,
                sin_port: addr.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from(*addr.ip()).to_be(),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    (&raw const sin).cast::<u8>(),
                    (&raw mut storage).cast::<u8>(),
                    std::mem::size_of::<libc::sockaddr_in>(),
                );
            }
            (storage, std::mem::size_of::<libc::sockaddr_in>() as _)
        }
        SocketAddr::V6(addr) => {
            let sin = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as _,
                sin6_port: addr.port().to_be(),
                sin6_flowinfo: addr.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: addr.ip().octets(),
                },
                sin6_scope_id: addr.scope_id(),
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    (&raw const sin).cast::<u8>(),
                    (&raw mut storage).cast::<u8>(),
                    std::mem::size_of::<libc::sockaddr_in6>(),
                );
            }
            (storage, std::mem::size_of::<libc::sockaddr_in6>() as _)
        }
    }
}

fn peer_from(name: &[u8]) -> Option<SocketAddr> {
    if name.len() < 4 {
        return None;
    }
    let family = u16::from_ne_bytes([name[0], name[1]]);
    if family == libc::AF_INET as u16 && name.len() >= 8 {
        let port = u16::from_be_bytes([name[2], name[3]]);
        let ip = Ipv4Addr::new(name[4], name[5], name[6], name[7]);
        return Some(SocketAddr::from((ip, port)));
    }
    if family == libc::AF_INET6 as u16 && name.len() >= 28 {
        let port = u16::from_be_bytes([name[2], name[3]]);
        let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&name[8..24]).ok()?);
        let scope = u32::from_ne_bytes([name[24], name[25], name[26], name[27]]);
        return Some(SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, scope)));
    }
    None
}

fn set_int(fd: RawFd, level: i32, opt: i32, val: i32) {
    unsafe {
        libc::setsockopt(fd, level, opt, (&raw const val).cast(), 4);
    }
}

fn tune_udp(fd: RawFd) {
    set_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, 4 << 20);
    set_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, 1 << 20);
}

fn udp_socket(v4: bool) -> std::io::Result<RawFd> {
    let domain = if v4 { libc::AF_INET } else { libc::AF_INET6 };
    let fd = unsafe {
        libc::socket(
            domain,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    tune_udp(fd);
    if !v4 {
        set_int(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 1);
    }
    let storage = if v4 {
        store_addr(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
    } else {
        store_addr(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))
    };
    let bound = unsafe { libc::bind(fd, (&raw const storage.0).cast(), storage.1) };
    if bound < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }
    Ok(fd)
}

fn tcp_socket(addr: SocketAddr) -> std::io::Result<RawFd> {
    let domain = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let fd = unsafe {
        libc::socket(
            domain,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    set_int(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1);
    set_int(fd, libc::IPPROTO_TCP, libc::TCP_QUICKACK, 1);
    set_int(fd, libc::IPPROTO_TCP, libc::TCP_FASTOPEN_CONNECT, 1);
    set_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1);
    set_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, 30);
    set_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, 10);
    set_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, 3);
    if addr.is_ipv4() {
        set_int(fd, libc::IPPROTO_IP, libc::IP_BIND_ADDRESS_NO_PORT, 1);
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_a_length_prefixed_message() {
        let mut buf = vec![0, 3, 1, 2, 3, 0, 2];
        assert_eq!(take_frame(&mut buf), Some(vec![1, 2, 3]));
        assert!(take_frame(&mut buf).is_none());
        buf.extend_from_slice(&[8, 9]);
        assert_eq!(take_frame(&mut buf), Some(vec![8, 9]));
    }
}
