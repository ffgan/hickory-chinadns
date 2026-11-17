use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::config::{Error, Transport, Upstream};

pub async fn query(
    upstreams: &[Upstream],
    packet: &[u8],
    via: Transport,
    limit: Duration,
) -> Result<Vec<u8>, Error> {
    if upstreams.is_empty() {
        return Err(Error::msg("no upstream"));
    }
    let ring = crate::reactor::handle();
    let mut tasks = tokio::task::JoinSet::new();
    for upstream in upstreams {
        let upstream = upstream.clone();
        let packet = packet.to_vec();
        let ring = ring.clone();
        tasks.spawn(async move { query_one(&upstream, &packet, via, limit, ring).await });
    }
    let mut last = Error::msg("upstream failed");
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(Ok(buf)) => {
                tasks.abort_all();
                return Ok(buf);
            }
            Ok(Err(err)) => last = err,
            Err(err) => last = Error::msg(err.to_string()),
        }
    }
    Err(last)
}

async fn query_one(
    upstream: &Upstream,
    packet: &[u8],
    via: Transport,
    limit: Duration,
    ring: Option<crate::reactor::Handle>,
) -> Result<Vec<u8>, Error> {
    let transport = upstream.transport.unwrap_or(via);
    let result = timeout(limit, async {
        if let Some(ring) = ring {
            return ring.exchange(transport, upstream.addr, packet, limit).await;
        }
        match transport {
            Transport::Tcp => query_tcp(upstream.addr, packet).await,
            Transport::Udp => query_udp(upstream.addr, packet).await,
        }
    })
    .await;
    match result {
        Ok(inner) => inner,
        Err(_) => Err(Error::msg(format!("upstream {} timed out", upstream.addr))),
    }
}

async fn query_tcp(addr: SocketAddr, packet: &[u8]) -> Result<Vec<u8>, Error> {
    if packet.len() > u16::MAX as usize {
        return Err(Error::msg("query exceeds tcp dns length"));
    }
    let mut stream = TcpStream::connect(addr).await.map_err(|source| Error::Io {
        path: addr.to_string(),
        source,
    })?;
    stream.set_nodelay(true).ok();
    let mut framed = Vec::with_capacity(2 + packet.len());
    framed.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    framed.extend_from_slice(packet);
    stream
        .write_all(&framed)
        .await
        .map_err(|source| Error::Io {
            path: addr.to_string(),
            source,
        })?;
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|source| Error::Io {
            path: addr.to_string(),
            source,
        })?;
    let n = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; n];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|source| Error::Io {
            path: addr.to_string(),
            source,
        })?;
    Ok(buf)
}

async fn query_udp(addr: SocketAddr, packet: &[u8]) -> Result<Vec<u8>, Error> {
    let bind = if addr.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let socket = UdpSocket::bind(bind).await.map_err(|source| Error::Io {
        path: bind.to_string(),
        source,
    })?;
    socket
        .send_to(packet, addr)
        .await
        .map_err(|source| Error::Io {
            path: addr.to_string(),
            source,
        })?;
    let mut buf = vec![0u8; 4096];
    let (n, _) = socket
        .recv_from(&mut buf)
        .await
        .map_err(|source| Error::Io {
            path: addr.to_string(),
            source,
        })?;
    buf.truncate(n);
    Ok(buf)
}
