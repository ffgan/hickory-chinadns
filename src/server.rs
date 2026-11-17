use std::sync::Arc;

use socket2::{Domain, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use crate::config::{Error, ListenProto, Transport};
use crate::resolve::App;

pub struct Server {
    pub local: std::net::SocketAddr,
    udp: Option<Arc<UdpSocket>>,
    tcp: Option<TcpListener>,
}

impl Server {
    pub fn bind(app: &App) -> Result<Self, Error> {
        let want_udp = matches!(app.listen, ListenProto::Udp | ListenProto::Both);
        let want_tcp = matches!(app.listen, ListenProto::Tcp | ListenProto::Both);
        let udp = if want_udp {
            Some(bind_udp(app.bind_template)?)
        } else {
            None
        };
        let local = udp
            .as_ref()
            .map(|sock| sock.local_addr())
            .transpose()
            .map_err(|source| Error::Io {
                path: app.bind_template.to_string(),
                source,
            })?
            .unwrap_or(app.bind_template);
        let tcp_addr = std::net::SocketAddr::new(app.bind_template.ip(), local.port());
        let tcp = if want_tcp {
            Some(bind_tcp(tcp_addr)?)
        } else {
            None
        };
        let local = tcp
            .as_ref()
            .map(|sock| sock.local_addr())
            .transpose()
            .map_err(|source| Error::Io {
                path: tcp_addr.to_string(),
                source,
            })?
            .unwrap_or(local);
        Ok(Self { local, udp, tcp })
    }

    pub async fn run(self, app: Arc<App>) -> Result<(), Error> {
        let udp = self.udp;
        let tcp = self.tcp;
        let app_udp = Arc::clone(&app);
        let app_tcp = app;
        tokio::try_join!(
            async move {
                if let Some(socket) = udp {
                    udp_loop(socket, app_udp).await?;
                }
                Ok(())
            },
            async move {
                if let Some(listener) = tcp {
                    tcp_loop(listener, app_tcp).await?;
                }
                Ok(())
            },
        )
        .map(|_| ())
    }
}

async fn udp_loop(socket: Arc<UdpSocket>, app: Arc<App>) -> Result<(), Error> {
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = socket
            .recv_from(&mut buf)
            .await
            .map_err(|source| Error::Io {
                path: "udp".to_string(),
                source,
            })?;
        let packet = buf[..n].to_vec();
        let socket = Arc::clone(&socket);
        let app = Arc::clone(&app);
        tokio::spawn(async move {
            let response = app.handle(&packet, Transport::Udp).await;
            if !response.is_empty() {
                let _ = socket.send_to(&response, peer).await;
            }
        });
    }
}

async fn tcp_loop(listener: TcpListener, app: Arc<App>) -> Result<(), Error> {
    loop {
        let (mut stream, _) = listener.accept().await.map_err(|source| Error::Io {
            path: "tcp".to_string(),
            source,
        })?;
        let app = Arc::clone(&app);
        tokio::spawn(async move {
            loop {
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    break;
                }
                let n = u16::from_be_bytes(len_buf) as usize;
                let mut packet = vec![0u8; n];
                if stream.read_exact(&mut packet).await.is_err() {
                    break;
                }
                let response = app.handle(&packet, Transport::Tcp).await;
                if response.is_empty() {
                    break;
                }
                let len = (response.len() as u16).to_be_bytes();
                if stream.write_all(&len).await.is_err()
                    || stream.write_all(&response).await.is_err()
                {
                    break;
                }
            }
        });
    }
}

fn bind_udp(addr: std::net::SocketAddr) -> Result<Arc<UdpSocket>, Error> {
    let std_socket = open_socket(addr, Type::DGRAM)?;
    let udp: std::net::UdpSocket = std_socket.into();
    udp.set_nonblocking(true).map_err(|source| Error::Io {
        path: addr.to_string(),
        source,
    })?;
    Ok(Arc::new(UdpSocket::from_std(udp).map_err(|source| {
        Error::Io {
            path: addr.to_string(),
            source,
        }
    })?))
}

fn bind_tcp(addr: std::net::SocketAddr) -> Result<TcpListener, Error> {
    let socket = open_socket(addr, Type::STREAM)?;
    socket.listen(1024).map_err(|source| Error::Io {
        path: addr.to_string(),
        source,
    })?;
    let listener: std::net::TcpListener = socket.into();
    listener.set_nonblocking(true).map_err(|source| Error::Io {
        path: addr.to_string(),
        source,
    })?;
    TcpListener::from_std(listener).map_err(|source| Error::Io {
        path: addr.to_string(),
        source,
    })
}

fn open_socket(addr: std::net::SocketAddr, kind: Type) -> Result<Socket, Error> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, kind, None).map_err(|source| Error::Io {
        path: addr.to_string(),
        source,
    })?;
    socket.set_reuse_address(true).ok();
    if addr.is_ipv6() {
        socket.set_only_v6(false).ok();
    }
    socket.bind(&addr.into()).map_err(|source| Error::Io {
        path: addr.to_string(),
        source,
    })?;
    socket.set_nonblocking(true).map_err(|source| Error::Io {
        path: addr.to_string(),
        source,
    })?;
    Ok(socket)
}

pub async fn query_udp(addr: std::net::SocketAddr, packet: &[u8]) -> Result<Vec<u8>, Error> {
    crate::upstream::query(
        &[crate::config::Upstream {
            transport: Some(Transport::Udp),
            addr,
        }],
        packet,
        Transport::Udp,
        std::time::Duration::from_secs(2),
    )
    .await
}
