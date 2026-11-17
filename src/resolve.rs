use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;
use lru::LruCache;

use crate::config::{AaaaPolicy, Config, DefaultTag, Error, GroupConfig, Transport, Upstream};
use crate::dns::{self, qname};
use crate::domains::{DomainMap, DomainTag};
use crate::ipset::{AddAddrs, Interval4, Interval6, NftAdder, NftSet, reserved};
use crate::upstream;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    China,
    Trust,
}

struct Route {
    upstreams: Vec<Upstream>,
    add_v4: Option<NftSet>,
    add_v6: Option<NftSet>,
    aaaa: AaaaPolicy,
}

pub struct App {
    pub bind_template: std::net::SocketAddr,
    pub listen: crate::config::ListenProto,
    filter_qtypes: Vec<u16>,
    drop_all_aaaa: bool,
    domains: DomainMap,
    groups: Vec<Route>,
    chn: Route,
    gfw: Route,
    none_aaaa: AaaaPolicy,
    default_tag: DomainTag,
    china: Vec<Upstream>,
    trust: Vec<Upstream>,
    china_v4: Interval4,
    china_v6: Interval6,
    adds: Arc<dyn AddAddrs>,
    hosts_v4: HashMap<String, Vec<Ipv4Addr>>,
    hosts_v6: HashMap<String, Vec<Ipv6Addr>>,
    verdict: Mutex<Option<LruCache<String, Side>>>,
    noip_as_chnip: bool,
    filter_reserved: bool,
    timeout: std::time::Duration,
}

impl App {
    pub fn boot(cfg: Config) -> Result<Self, Error> {
        let china_v4 = match &cfg.test_v4 {
            Some(set) => Interval4::load_nft(set)?,
            None => Interval4::empty(),
        };
        let china_v6 = match &cfg.test_v6 {
            Some(set) => Interval6::load_nft(set)?,
            None => Interval6::empty(),
        };
        Self::assemble(cfg, china_v4, china_v6, Arc::new(NftAdder))
    }

    pub fn assemble(
        cfg: Config,
        china_v4: Interval4,
        china_v6: Interval6,
        adds: Arc<dyn AddAddrs>,
    ) -> Result<Self, Error> {
        let mut domains = DomainMap::new();
        // Later custom groups outrank earlier ones, and every custom group
        // outranks gfwlist/chnlist. First stored suffix wins, so load in
        // reverse priority.
        for (idx, group) in cfg.groups.iter().enumerate().rev() {
            let tag = if group.name == "null" {
                DomainTag::Null
            } else {
                DomainTag::Group(idx)
            };
            for path in &group.lists {
                domains.load_file(path, tag)?;
            }
        }
        let builtins = if cfg.chnlist_first {
            [
                (DomainTag::Chn, &cfg.chn.lists),
                (DomainTag::Gfw, &cfg.gfw.lists),
            ]
        } else {
            [
                (DomainTag::Gfw, &cfg.gfw.lists),
                (DomainTag::Chn, &cfg.chn.lists),
            ]
        };
        for (tag, lists) in builtins {
            for path in lists {
                domains.load_file(path, tag)?;
            }
        }

        let default_tag = match &cfg.default_tag {
            DefaultTag::None => DomainTag::None,
            DefaultTag::Chn => DomainTag::Chn,
            DefaultTag::Gfw => DomainTag::Gfw,
            DefaultTag::Null => DomainTag::Null,
            DefaultTag::Group(name) => {
                let idx = cfg
                    .groups
                    .iter()
                    .position(|group| group.name == *name)
                    .ok_or_else(|| Error::msg(format!("unknown default-tag {name}")))?;
                if name == "null" {
                    DomainTag::Null
                } else {
                    DomainTag::Group(idx)
                }
            }
        };

        let (hosts_v4, hosts_v6) = load_hosts(&cfg.hosts)?;
        let verdict = Mutex::new(NonZeroUsize::new(cfg.verdict_cache).map(LruCache::new));
        tracing::info!(
            domains = domains.len(),
            groups = cfg.groups.len(),
            hosts = hosts_v4.len(),
            "loaded rules"
        );

        let groups = cfg.groups.iter().map(route_from_group).collect::<Vec<_>>();
        Ok(Self {
            bind_template: cfg.bind,
            listen: cfg.listen,
            filter_qtypes: cfg.filter_qtypes,
            drop_all_aaaa: cfg.drop_all_aaaa,
            domains,
            groups,
            chn: Route {
                upstreams: cfg.china.clone(),
                add_v4: cfg.chn.add_v4,
                add_v6: cfg.chn.add_v6,
                aaaa: cfg.chn.aaaa,
            },
            gfw: Route {
                upstreams: cfg.trust.clone(),
                add_v4: cfg.gfw.add_v4,
                add_v6: cfg.gfw.add_v6,
                aaaa: cfg.gfw.aaaa,
            },
            none_aaaa: cfg.none_aaaa,
            default_tag,
            china: cfg.china,
            trust: cfg.trust,
            china_v4,
            china_v6,
            adds,
            hosts_v4,
            hosts_v6,
            verdict,
            noip_as_chnip: cfg.noip_as_chnip,
            filter_reserved: cfg.filter_reserved,
            timeout: cfg.timeout,
        })
    }

    pub async fn handle(&self, packet: &[u8], via: Transport) -> Vec<u8> {
        let query = match dns::parse(packet) {
            Ok(query) => query,
            Err(err) => {
                tracing::debug!(%err, "dropped unparsable query");
                return Vec::new();
            }
        };
        if query.metadata.op_code != hickory_proto::op::OpCode::Query || query.queries.len() != 1 {
            return dns::failure(&query, ResponseCode::FormErr);
        }
        let question = &query.queries[0];
        let qtype: u16 = question.query_type().into();
        if self.filter_qtypes.contains(&qtype) {
            return dns::nodata(&query)
                .unwrap_or_else(|_| dns::failure(&query, ResponseCode::ServFail));
        }
        let name = qname(&query).unwrap_or_default();
        if let Some(answer) = self.hosts_hit(&query, &name) {
            return answer;
        }
        let tag = self.domains.lookup(&name).unwrap_or(self.default_tag);
        if self.drop_aaaa_now(tag, question.query_type()) {
            return dns::nodata(&query)
                .unwrap_or_else(|_| dns::failure(&query, ResponseCode::ServFail));
        }
        let answered = if tag == DomainTag::None {
            self.resolve_none(packet, via, &name).await
        } else if tag == DomainTag::Null {
            dns::nodata(&query).map_err(|err| err.to_string())
        } else {
            self.resolve_tagged(packet, via, tag).await
        };
        match answered {
            Ok(buf) => self.finish(&query, tag, buf),
            Err(err) => {
                tracing::debug!(%name, %err, "resolve failed");
                dns::failure(&query, ResponseCode::ServFail)
            }
        }
    }

    fn hosts_hit(&self, query: &Message, name: &str) -> Option<Vec<u8>> {
        if !self.hosts_v4.contains_key(name) && !self.hosts_v6.contains_key(name) {
            return None;
        }
        let v4 = self.hosts_v4.get(name).map(Vec::as_slice).unwrap_or(&[]);
        let v6 = self.hosts_v6.get(name).map(Vec::as_slice).unwrap_or(&[]);
        dns::hosts_answer(query, v4, v6).ok()
    }

    fn drop_aaaa_now(&self, tag: DomainTag, qtype: RecordType) -> bool {
        qtype == RecordType::AAAA && self.policy(tag) == AaaaPolicy::Drop
    }

    fn policy(&self, tag: DomainTag) -> AaaaPolicy {
        if self.drop_all_aaaa {
            return AaaaPolicy::Drop;
        }
        match tag {
            DomainTag::Chn => self.chn.aaaa,
            DomainTag::Gfw => self.gfw.aaaa,
            DomainTag::Null => AaaaPolicy::Drop,
            DomainTag::None => self.none_aaaa,
            DomainTag::Group(idx) => self
                .groups
                .get(idx)
                .map(|route| route.aaaa)
                .unwrap_or(AaaaPolicy::Allow),
        }
    }

    async fn resolve_tagged(
        &self,
        packet: &[u8],
        via: Transport,
        tag: DomainTag,
    ) -> Result<Vec<u8>, String> {
        let route = self
            .route(tag)
            .ok_or_else(|| "no route for tag".to_string())?;
        upstream::query(&route.upstreams, packet, via, self.timeout)
            .await
            .map_err(|err| err.to_string())
    }

    fn route(&self, tag: DomainTag) -> Option<&Route> {
        match tag {
            DomainTag::Chn => Some(&self.chn),
            DomainTag::Gfw => Some(&self.gfw),
            DomainTag::Group(idx) => self.groups.get(idx),
            DomainTag::Null | DomainTag::None => None,
        }
    }

    async fn resolve_none(
        &self,
        packet: &[u8],
        via: Transport,
        name: &str,
    ) -> Result<Vec<u8>, String> {
        if let Some(side) = self.verdict(name) {
            return self.query_side(side, packet, via).await;
        }
        let packet_trust = packet.to_vec();
        let trust = self.trust.clone();
        let timeout = self.timeout;
        let trust_task =
            tokio::spawn(async move { upstream::query(&trust, &packet_trust, via, timeout).await });
        match upstream::query(&self.china, packet, via, self.timeout).await {
            Ok(buf) if self.accepts_china(&buf) => {
                trust_task.abort();
                self.remember(name, Side::China);
                Ok(buf)
            }
            other => {
                if let Err(err) = &other {
                    tracing::debug!(%name, %err, "china upstream not accepted");
                }
                match trust_task.await {
                    Ok(Ok(buf)) => {
                        self.remember(name, Side::Trust);
                        Ok(buf)
                    }
                    Ok(Err(err)) => Err(err.to_string()),
                    Err(err) => Err(err.to_string()),
                }
            }
        }
    }

    async fn query_side(
        &self,
        side: Side,
        packet: &[u8],
        via: Transport,
    ) -> Result<Vec<u8>, String> {
        let upstreams = match side {
            Side::China => &self.china,
            Side::Trust => &self.trust,
        };
        upstream::query(upstreams, packet, via, self.timeout)
            .await
            .map_err(|err| err.to_string())
    }

    fn accepts_china(&self, packet: &[u8]) -> bool {
        let Ok(message) = dns::parse(packet) else {
            return false;
        };
        let addrs = dns::answer_addrs(&message);
        if addrs.is_empty() {
            return self.noip_as_chnip;
        }
        addrs.iter().all(|ip| match ip {
            IpAddr::V4(ip) => self.china_v4.contains(*ip),
            IpAddr::V6(ip) => self.china_v6.contains(*ip),
        })
    }

    fn verdict(&self, name: &str) -> Option<Side> {
        self.verdict
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .as_mut()?
            .get(name)
            .copied()
    }

    fn remember(&self, name: &str, side: Side) {
        if let Some(cache) = self
            .verdict
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .as_mut()
        {
            cache.put(name.to_string(), side);
        }
    }

    fn finish(&self, query: &Message, tag: DomainTag, mut packet: Vec<u8>) -> Vec<u8> {
        dns::set_id(&mut packet, query.metadata.id);
        let Ok(message) = dns::parse(&packet) else {
            return dns::failure(query, ResponseCode::ServFail);
        };
        if self.drop_aaaa_after(tag, &message) {
            return dns::nodata(query)
                .unwrap_or_else(|_| dns::failure(query, ResponseCode::ServFail));
        }
        if let Some(route) = self.route(tag) {
            self.publish(route.add_v4.as_ref(), route.add_v6.as_ref(), &message);
        }
        packet
    }

    fn drop_aaaa_after(&self, tag: DomainTag, message: &Message) -> bool {
        let policy = self.policy(tag);
        let v6: Vec<Ipv6Addr> = dns::answer_addrs(message)
            .into_iter()
            .filter_map(|ip| match ip {
                IpAddr::V6(ip) => Some(ip),
                IpAddr::V4(_) => None,
            })
            .collect();
        if v6.is_empty() {
            return false;
        }
        match policy {
            AaaaPolicy::DropIfChina => v6.iter().all(|ip| self.china_v6.contains(*ip)),
            AaaaPolicy::DropIfNonChina => v6.iter().all(|ip| !self.china_v6.contains(*ip)),
            AaaaPolicy::Allow | AaaaPolicy::Drop => false,
        }
    }

    fn publish(&self, v4: Option<&NftSet>, v6: Option<&NftSet>, message: &Message) {
        for ip in dns::answer_addrs(message) {
            if self.filter_reserved && reserved(ip) {
                continue;
            }
            match ip {
                IpAddr::V4(_) => {
                    if let Some(set) = v4 {
                        self.adds.add(set, ip);
                    }
                }
                IpAddr::V6(_) => {
                    if let Some(set) = v6 {
                        self.adds.add(set, ip);
                    }
                }
            }
        }
    }
}

fn route_from_group(group: &GroupConfig) -> Route {
    Route {
        upstreams: group.upstreams.clone(),
        add_v4: group.add_v4.clone(),
        add_v6: group.add_v6.clone(),
        aaaa: group.aaaa,
    }
}

type HostTables = (
    HashMap<String, Vec<Ipv4Addr>>,
    HashMap<String, Vec<Ipv6Addr>>,
);

fn load_hosts(paths: &[std::path::PathBuf]) -> Result<HostTables, Error> {
    let mut v4: HashMap<String, Vec<Ipv4Addr>> = HashMap::new();
    let mut v6: HashMap<String, Vec<Ipv6Addr>> = HashMap::new();
    for path in paths {
        let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.display().to_string(),
            source,
        })?;
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(addr) = parts.next() else { continue };
            let Ok(ip) = addr.parse::<IpAddr>() else {
                continue;
            };
            for name in parts {
                let name = name.trim_end_matches('.').to_ascii_lowercase();
                match ip {
                    IpAddr::V4(ip) => v4.entry(name).or_default().push(ip),
                    IpAddr::V6(ip) => v6.entry(name).or_default().push(ip),
                }
            }
        }
    }
    Ok((v4, v6))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use hickory_proto::op::Query;
    use hickory_proto::op::{Message, OpCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::ipset::MemoryAdds;
    use crate::server::{Server, query_udp};

    #[tokio::test]
    async fn forwards_by_list_and_china_ip() {
        let dir = std::env::temp_dir().join(format!("hickory-chinadns-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("gfw"), "blocked.example\n").unwrap();
        std::fs::write(dir.join("chn"), "cn.example\n").unwrap();
        std::fs::write(dir.join("proxy"), "proxy.example\n").unwrap();
        std::fs::write(dir.join("null"), "null.example\n").unwrap();
        std::fs::write(dir.join("hosts"), "10.0.0.1 local.test\n").unwrap();

        let poisoned_again = Arc::new(AtomicBool::new(false));
        let china = mock_dns(Arc::new(AtomicUsize::new(0)), {
            let poisoned_again = Arc::clone(&poisoned_again);
            move |name, _| {
                if name == "cn.example" {
                    return "1.1.1.1".parse().unwrap();
                }
                if name == "poisoned.example" && poisoned_again.swap(true, Ordering::SeqCst) {
                    return "1.1.1.1".parse().unwrap();
                }
                "8.8.8.8".parse().unwrap()
            }
        })
        .await;
        let trust = mock_dns(Arc::new(AtomicUsize::new(0)), |_, _| {
            "9.9.9.9".parse().unwrap()
        })
        .await;

        let cfg = Config::parse(&format!(
            "
            bind-addr 127.0.0.1
            bind-port 0
            china-dns tcp://{china}
            trust-dns tcp://{trust}
            filter-qtype 65
            group proxylist
            group-dnl {proxy}
            group-upstream tcp://{trust}
            group-ipset inet@passwall@psw_black
            group null
            group-dnl {null_list}
            gfwlist-file {gfw}
            add-taggfw-ip inet@passwall@psw_gfw
            chnlist-file {chn}
            ipset-name4 null
            ipset-name6 null
            add-tagchn-ip inet@passwall@psw_chn
            default-tag none
            verdict-cache 100
            hosts {hosts}
            timeout-sec 2
            ",
            proxy = dir.join("proxy").display(),
            null_list = dir.join("null").display(),
            gfw = dir.join("gfw").display(),
            chn = dir.join("chn").display(),
            hosts = dir.join("hosts").display(),
        ))
        .unwrap();
        let adds = Arc::new(MemoryAdds::default());
        let app = Arc::new(
            App::assemble(
                cfg,
                Interval4::from_cidrs(&["1.1.1.1/32"]),
                Interval6::empty(),
                adds.clone(),
            )
            .unwrap(),
        );
        let server = Server::bind(&app).unwrap();
        let local = server.local;
        let running = tokio::spawn(async move { server.run(app).await });

        let cn = ask(local, "cn.example", RecordType::A).await;
        assert_eq!(first_a(&cn), Some("1.1.1.1".parse().unwrap()));

        let poisoned = ask(local, "poisoned.example", RecordType::A).await;
        assert_eq!(first_a(&poisoned), Some("9.9.9.9".parse().unwrap()));
        let poisoned_again = ask(local, "poisoned.example", RecordType::A).await;
        assert_eq!(first_a(&poisoned_again), Some("9.9.9.9".parse().unwrap()));

        let blocked = ask(local, "blocked.example", RecordType::A).await;
        assert_eq!(first_a(&blocked), Some("9.9.9.9".parse().unwrap()));
        let proxy = ask(local, "proxy.example", RecordType::A).await;
        assert_eq!(first_a(&proxy), Some("9.9.9.9".parse().unwrap()));

        let https = ask(local, "cn.example", RecordType::HTTPS).await;
        let https_msg = Message::from_vec(&https).unwrap();
        assert!(https_msg.answers.is_empty());
        assert_eq!(
            https_msg.metadata.response_code,
            hickory_proto::op::ResponseCode::NoError
        );

        let blocked_name = ask(local, "null.example", RecordType::A).await;
        assert!(Message::from_vec(&blocked_name).unwrap().answers.is_empty());

        let host = ask(local, "local.test", RecordType::A).await;
        assert_eq!(first_a(&host), Some("10.0.0.1".parse().unwrap()));

        let added = adds.added.lock().unwrap().clone();
        let is = |set: &str, addr: &str| {
            added
                .iter()
                .any(|(name, ip)| name == set && *ip == addr.parse::<IpAddr>().unwrap())
        };
        assert!(is("psw_chn", "1.1.1.1"));
        assert!(is("psw_gfw", "9.9.9.9"));
        assert!(is("psw_black", "9.9.9.9"));
        assert!(
            !added
                .iter()
                .any(|(_, ip)| *ip == "8.8.8.8".parse::<IpAddr>().unwrap())
        );

        running.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    async fn ask(addr: std::net::SocketAddr, name: &str, qtype: RecordType) -> Vec<u8> {
        let mut message = Message::query();
        message.add_query(Query::query(Name::from_ascii(name).unwrap(), qtype));
        message.metadata.recursion_desired = true;
        query_udp(addr, &message.to_vec().unwrap()).await.unwrap()
    }

    fn first_a(packet: &[u8]) -> Option<Ipv4Addr> {
        dns::answer_addrs(&Message::from_vec(packet).unwrap())
            .into_iter()
            .find_map(|ip| match ip {
                IpAddr::V4(ip) => Some(ip),
                IpAddr::V6(_) => None,
            })
    }

    async fn mock_dns(
        hits: Arc<AtomicUsize>,
        pick: impl Fn(&str, usize) -> Ipv4Addr + Send + Sync + 'static,
    ) -> std::net::SocketAddr {
        let pick = Arc::new(pick);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let hits = Arc::clone(&hits);
                let pick = Arc::clone(&pick);
                tokio::spawn(async move {
                    let mut len_buf = [0u8; 2];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let n = u16::from_be_bytes(len_buf) as usize;
                    let mut packet = vec![0u8; n];
                    if stream.read_exact(&mut packet).await.is_err() {
                        return;
                    }
                    let Ok(query) = dns::parse(&packet) else {
                        return;
                    };
                    let name = qname(&query).unwrap_or_default();
                    let seen = hits.fetch_add(1, Ordering::SeqCst) + 1;
                    let ip = pick(&name, seen);
                    let mut message = Message::response(query.metadata.id, OpCode::Query);
                    message.metadata.recursion_available = true;
                    if let Some(question) = query.queries.first() {
                        message.add_query(question.clone());
                        message.add_answer(Record::from_rdata(
                            question.name().clone(),
                            30,
                            RData::A(A(ip)),
                        ));
                    }
                    let Ok(bytes) = dns::encode(&message) else {
                        return;
                    };
                    let len = (bytes.len() as u16).to_be_bytes();
                    let _ = stream.write_all(&len).await;
                    let _ = stream.write_all(&bytes).await;
                });
            }
        });
        addr
    }
}
