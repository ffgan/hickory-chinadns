use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::ipset::NftSet;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Msg(String),
    #[error("{path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
}

impl Error {
    pub fn msg(text: impl Into<String>) -> Self {
        Self::Msg(text.into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenProto {
    Udp,
    Tcp,
    Both,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub transport: Option<Transport>,
    pub addr: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AaaaPolicy {
    Allow,
    Drop,
    DropIfChina,
    DropIfNonChina,
}

#[derive(Debug, Clone)]
pub struct GroupConfig {
    pub name: String,
    pub lists: Vec<PathBuf>,
    pub upstreams: Vec<Upstream>,
    pub add_v4: Option<NftSet>,
    pub add_v6: Option<NftSet>,
    pub aaaa: AaaaPolicy,
}

#[derive(Debug, Clone)]
pub struct BuiltinRoute {
    pub lists: Vec<PathBuf>,
    pub add_v4: Option<NftSet>,
    pub add_v6: Option<NftSet>,
    pub aaaa: AaaaPolicy,
    /// `add-tagchn-ip` without a set name uses the ip test sets.
    pub add_follows_test: bool,
}

#[derive(Debug, Clone)]
pub enum DefaultTag {
    None,
    Chn,
    Gfw,
    Null,
    Group(String),
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub listen: ListenProto,
    pub china: Vec<Upstream>,
    pub trust: Vec<Upstream>,
    pub groups: Vec<GroupConfig>,
    pub gfw: BuiltinRoute,
    pub chn: BuiltinRoute,
    pub chnlist_first: bool,
    pub default_tag: DefaultTag,
    pub test_v4: Option<NftSet>,
    pub test_v6: Option<NftSet>,
    pub filter_qtypes: Vec<u16>,
    pub drop_all_aaaa: bool,
    pub none_aaaa: AaaaPolicy,
    pub hosts: Vec<PathBuf>,
    pub verdict_cache: usize,
    pub timeout: Duration,
    pub noip_as_chnip: bool,
    pub filter_reserved: bool,
    pub verbose: bool,
}

impl Default for BuiltinRoute {
    fn default() -> Self {
        Self {
            lists: Vec::new(),
            add_v4: None,
            add_v6: None,
            aaaa: AaaaPolicy::Allow,
            add_follows_test: false,
        }
    }
}

impl Config {
    pub fn from_file(path: &Path) -> Result<Self, Error> {
        let text = fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut bind_addr: IpAddr = IpAddr::from([127, 0, 0, 1]);
        let mut port = 65353u16;
        let mut listen = ListenProto::Both;
        let mut china = Vec::new();
        let mut trust = Vec::new();
        let mut groups: Vec<GroupConfig> = Vec::new();
        let mut current: Option<usize> = None;
        let mut gfw = BuiltinRoute::default();
        let mut chn = BuiltinRoute::default();
        let mut chnlist_first = false;
        let mut default_tag = DefaultTag::None;
        let mut test_v4 = None;
        let mut test_v6 = None;
        let mut filter_qtypes = Vec::new();
        let mut drop_all_aaaa = false;
        let mut none_aaaa = AaaaPolicy::Allow;
        let mut hosts = Vec::new();
        let mut hosts_default = false;
        let mut verdict_cache = 0usize;
        let mut timeout = Duration::from_secs(5);
        let mut noip_as_chnip = false;
        let mut filter_reserved = true;
        let mut verbose = false;

        for (idx, raw) in text.lines().enumerate() {
            let line_no = idx + 1;
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once(char::is_whitespace)
                .map(|(k, v)| (k, v.trim()))
                .unwrap_or((line, ""));
            let err = |text: &str| Error::msg(format!("line {line_no}: {text}"));
            let line_err = |error: Error| Error::msg(format!("line {line_no}: {error}"));

            match key {
                "bind-addr" => {
                    bind_addr = value
                        .parse()
                        .map_err(|_| err(&format!("bad bind-addr {value}")))?;
                }
                "bind-port" => {
                    let (p, proto) = value.split_once('@').unwrap_or((value, ""));
                    port = p
                        .parse()
                        .map_err(|_| err(&format!("bad bind-port {value}")))?;
                    listen = match proto {
                        "" => ListenProto::Both,
                        "udp" => ListenProto::Udp,
                        "tcp" => ListenProto::Tcp,
                        _ => return Err(err(&format!("bad bind-port proto {proto}"))),
                    };
                }
                "china-dns" => china.extend(parse_upstreams(value).map_err(line_err)?),
                "trust-dns" => trust.extend(parse_upstreams(value).map_err(line_err)?),
                "chnlist-file" => chn.lists.extend(csv_paths(value)),
                "gfwlist-file" => gfw.lists.extend(csv_paths(value)),
                "chnlist-first" => {
                    reject_value(value).map_err(line_err)?;
                    chnlist_first = true;
                }
                "default-tag" => {
                    default_tag = match value {
                        "none" => DefaultTag::None,
                        "chn" => DefaultTag::Chn,
                        "gfw" => DefaultTag::Gfw,
                        "null" => DefaultTag::Null,
                        name if !name.is_empty() => DefaultTag::Group(name.to_string()),
                        _ => return Err(err("default-tag needs a value")),
                    };
                }
                "add-tagchn-ip" => {
                    if value.is_empty() {
                        chn.add_follows_test = true;
                    } else {
                        let (v4, v6) = parse_set_pair(value).map_err(line_err)?;
                        chn.add_v4 = v4;
                        chn.add_v6 = v6;
                    }
                }
                "add-taggfw-ip" => {
                    let (v4, v6) = parse_set_pair(value).map_err(line_err)?;
                    gfw.add_v4 = v4;
                    gfw.add_v6 = v6;
                }
                "ipset-name4" => test_v4 = parse_set_name(value).map_err(line_err)?,
                "ipset-name6" => test_v6 = parse_set_name(value).map_err(line_err)?,
                "group" => {
                    if value.is_empty() {
                        return Err(err("group needs a name"));
                    }
                    if matches!(value, "chn" | "gfw" | "none") {
                        return Err(err(&format!("group name {value} is reserved")));
                    }
                    groups.push(GroupConfig {
                        name: value.to_string(),
                        lists: Vec::new(),
                        upstreams: Vec::new(),
                        add_v4: None,
                        add_v6: None,
                        aaaa: AaaaPolicy::Allow,
                    });
                    current = Some(groups.len() - 1);
                }
                "group-dnl" => {
                    let group =
                        current_group(&mut groups, current).map_err(|e| err(&e.to_string()))?;
                    group.lists.extend(csv_paths(value));
                }
                "group-upstream" => {
                    let ups = parse_upstreams(value).map_err(line_err)?;
                    let group =
                        current_group(&mut groups, current).map_err(|e| err(&e.to_string()))?;
                    if group.name == "null" {
                        return Err(err("null group does not take an upstream"));
                    }
                    group.upstreams.extend(ups);
                }
                "group-ipset" => {
                    let (v4, v6) = parse_set_pair(value).map_err(line_err)?;
                    let group =
                        current_group(&mut groups, current).map_err(|e| err(&e.to_string()))?;
                    group.add_v4 = v4;
                    group.add_v6 = v6;
                }
                "no-ipv6" => {
                    if value.is_empty() {
                        drop_all_aaaa = true;
                    } else {
                        for rule in split_csv(value) {
                            apply_aaaa_rule(rule, &mut groups, &mut gfw, &mut chn, &mut none_aaaa)
                                .map_err(line_err)?;
                        }
                    }
                }
                "filter-qtype" => {
                    for part in split_csv(value) {
                        let qtype = part
                            .parse()
                            .map_err(|_| err(&format!("bad qtype {part}")))?;
                        filter_qtypes.push(qtype);
                    }
                }
                "verdict-cache" => {
                    verdict_cache = value
                        .parse()
                        .map_err(|_| err(&format!("bad verdict-cache {value}")))?;
                }
                "hosts" => {
                    if value.is_empty() {
                        hosts_default = true;
                    } else {
                        hosts.push(PathBuf::from(value));
                    }
                }
                "timeout-sec" => {
                    let secs: u64 = value
                        .parse()
                        .map_err(|_| err(&format!("bad timeout-sec {value}")))?;
                    timeout = Duration::from_secs(secs);
                }
                "noip-as-chnip" => {
                    reject_value(value).map_err(line_err)?;
                    noip_as_chnip = true;
                }
                "no-ipset-blacklist" => {
                    reject_value(value).map_err(line_err)?;
                    filter_reserved = false;
                }
                "verbose" => {
                    reject_value(value).map_err(line_err)?;
                    verbose = true;
                }
                "fair-mode" | "reuse-port" => reject_value(value).map_err(line_err)?,
                "cache" | "cache-stale" | "cache-refresh" | "cache-nodata-ttl"
                | "cache-min-ttl" | "cache-max-ttl" | "cache-ignore" | "cache-db"
                | "verdict-cache-db" | "dns-rr-ip" | "cert-verify" | "ca-certs"
                | "repeat-times" => {
                    return Err(err(&format!("{key} is not implemented")));
                }
                _ => return Err(err(&format!("unknown option {key}"))),
            }
        }

        if china.is_empty() {
            china.push(Upstream {
                transport: None,
                addr: SocketAddr::from(([114, 114, 114, 114], 53)),
            });
        }
        if trust.is_empty() {
            trust.push(Upstream {
                transport: None,
                addr: SocketAddr::from(([8, 8, 8, 8], 53)),
            });
        }
        if chn.add_follows_test {
            chn.add_v4 = test_v4.clone();
            chn.add_v6 = test_v6.clone();
        }
        if hosts_default {
            hosts.push(PathBuf::from("/etc/hosts"));
        }
        if let DefaultTag::Group(name) = &default_tag {
            if !groups.iter().any(|group| group.name == *name) {
                return Err(Error::msg(format!("default-tag {name} has no group")));
            }
        }
        for group in &groups {
            if group.name != "null" && group.upstreams.is_empty() {
                return Err(Error::msg(format!(
                    "group {} has no group-upstream",
                    group.name
                )));
            }
            if group.lists.is_empty() {
                return Err(Error::msg(format!("group {} has no group-dnl", group.name)));
            }
        }

        Ok(Config {
            bind: SocketAddr::new(bind_addr, port),
            listen,
            china,
            trust,
            groups,
            gfw,
            chn,
            chnlist_first,
            default_tag,
            test_v4,
            test_v6,
            filter_qtypes,
            drop_all_aaaa,
            none_aaaa,
            hosts,
            verdict_cache,
            timeout,
            noip_as_chnip,
            filter_reserved,
            verbose,
        })
    }
}

fn current_group(
    groups: &mut [GroupConfig],
    current: Option<usize>,
) -> Result<&mut GroupConfig, Error> {
    let idx = current.ok_or_else(|| Error::msg("group-* before group"))?;
    Ok(&mut groups[idx])
}

fn reject_value(value: &str) -> Result<(), Error> {
    if value.is_empty() {
        Ok(())
    } else {
        Err(Error::msg(format!("unexpected value {value}")))
    }
}

fn csv_paths(value: &str) -> Vec<PathBuf> {
    split_csv(value).map(PathBuf::from).collect()
}

fn split_csv(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
}

pub fn parse_upstreams(value: &str) -> Result<Vec<Upstream>, Error> {
    let mut out = Vec::new();
    for part in split_csv(value) {
        out.push(parse_upstream(part)?);
    }
    if out.is_empty() {
        return Err(Error::msg("upstream list is empty"));
    }
    Ok(out)
}

pub fn parse_upstream(raw: &str) -> Result<Upstream, Error> {
    let spec = raw.split('?').next().unwrap_or(raw);
    let (transport, rest) = if let Some(rest) = spec.strip_prefix("tcp://") {
        (Some(Transport::Tcp), rest)
    } else if let Some(rest) = spec.strip_prefix("udp://") {
        (Some(Transport::Udp), rest)
    } else if spec.contains("://") {
        return Err(Error::msg(format!("unsupported upstream {raw}")));
    } else {
        (None, spec)
    };
    let rest = rest.rsplit_once('@').map(|(_, ip)| ip).unwrap_or(rest);
    let (host, port) = if let Some((host, port)) = rest.rsplit_once('#') {
        let port = port
            .parse()
            .map_err(|_| Error::msg(format!("bad port in {raw}")))?;
        (host, port)
    } else if let Some((host, port)) = rest.rsplit_once(':') {
        if host.parse::<std::net::Ipv4Addr>().is_ok() {
            let port = port
                .parse()
                .map_err(|_| Error::msg(format!("bad port in {raw}")))?;
            (host, port)
        } else {
            (rest, 53)
        }
    } else {
        (rest, 53)
    };
    let ip: IpAddr = host
        .parse()
        .map_err(|_| Error::msg(format!("bad upstream address {raw}")))?;
    Ok(Upstream {
        transport,
        addr: SocketAddr::new(ip, port),
    })
}

fn parse_set_pair(value: &str) -> Result<(Option<NftSet>, Option<NftSet>), Error> {
    let mut parts = split_csv(value);
    let v4 = match parts.next() {
        Some(name) => parse_set_name(name)?,
        None => return Err(Error::msg("missing nft set")),
    };
    let v6 = match parts.next() {
        Some(name) => parse_set_name(name)?,
        None => None,
    };
    if parts.next().is_some() {
        return Err(Error::msg(format!("too many nft sets in {value}")));
    }
    Ok((v4, v6))
}

fn parse_set_name(value: &str) -> Result<Option<NftSet>, Error> {
    if value == "null" {
        return Ok(None);
    }
    let mut parts = value.split('@');
    let family = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| Error::msg(format!("bad nft set {value}")))?;
    let table = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| Error::msg(format!("nft set {value} needs family@table@set")))?;
    let name = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| Error::msg(format!("nft set {value} needs family@table@set")))?;
    if parts.next().is_some() {
        return Err(Error::msg(format!("bad nft set {value}")));
    }
    Ok(Some(NftSet {
        family: family.to_string(),
        table: table.to_string(),
        name: name.to_string(),
    }))
}

fn apply_aaaa_rule(
    rule: &str,
    groups: &mut [GroupConfig],
    gfw: &mut BuiltinRoute,
    chn: &mut BuiltinRoute,
    none_aaaa: &mut AaaaPolicy,
) -> Result<(), Error> {
    let (tag, policy) = if let Some(rest) = rule.strip_prefix("tag:") {
        let (name, test) = rest
            .split_once('@')
            .map(|(name, test)| (name, Some(test)))
            .unwrap_or((rest, None));
        (Some(name), aaaa_policy(test)?)
    } else {
        (None, aaaa_policy(Some(rule))?)
    };
    let Some(tag) = tag else {
        *none_aaaa = policy;
        gfw.aaaa = policy;
        chn.aaaa = policy;
        for group in groups.iter_mut() {
            group.aaaa = policy;
        }
        return Ok(());
    };
    match tag {
        "chn" => chn.aaaa = policy,
        "gfw" => gfw.aaaa = policy,
        "none" => *none_aaaa = policy,
        "null" => {}
        name => {
            let group = groups
                .iter_mut()
                .find(|group| group.name == name)
                .ok_or_else(|| Error::msg(format!("no-ipv6 tag {name} is not a group")))?;
            group.aaaa = policy;
        }
    }
    Ok(())
}

fn aaaa_policy(test: Option<&str>) -> Result<AaaaPolicy, Error> {
    match test {
        None => Ok(AaaaPolicy::Drop),
        Some("ip:china") => Ok(AaaaPolicy::DropIfChina),
        Some("ip:non_china") => Ok(AaaaPolicy::DropIfNonChina),
        Some(other) => Err(Error::msg(format!("bad no-ipv6 rule {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_passwall_shape() {
        let cfg = Config::parse(
            "
            bind-addr ::
            bind-port 15354
            china-dns tcp://223.5.5.5
            trust-dns tcp://1.1.1.1#53
            filter-qtype 65,28
            group proxylist
            group-dnl /tmp/proxy_host
            group-upstream tcp://1.1.1.1
            group-ipset inet@passwall@psw_black,inet@passwall@psw_black6
            no-ipv6 tag:proxylist
            group null
            group-dnl /tmp/block_host
            gfwlist-file /tmp/gfwlist
            add-taggfw-ip inet@passwall@psw_gfw,inet@passwall@psw_gfw6
            no-ipv6 tag:gfw
            chnlist-file /tmp/chnlist
            ipset-name4 inet@passwall@psw_chn_static
            ipset-name6 inet@passwall@psw_chn6_static
            add-tagchn-ip inet@passwall@psw_chn,inet@passwall@psw_chn6
            default-tag none
            verdict-cache 5000
            hosts
            ",
        )
        .unwrap();
        assert_eq!(cfg.bind.port(), 15354);
        assert!(cfg.bind.ip().is_ipv6());
        assert_eq!(cfg.groups.len(), 2);
        assert_eq!(cfg.groups[0].name, "proxylist");
        assert_eq!(cfg.groups[0].aaaa, AaaaPolicy::Drop);
        assert_eq!(cfg.groups[1].name, "null");
        assert!(cfg.groups[1].upstreams.is_empty());
        assert_eq!(cfg.verdict_cache, 5000);
        assert_eq!(cfg.filter_qtypes, vec![65, 28]);
        assert_eq!(cfg.gfw.aaaa, AaaaPolicy::Drop);
        assert_eq!(
            cfg.test_v4.as_ref().map(|set| set.name.as_str()),
            Some("psw_chn_static")
        );
        assert_eq!(cfg.hosts, vec![PathBuf::from("/etc/hosts")]);
        assert_eq!(cfg.china[0].transport, Some(Transport::Tcp));
        assert_eq!(cfg.trust[0].addr.port(), 53);
    }
}
