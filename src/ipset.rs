use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::sync::Mutex;

use serde_json::Value;

use crate::config::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftSet {
    pub family: String,
    pub table: String,
    pub name: String,
}

impl std::fmt::Display for NftSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}@{}", self.family, self.table, self.name)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Interval4 {
    ranges: Vec<(u32, u32)>,
}

#[derive(Debug, Clone, Default)]
pub struct Interval6 {
    ranges: Vec<(u128, u128)>,
}

impl Interval4 {
    pub fn empty() -> Self {
        Self { ranges: Vec::new() }
    }

    pub fn from_cidrs(cidrs: &[&str]) -> Self {
        let mut ranges = Vec::new();
        for cidr in cidrs {
            if let Some(range) = parse_v4_token(cidr) {
                ranges.push(range);
            }
        }
        Self {
            ranges: merge_u32(ranges),
        }
    }

    pub fn load_nft(set: &NftSet) -> Result<Self, Error> {
        let json = nft_json(set)?;
        let mut ranges = Vec::new();
        for elem in nft_elements(&json)? {
            if let Some(range) = v4_from_elem(&elem) {
                ranges.push(range);
            }
        }
        Ok(Self {
            ranges: merge_u32(ranges),
        })
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        contains_u32(&self.ranges, u32::from(ip))
    }
}

impl Interval6 {
    pub fn empty() -> Self {
        Self { ranges: Vec::new() }
    }

    pub fn load_nft(set: &NftSet) -> Result<Self, Error> {
        let json = nft_json(set)?;
        let mut ranges = Vec::new();
        for elem in nft_elements(&json)? {
            if let Some(range) = v6_from_elem(&elem) {
                ranges.push(range);
            }
        }
        Ok(Self {
            ranges: merge_u128(ranges),
        })
    }

    pub fn contains(&self, ip: Ipv6Addr) -> bool {
        contains_u128(&self.ranges, u128::from(ip))
    }
}

pub trait AddAddrs: Send + Sync {
    fn add(&self, set: &NftSet, ip: std::net::IpAddr);
}

#[derive(Default)]
pub struct MemoryAdds {
    pub added: Mutex<Vec<(String, std::net::IpAddr)>>,
}

impl AddAddrs for MemoryAdds {
    fn add(&self, set: &NftSet, ip: std::net::IpAddr) {
        self.added
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .push((set.name.clone(), ip));
    }
}

pub struct NftAdder;

impl AddAddrs for NftAdder {
    fn add(&self, set: &NftSet, ip: std::net::IpAddr) {
        let set = set.clone();
        tokio::spawn(async move {
            let _ = tokio::task::spawn_blocking(move || add_element(&set, ip)).await;
        });
    }
}

pub fn reserved(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => ip.octets()[0] == 0 || ip.is_loopback(),
        std::net::IpAddr::V6(ip) => ip.is_unspecified() || ip.is_loopback(),
    }
}

fn nft_json(set: &NftSet) -> Result<String, Error> {
    let output = Command::new("nft")
        .args(["-j", "list", "set", &set.family, &set.table, &set.name])
        .output()
        .map_err(|source| Error::Io {
            path: "nft".to_string(),
            source,
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::msg(format!("nft list set {set} failed: {stderr}")));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| Error::msg(format!("nft list set {set} returned non-utf8")))
}

fn nft_elements(json: &str) -> Result<Vec<Value>, Error> {
    let value: Value =
        serde_json::from_str(json).map_err(|err| Error::msg(format!("nft json: {err}")))?;
    let sets = value
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::msg("nft json has no nftables array"))?;
    for item in sets {
        if let Some(elements) = item.get("set").and_then(|set| set.get("elem")) {
            return Ok(elements.as_array().cloned().unwrap_or_default());
        }
    }
    Ok(Vec::new())
}

fn add_element(set: &NftSet, ip: std::net::IpAddr) {
    // chinadns-ng inserts a half-open interval [ip, ip+1) over netlink and lets
    // the set's own timeout apply. `nft add element` userspace-merges interval
    // sets first, and that merge returns ENOENT on the live psw_chn / psw_white
    // sets even though the kernel accepts the same netlink message.
    if let Err(err) = netlink_add(set, ip) {
        tracing::warn!(%set, %ip, %err, "nft add element failed");
    }
}

const NETLINK_NETFILTER: i32 = 12;
const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFT_MSG_NEWSETELEM: u16 = 12;
const NFNL_MSG_BATCH_BEGIN: u16 = 16;
const NFNL_MSG_BATCH_END: u16 = 17;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLMSG_ERROR: u16 = 2;
const NLA_F_NESTED: u16 = 1 << 15;
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
const NFT_SET_ELEM_INTERVAL_END: u32 = 1;

fn netlink_add(set: &NftSet, ip: std::net::IpAddr) -> Result<(), String> {
    let family = nfproto(&set.family)?;
    let bytes = match ip {
        std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
        std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    let end = next_addr(&bytes).ok_or_else(|| "address overflow".to_string())?;
    let batch = build_add_batch(family, &set.table, &set.name, &bytes, &end);
    send_netlink(&batch)
}

fn nfproto(family: &str) -> Result<u8, String> {
    match family {
        "inet" => Ok(1),
        "ip" => Ok(2),
        "arp" => Ok(3),
        "netdev" => Ok(5),
        "bridge" => Ok(7),
        "ip6" => Ok(10),
        other => Err(format!("unknown nft family {other}")),
    }
}

fn next_addr(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut end = bytes.to_vec();
    for byte in end.iter_mut().rev() {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            return Some(end);
        }
    }
    None
}

fn build_add_batch(family: u8, table: &str, name: &str, start: &[u8], end: &[u8]) -> Vec<u8> {
    let mut batch = Vec::new();
    push_batch_marker(&mut batch, NFNL_MSG_BATCH_BEGIN);
    push_newsetelem(&mut batch, family, table, name, start, end);
    push_batch_marker(&mut batch, NFNL_MSG_BATCH_END);
    batch
}

fn push_batch_marker(buf: &mut Vec<u8>, kind: u16) {
    push_nlmsg(buf, kind, NLM_F_REQUEST, 0, NFNL_SUBSYS_NFTABLES, |_| {});
}

fn push_newsetelem(buf: &mut Vec<u8>, family: u8, table: &str, name: &str, start: &[u8], end: &[u8]) {
    let typ = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM;
    push_nlmsg(buf, typ, NLM_F_REQUEST | NLM_F_ACK, family, 0, |buf| {
        put_nla(buf, 1, c_string(table));
        put_nla(buf, 2, c_string(name));
        let elements = nest(buf, 3 | NLA_F_NESTED);
        put_interval(buf, start, false);
        put_interval(buf, end, true);
        nest_end(buf, elements);
    });
}

fn put_interval(buf: &mut Vec<u8>, addr: &[u8], interval_end: bool) {
    let elem = nest(buf, 1 | NLA_F_NESTED);
    if interval_end {
        put_nla(buf, 3, NFT_SET_ELEM_INTERVAL_END.to_be_bytes());
    }
    let key = nest(buf, 1 | NLA_F_NESTED);
    put_nla(buf, 1 | NLA_F_NET_BYTEORDER, addr);
    nest_end(buf, key);
    nest_end(buf, elem);
}

fn c_string(text: &str) -> Vec<u8> {
    let mut bytes = text.as_bytes().to_vec();
    bytes.push(0);
    bytes
}

fn push_nlmsg(
    buf: &mut Vec<u8>,
    typ: u16,
    flags: u16,
    family: u8,
    res_id: u16,
    body: impl FnOnce(&mut Vec<u8>),
) {
    let start = buf.len();
    buf.extend_from_slice(&0u32.to_ne_bytes());
    buf.extend_from_slice(&typ.to_ne_bytes());
    buf.extend_from_slice(&flags.to_ne_bytes());
    buf.extend_from_slice(&1u32.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes());
    buf.push(family);
    buf.push(0);
    buf.extend_from_slice(&res_id.to_be_bytes());
    body(buf);
    pad4(buf);
    let len = u32::try_from(buf.len() - start).unwrap_or(u32::MAX);
    buf[start..start + 4].copy_from_slice(&len.to_ne_bytes());
}

fn nest(buf: &mut Vec<u8>, typ: u16) -> usize {
    let start = buf.len();
    buf.extend_from_slice(&0u16.to_ne_bytes());
    buf.extend_from_slice(&typ.to_ne_bytes());
    start
}

fn nest_end(buf: &mut Vec<u8>, start: usize) {
    let len = u16::try_from(buf.len() - start).unwrap_or(u16::MAX);
    buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
}

fn put_nla(buf: &mut Vec<u8>, typ: u16, payload: impl AsRef<[u8]>) {
    let payload = payload.as_ref();
    let len = u16::try_from(4 + payload.len()).unwrap_or(u16::MAX);
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&typ.to_ne_bytes());
    buf.extend_from_slice(payload);
    pad4(buf);
}

fn pad4(buf: &mut Vec<u8>) {
    let pad = (4 - (buf.len() % 4)) % 4;
    buf.extend(std::iter::repeat_n(0, pad));
}

fn send_netlink(batch: &[u8]) -> Result<(), String> {
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_NETFILTER) };
    if fd < 0 {
        return Err(format!("netlink socket: {}", std::io::Error::last_os_error()));
    }
    let _guard = Close(fd);
    let mut addr = unsafe { std::mem::zeroed::<libc::sockaddr_nl>() };
    addr.nl_family = libc::AF_NETLINK as u16;
    let bound = unsafe {
        libc::bind(
            fd,
            (&raw const addr).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if bound < 0 {
        return Err(format!("netlink bind: {}", std::io::Error::last_os_error()));
    }
    let sent = unsafe {
        libc::send(
            fd,
            batch.as_ptr().cast(),
            batch.len(),
            0,
        )
    };
    if sent < 0 {
        return Err(format!("netlink send: {}", std::io::Error::last_os_error()));
    }
    let mut reply = [0u8; 1024];
    let got = unsafe { libc::recv(fd, reply.as_mut_ptr().cast(), reply.len(), 0) };
    if got < 0 {
        return Err(format!("netlink recv: {}", std::io::Error::last_os_error()));
    }
    parse_acks(&reply[..got as usize])
}

struct Close(i32);

impl Drop for Close {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

fn parse_acks(buf: &[u8]) -> Result<(), String> {
    let mut off = 0;
    let mut saw = false;
    while off + 16 <= buf.len() {
        let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        if len < 16 || off + len > buf.len() {
            break;
        }
        let typ = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
        if typ == NLMSG_ERROR {
            if off + 20 > buf.len() {
                return Err("short netlink error".to_string());
            }
            let err = i32::from_ne_bytes(buf[off + 16..off + 20].try_into().unwrap());
            if err != 0 && err != -libc::EEXIST {
                return Err(std::io::Error::from_raw_os_error(-err).to_string());
            }
            saw = true;
        }
        let step = (len + 3) & !3;
        if step == 0 {
            break;
        }
        off += step;
    }
    if saw {
        Ok(())
    } else {
        Err("netlink add was not acknowledged".to_string())
    }
}

fn v4_from_elem(elem: &Value) -> Option<(u32, u32)> {
    match elem {
        Value::String(text) => parse_v4_token(text),
        Value::Object(map) => {
            if let Some(prefix) = map.get("prefix") {
                return v4_from_elem(prefix);
            }
            if let Some(Value::Array(bounds)) = map.get("range") {
                return v4_range(&bounds[0], bounds.get(1)?);
            }
            if let Some(inner) = map.get("elem").or_else(|| map.get("val")) {
                return v4_from_elem(inner);
            }
            prefix_v4(map.get("addr")?.as_str()?, map.get("len")?)
        }
        _ => None,
    }
}

fn v6_from_elem(elem: &Value) -> Option<(u128, u128)> {
    match elem {
        Value::String(text) => parse_v6_token(text),
        Value::Object(map) => {
            if let Some(prefix) = map.get("prefix") {
                return v6_from_elem(prefix);
            }
            if let Some(Value::Array(bounds)) = map.get("range") {
                return v6_range(&bounds[0], bounds.get(1)?);
            }
            if let Some(inner) = map.get("elem").or_else(|| map.get("val")) {
                return v6_from_elem(inner);
            }
            prefix_v6(map.get("addr")?.as_str()?, map.get("len")?)
        }
        _ => None,
    }
}

fn parse_v4_token(text: &str) -> Option<(u32, u32)> {
    if let Some((addr, len)) = text.split_once('/') {
        return prefix_v4(addr, &Value::String(len.to_string()));
    }
    let ip: Ipv4Addr = text.parse().ok()?;
    let value = u32::from(ip);
    Some((value, value))
}

fn parse_v6_token(text: &str) -> Option<(u128, u128)> {
    if let Some((addr, len)) = text.split_once('/') {
        return prefix_v6(addr, &Value::String(len.to_string()));
    }
    let ip: Ipv6Addr = text.parse().ok()?;
    let value = u128::from(ip);
    Some((value, value))
}

fn prefix_v4(addr: &str, len: &Value) -> Option<(u32, u32)> {
    let ip: Ipv4Addr = addr.parse().ok()?;
    let len = json_u8(len)?;
    if len > 32 {
        return None;
    }
    let ip = u32::from(ip);
    if len == 0 {
        return Some((0, u32::MAX));
    }
    let mask = u32::MAX << (32 - len);
    let start = ip & mask;
    Some((start, start | !mask))
}

fn prefix_v6(addr: &str, len: &Value) -> Option<(u128, u128)> {
    let ip: Ipv6Addr = addr.parse().ok()?;
    let len = json_u8(len)?;
    if len > 128 {
        return None;
    }
    let ip = u128::from(ip);
    if len == 0 {
        return Some((0, u128::MAX));
    }
    let mask = u128::MAX << (128 - len);
    let start = ip & mask;
    Some((start, start | !mask))
}

fn v4_range(start: &Value, end: &Value) -> Option<(u32, u32)> {
    let start: Ipv4Addr = start.as_str()?.parse().ok()?;
    let end: Ipv4Addr = end.as_str()?.parse().ok()?;
    Some((u32::from(start), u32::from(end)))
}

fn v6_range(start: &Value, end: &Value) -> Option<(u128, u128)> {
    let start: Ipv6Addr = start.as_str()?.parse().ok()?;
    let end: Ipv6Addr = end.as_str()?.parse().ok()?;
    Some((u128::from(start), u128::from(end)))
}

fn json_u8(value: &Value) -> Option<u8> {
    match value {
        Value::Number(n) => n.as_u64().and_then(|n| u8::try_from(n).ok()),
        Value::String(text) => text.parse().ok(),
        _ => None,
    }
}

fn merge_u32(mut ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    ranges.sort_unstable();
    let mut out: Vec<(u32, u32)> = Vec::new();
    for (start, end) in ranges {
        if let Some(last) = out.last_mut() {
            if start <= last.1.saturating_add(1) {
                last.1 = last.1.max(end);
                continue;
            }
        }
        out.push((start, end));
    }
    out
}

fn merge_u128(mut ranges: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    ranges.sort_unstable();
    let mut out: Vec<(u128, u128)> = Vec::new();
    for (start, end) in ranges {
        if let Some(last) = out.last_mut() {
            if start <= last.1.saturating_add(1) {
                last.1 = last.1.max(end);
                continue;
            }
        }
        out.push((start, end));
    }
    out
}

fn contains_u32(ranges: &[(u32, u32)], ip: u32) -> bool {
    let idx = ranges.partition_point(|range| range.0 <= ip);
    idx > 0 && ip <= ranges[idx - 1].1
}

fn contains_u128(ranges: &[(u128, u128)], ip: u128) -> bool {
    let idx = ranges.partition_point(|range| range.0 <= ip);
    idx > 0 && ip <= ranges[idx - 1].1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nft_prefixes_and_ranges() {
        let json = r#"{"nftables":[{"set":{"elem":[
            {"prefix":{"addr":"1.1.8.0","len":24}},
            {"range":["1.80.0.0","1.92.255.255"]},
            "10.0.0.1"
        ]}}]}"#;
        let mut ranges = Vec::new();
        for elem in nft_elements(json).unwrap() {
            ranges.push(v4_from_elem(&elem).unwrap());
        }
        let set = Interval4 {
            ranges: merge_u32(ranges),
        };
        assert!(set.contains("1.1.8.9".parse().unwrap()));
        assert!(!set.contains("1.1.9.1".parse().unwrap()));
        assert!(set.contains("1.80.1.1".parse().unwrap()));
        assert!(set.contains("10.0.0.1".parse().unwrap()));
        assert!(!set.contains("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn interval_batch_matches_chinadns() {
        let start = [192u8, 0, 2, 8];
        let end = next_addr(&start).unwrap();
        assert_eq!(end, vec![192, 0, 2, 9]);
        let batch = build_add_batch(1, "passwall", "psw_chn", &start, &end);
        assert!(batch.windows(4).any(|window| window == start));
        assert!(batch.windows(4).any(|window| window == [192, 0, 2, 9]));
        assert!(batch.windows(4).any(|window| window == 1u32.to_be_bytes()));
        assert!(next_addr(&[255, 255, 255, 255]).is_none());
    }
}
