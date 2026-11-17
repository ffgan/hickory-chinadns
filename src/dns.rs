use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record};

use crate::config::Error;

pub fn parse(packet: &[u8]) -> Result<Message, Error> {
    Message::from_vec(packet).map_err(|err| Error::msg(format!("dns parse: {err}")))
}

pub fn encode(message: &Message) -> Result<Vec<u8>, Error> {
    message
        .to_vec()
        .map_err(|err| Error::msg(format!("dns encode: {err}")))
}

pub fn set_id(packet: &mut [u8], id: u16) {
    if packet.len() >= 2 {
        packet[..2].copy_from_slice(&id.to_be_bytes());
    }
}

pub fn nodata(query: &Message) -> Result<Vec<u8>, Error> {
    let mut message = Message::response(query.metadata.id, query.metadata.op_code);
    message.metadata.recursion_desired = query.metadata.recursion_desired;
    message.metadata.recursion_available = true;
    message.metadata.response_code = ResponseCode::NoError;
    if let Some(question) = query.queries.first() {
        message.add_query(question.clone());
    }
    encode(&message)
}

pub fn failure(query: &Message, code: ResponseCode) -> Vec<u8> {
    let mut message = Message::error_msg(query.metadata.id, query.metadata.op_code, code);
    message.metadata.recursion_desired = query.metadata.recursion_desired;
    message.metadata.recursion_available = true;
    if let Some(question) = query.queries.first() {
        message.add_query(question.clone());
    }
    encode(&message).unwrap_or_else(|_| {
        let bare = Message::error_msg(query.metadata.id, OpCode::Query, code);
        encode(&bare).unwrap_or_default()
    })
}

pub fn hosts_answer(query: &Message, v4: &[Ipv4Addr], v6: &[Ipv6Addr]) -> Result<Vec<u8>, Error> {
    let question = query
        .queries
        .first()
        .ok_or_else(|| Error::msg("missing question"))?;
    let mut message = Message::response(query.metadata.id, query.metadata.op_code);
    message.metadata.recursion_desired = query.metadata.recursion_desired;
    message.metadata.recursion_available = true;
    message.metadata.authoritative = true;
    message.add_query(question.clone());
    match question.query_type() {
        hickory_proto::rr::RecordType::A => {
            for ip in v4 {
                message.add_answer(Record::from_rdata(
                    question.name().clone(),
                    60,
                    RData::A(A(*ip)),
                ));
            }
        }
        hickory_proto::rr::RecordType::AAAA => {
            for ip in v6 {
                message.add_answer(Record::from_rdata(
                    question.name().clone(),
                    60,
                    RData::AAAA(AAAA(*ip)),
                ));
            }
        }
        _ => {}
    }
    encode(&message)
}

pub fn answer_addrs(message: &Message) -> Vec<IpAddr> {
    message
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(ip) => Some(IpAddr::V4(ip.0)),
            RData::AAAA(ip) => Some(IpAddr::V6(ip.0)),
            _ => None,
        })
        .collect()
}

pub fn qname(message: &Message) -> Option<String> {
    message.queries.first().map(|query| normalize(query.name()))
}

pub fn normalize(name: &Name) -> String {
    name.to_utf8().trim_end_matches('.').to_ascii_lowercase()
}
