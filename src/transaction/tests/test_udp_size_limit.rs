use crate::sip::{headers::*, Method, Request, Uri, Version};
use crate::transaction::key::{TransactionKey, TransactionRole};
use crate::transaction::transaction::Transaction;
use crate::Result;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

const LIMIT: usize = 1300;
const UDP_VIA: &str = "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKsizelimit";
const TCP_VIA: &str = "Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bKsizelimit";

fn make_request(port: u16, body_len: usize) -> Result<Request> {
    Ok(Request {
        method: Method::Invite,
        uri: Uri::try_from(format!("sip:bob@127.0.0.1:{port}").as_str())?,
        headers: vec![
            Via::new("SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKsizelimit;rport").into(),
            CSeq::new("1 INVITE").into(),
            From::new("<sip:alice@example.com>;tag=from-tag").into(),
            To::new("<sip:bob@example.com>").into(),
            CallId::new("sizelimit@example.com").into(),
            MaxForwards::new("70").into(),
        ]
        .into(),
        version: Version::V2,
        body: vec![b'x'; body_len],
    })
}

async fn send(port: u16, body_len: usize) -> Result<Transaction> {
    let endpoint = super::create_test_endpoint(Some("127.0.0.1:0")).await?;
    let req = make_request(port, body_len)?;
    let key = TransactionKey::from_request(&req, TransactionRole::Client)?;
    let mut tx = Transaction::new_client(key, req, endpoint.inner.clone(), None);
    tx.max_udp_request_size = Some(LIMIT);
    tx.send().await?;
    Ok(tx)
}

async fn recv_udp(socket: &UdpSocket) -> String {
    let mut buf = vec![0; 65535];
    let (len, _) = timeout(Duration::from_secs(1), socket.recv_from(&mut buf))
        .await
        .expect("udp datagram")
        .expect("udp recv");
    String::from_utf8_lossy(&buf[..len]).into_owned()
}

#[tokio::test]
async fn large_request_goes_over_tcp_with_tcp_via() -> Result<()> {
    let tcp = TcpListener::bind("127.0.0.1:0").await?;
    let port = tcp.local_addr()?.port();
    let udp = UdpSocket::bind(("127.0.0.1", port)).await?;

    let tx = send(port, LIMIT).await?;
    assert!(tx.connection.as_ref().is_some_and(|c| c.is_reliable()));
    assert!(tx.timer_a.is_none(), "no retransmissions over TCP");
    assert!(tx.original.to_string().contains(TCP_VIA));

    let (mut stream, _) = timeout(Duration::from_secs(1), tcp.accept())
        .await
        .expect("tcp connect")?;
    let mut received = Vec::new();
    while !received.ends_with(&[b'x'; LIMIT]) {
        let mut chunk = [0; 4096];
        let n = timeout(Duration::from_secs(1), stream.read(&mut chunk))
            .await
            .expect("tcp data")?;
        assert_ne!(n, 0, "tcp closed early");
        received.extend_from_slice(&chunk[..n]);
    }
    let received = String::from_utf8_lossy(&received);
    assert!(received.starts_with("INVITE sip:bob@127.0.0.1"));
    assert!(received.contains(TCP_VIA));

    let mut buf = [0; 16];
    assert!(
        udp.try_recv_from(&mut buf).is_err(),
        "nothing sent over UDP"
    );
    Ok(())
}

#[tokio::test]
async fn large_request_falls_back_to_udp_without_tcp() -> Result<()> {
    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    let port = udp.local_addr()?.port();

    let tx = send(port, LIMIT).await?;
    assert!(tx.connection.as_ref().is_some_and(|c| !c.is_reliable()));
    assert!(tx.timer_a.is_some(), "UDP keeps retransmitting");
    assert!(recv_udp(&udp).await.contains(UDP_VIA));
    Ok(())
}

#[tokio::test]
async fn small_request_stays_on_udp() -> Result<()> {
    let tcp = TcpListener::bind("127.0.0.1:0").await?;
    let port = tcp.local_addr()?.port();
    let udp = UdpSocket::bind(("127.0.0.1", port)).await?;

    let tx = send(port, 10).await?;
    assert!(tx.connection.as_ref().is_some_and(|c| !c.is_reliable()));
    assert!(recv_udp(&udp).await.contains(UDP_VIA));
    assert!(
        timeout(Duration::from_millis(100), tcp.accept())
            .await
            .is_err(),
        "no TCP connection"
    );
    Ok(())
}
