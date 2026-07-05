use crate::{
    sip::SipMessage,
    transport::{
        connection::{KEEPALIVE_REQUEST, KEEPALIVE_RESPONSE},
        udp::UdpConnection,
        TransportEvent,
    },
    Result,
};
use std::time::Duration;
use tokio::{select, sync::mpsc::unbounded_channel, time::sleep};

#[tokio::test]
async fn test_udp_keepalive() -> Result<()> {
    let peer_bob = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    let peer_alice = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    let (alice_tx, _) = unbounded_channel::<TransportEvent>();

    let bob_loop = async {
        sleep(Duration::from_millis(20)).await; // wait for serve_loop to start
                                                // send keep alive
        peer_bob
            .send_raw(KEEPALIVE_REQUEST, peer_alice.get_addr())
            .await
            .expect("send_raw");
        // wait for keep alive response
        let buf = &mut [0u8; 2048];
        let (n, _) = peer_bob.recv_raw(buf).await.expect("recv_raw");
        assert_eq!(&buf[..n], KEEPALIVE_RESPONSE);
    };

    select! {
        _ = peer_alice.serve_loop(alice_tx) => {
            assert!(false, "serve_loop exited");
        }
        _ = bob_loop => {}
        _= sleep(Duration::from_millis(200)) => {
            assert!(false, "timeout waiting for keep alive response");
        }
    };
    Ok(())
}

#[tokio::test]
async fn test_udp_recv_sip_message() -> Result<()> {
    let peer_bob = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    let peer_alice = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    let (alice_tx, _) = unbounded_channel();
    let (bob_tx, mut bob_rx) = unbounded_channel();

    let send_loop = async {
        sleep(Duration::from_millis(20)).await; // wait for serve_loop to start
        let msg_1 = "REGISTER sip:bob@restsend.com SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bKnashd92\r\nCSeq: 1 REGISTER\r\n\r\n";
        peer_alice
            .send_raw(msg_1.as_bytes(), peer_bob.get_addr())
            .await
            .expect("send_raw");
        sleep(Duration::from_secs(3)).await;
    };

    select! {
        _ = peer_alice.serve_loop(alice_tx) => {
            assert!(false, "alice serve_loop exited");
        }
        _ = peer_bob.serve_loop(bob_tx) => {
            assert!(false, "bob serve_loop exited");
        }
        _ = send_loop => {
            assert!(false, "send_loop exited");
        }
        event = bob_rx.recv() => {
            match event {
                Some(TransportEvent::Incoming(msg, connection, from)) => {
                    assert!(msg.is_request());
                    assert_eq!(from, peer_alice.get_addr().to_owned());
                    assert_eq!(connection.get_addr(), peer_bob.get_addr());
                    assert_eq!(connection.get_remote_addr(), Some(peer_alice.get_addr()));
                }
                _ => {
                    assert!(false, "unexpected event");
                }
            }
        }
        _= sleep(Duration::from_millis(500)) => {
            assert!(false, "timeout waiting");
        }
    };
    Ok(())
}

// A SIP body is opaque octets (RFC 3261 §7.4) and may not be valid UTF-8, e.g.
// application/vnd.3gpp.sms. Such messages must still be received over UDP.
#[tokio::test]
async fn test_udp_recv_binary_body() -> Result<()> {
    let peer_bob = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    let peer_alice = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    let (alice_tx, _) = unbounded_channel();
    let (bob_tx, mut bob_rx) = unbounded_channel();

    // 0x91 is an invalid UTF-8 lead byte, so from_utf8 over the whole datagram would fail.
    let body: [u8; 3] = [0x00, 0x91, 0x01];

    let send_loop = async {
        sleep(Duration::from_millis(20)).await; // wait for serve_loop to start
        let headers = "MESSAGE sip:bob@restsend.com SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bKbinbody\r\nCSeq: 1 MESSAGE\r\nContent-Type: application/vnd.3gpp.sms\r\nContent-Length: 3\r\n\r\n";
        let mut datagram = headers.as_bytes().to_vec();
        datagram.extend_from_slice(&body);
        peer_alice
            .send_raw(&datagram, peer_bob.get_addr())
            .await
            .expect("send_raw");
        sleep(Duration::from_secs(3)).await;
    };

    select! {
        _ = peer_alice.serve_loop(alice_tx) => {
            assert!(false, "alice serve_loop exited");
        }
        _ = peer_bob.serve_loop(bob_tx) => {
            assert!(false, "bob serve_loop exited");
        }
        _ = send_loop => {
            assert!(false, "send_loop exited");
        }
        event = bob_rx.recv() => {
            match event {
                Some(TransportEvent::Incoming(SipMessage::Request(req), _, _)) => {
                    assert_eq!(req.body(), &body, "binary body not preserved");
                }
                _ => {
                    assert!(false, "message with binary body was dropped");
                }
            }
        }
        _= sleep(Duration::from_millis(500)) => {
            assert!(false, "timeout: binary-body message never received");
        }
    };
    Ok(())
}
