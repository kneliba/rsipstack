use super::{connection::TransportSender, SipAddr, SipConnection};
use crate::{
    transport::transport_layer::TransportLayerInnerRef,
    transport::{
        connection::{KEEPALIVE_REQUEST, KEEPALIVE_RESPONSE, MAX_UDP_BUF_SIZE},
        TransportEvent,
    },
    Result,
};
use bytes::BytesMut;
use socket2::{Domain, Protocol, Socket, Type};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};
pub struct UdpInner {
    pub conn: UdpSocket,
    pub addr: SipAddr,
}

#[derive(Clone)]
pub struct UdpConnection {
    pub external: Option<SipAddr>,
    remote: Option<SipAddr>,
    cancel_token: Option<CancellationToken>,
    inner: Arc<UdpInner>,
    pmtu_mode: Arc<tokio::sync::Mutex<Option<pmtu::Mode>>>,
}

impl UdpConnection {
    pub async fn attach(
        inner: UdpInner,
        external: Option<SocketAddr>,
        cancel_token: Option<CancellationToken>,
    ) -> Self {
        UdpConnection {
            external: external.map(|addr| SipAddr {
                r#type: Some(crate::sip::transport::Transport::Udp),
                addr: SipConnection::resolve_bind_address(addr).into(),
            }),
            remote: None,
            inner: Arc::new(inner),
            cancel_token,
            pmtu_mode: Arc::default(),
        }
    }

    pub async fn create_connection(
        local: SocketAddr,
        external: Option<SocketAddr>,
        cancel_token: Option<CancellationToken>,
    ) -> Result<Self> {
        let domain = if local.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        match socket.set_reuse_address(true) {
            Ok(_) => (),
            Err(e) => {
                warn!(error = %e, "Failed to set SO_REUSEADDR on UDP socket");
            }
        }
        socket.set_nonblocking(true)?;
        socket.bind(&local.into())?;
        let conn = UdpSocket::from_std(socket.into())?;

        let addr = SipAddr {
            r#type: Some(crate::sip::transport::Transport::Udp),
            addr: SipConnection::resolve_bind_address(conn.local_addr()?).into(),
        };

        let t = UdpConnection {
            external: external.map(|addr| SipAddr {
                r#type: Some(crate::sip::transport::Transport::Udp),
                addr: addr.into(),
            }),
            remote: None,
            inner: Arc::new(UdpInner { addr, conn }),
            cancel_token,
            pmtu_mode: Arc::default(),
        };
        debug!(local = %t, ?external, "created UDP connection");
        Ok(t)
    }

    pub async fn serve_loop(&self, sender: TransportSender) -> Result<()> {
        self.serve_loop_with_whitelist(sender, None).await
    }

    pub async fn serve_loop_with_whitelist(
        &self,
        sender: TransportSender,
        transport_layer_inner: Option<TransportLayerInnerRef>,
    ) -> Result<()> {
        let mut buf = BytesMut::with_capacity(MAX_UDP_BUF_SIZE);
        buf.resize(MAX_UDP_BUF_SIZE, 0);
        loop {
            let (len, addr) = tokio::select! {
                // Check for cancellation on each iteration
                _ = async {
                    if let Some(ref cancel_token) = self.cancel_token {
                        cancel_token.cancelled().await;
                    } else {
                        // If no cancel token, wait forever
                        std::future::pending::<()>().await;
                    }
                } => {
                    debug!(local = %self.get_addr(), "UDP serve_loop cancelled");
                    return Ok(());
                }
                // Receive UDP packets
                result = self.inner.conn.recv_from(&mut buf) => {
                    match result {
                        Ok((len, addr)) => (len, addr),
                        Err(e) => {
                            warn!(error = %e, "error receiving UDP packet");
                            continue;
                        }
                    }
                }
            };

            if let Some(transport_layer_inner) = &transport_layer_inner {
                if !transport_layer_inner.is_whitelisted(addr.ip()).await {
                    debug!(src = %addr, "udp packet rejected by whitelist");
                    continue;
                }
            }

            let packet = &buf[..len];

            match packet {
                KEEPALIVE_REQUEST => {
                    self.inner.conn.send_to(KEEPALIVE_RESPONSE, addr).await.ok();
                    continue;
                }
                KEEPALIVE_RESPONSE => continue,
                _ => {
                    if packet.iter().all(|&b| b.is_ascii_whitespace()) {
                        continue;
                    }
                }
            }

            let raw_message = String::from_utf8_lossy(packet);

            let msg = match crate::sip::SipMessage::try_from(packet) {
                Ok(msg) => msg,
                Err(e) => {
                    debug!(
                        src = %addr,
                        error = %e,
                        raw_message = %raw_message,
                        "error parsing SIP message"
                    );
                    continue;
                }
            };

            let msg = match SipConnection::update_msg_received(
                msg,
                addr,
                crate::sip::transport::Transport::Udp,
            ) {
                Ok(msg) => msg,
                Err(e) => {
                    debug!(
                        src = %addr,
                        error = ?e,
                        raw_message = %raw_message,
                        "error updating SIP via"
                    );
                    continue;
                }
            };

            debug!(len, src=%addr, dest=%self.get_addr(), raw_message = %raw_message, "udp received");

            let from = SipAddr {
                r#type: Some(crate::sip::transport::Transport::Udp),
                addr: addr.into(),
            };

            sender.send(TransportEvent::Incoming(
                msg,
                SipConnection::Udp(Self {
                    external: self.external.clone(),
                    remote: Some(from.clone()),
                    cancel_token: self.cancel_token.clone(),
                    inner: self.inner.clone(),
                    pmtu_mode: self.pmtu_mode.clone(),
                }),
                from,
            ))?;
        }
    }

    pub async fn send(
        &self,
        msg: crate::sip::SipMessage,
        destination: Option<&SipAddr>,
    ) -> crate::Result<()> {
        let destination = match destination {
            Some(addr) => addr.get_socketaddr(),
            None => SipConnection::get_destination(&msg),
        }?;
        // Use to_bytes() (not to_string()) so binary bodies are preserved
        // byte-for-byte; a SIP body is opaque octets (RFC 3261 §7.4).
        let buf = msg.to_bytes();

        debug!(len=buf.len(), dest=%destination, src=%self.get_addr(), raw_message=%msg, "udp send");

        self.send_to(&buf, destination).await
    }

    pub async fn send_raw(&self, buf: &[u8], destination: &SipAddr) -> Result<()> {
        self.send_to(buf, destination.get_socketaddr()?).await
    }

    async fn send_to(&self, buf: &[u8], destination: SocketAddr) -> Result<()> {
        let mut mode = self.pmtu_mode.lock().await;
        if destination.is_ipv4() {
            let wanted = pmtu::Mode::for_ipv4_payload(buf.len());
            if *mode != Some(wanted) {
                if let Err(e) = pmtu::set(&self.inner.conn, wanted) {
                    warn!(error = %e, ?wanted, "failed to set UDP path MTU discovery mode");
                }
                *mode = Some(wanted);
            }
        }
        self.inner
            .conn
            .send_to(buf, destination)
            .await
            .map_err(|e| {
                crate::Error::TransportLayerError(e.to_string(), self.get_addr().to_owned())
            })
            .map(|_| ())
    }

    pub async fn recv_raw(&self, buf: &mut [u8]) -> Result<(usize, SipAddr)> {
        let (len, addr) = self.inner.conn.recv_from(buf).await?;
        Ok((
            len,
            SipAddr {
                r#type: Some(crate::sip::transport::Transport::Udp),
                addr: addr.into(),
            },
        ))
    }

    pub fn get_addr(&self) -> &SipAddr {
        if let Some(external) = &self.external {
            external
        } else {
            &self.inner.addr
        }
    }

    pub fn get_remote_addr(&self) -> Option<&SipAddr> {
        self.remote.as_ref()
    }

    pub fn cancel_token(&self) -> Option<CancellationToken> {
        self.cancel_token.clone()
    }
}

impl std::fmt::Display for UdpConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.inner.conn.local_addr() {
            Ok(addr) => write!(f, "{}", addr),
            Err(_) => write!(f, "*:*"),
        }
    }
}

impl std::fmt::Debug for UdpConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner.addr)
    }
}

impl Drop for UdpInner {
    fn drop(&mut self) {
        debug!(addr = %self.addr, "dropping UDP transport");
    }
}

// GTP gateways black-hole DF datagrams just under 1500; larger ones keep DF so PMTU is still learned.
mod pmtu {
    use tokio::net::UdpSocket;

    const MAX_UNFRAGMENTED_IP_LEN: usize = 1500;
    const IPV4_UDP_HEADER_LEN: usize = 20 + 8;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Mode {
        Dont,
        Want,
    }

    impl Mode {
        pub(super) fn for_ipv4_payload(len: usize) -> Self {
            if len + IPV4_UDP_HEADER_LEN <= MAX_UNFRAGMENTED_IP_LEN {
                Mode::Dont
            } else {
                Mode::Want
            }
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn set(socket: &UdpSocket, mode: Mode) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;

        let val: libc::c_int = match mode {
            Mode::Dont => libc::IP_PMTUDISC_DONT,
            Mode::Want => libc::IP_PMTUDISC_WANT,
        };
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                (&raw const val).cast(),
                std::mem::size_of_val(&val) as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn set(_socket: &UdpSocket, _mode: Mode) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dont_fragment_only_above_1500_ip_bytes() {
        assert_eq!(pmtu::Mode::for_ipv4_payload(1472), pmtu::Mode::Dont);
        assert_eq!(pmtu::Mode::for_ipv4_payload(1473), pmtu::Mode::Want);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn send_toggles_path_mtu_discovery_by_size() -> Result<()> {
        use std::os::fd::AsRawFd;

        fn mtu_discover(conn: &UdpConnection) -> libc::c_int {
            let mut val: libc::c_int = -1;
            let mut len = std::mem::size_of_val(&val) as libc::socklen_t;
            let rc = unsafe {
                libc::getsockopt(
                    conn.inner.conn.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_MTU_DISCOVER,
                    (&raw mut val).cast(),
                    &raw mut len,
                )
            };
            assert_eq!(rc, 0);
            val
        }

        let conn = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
        let peer = UdpSocket::bind("127.0.0.1:0").await?;
        let dest = SipAddr {
            r#type: Some(crate::sip::transport::Transport::Udp),
            addr: peer.local_addr()?.into(),
        };

        conn.send_raw(&[b'x'; 1472], &dest).await?;
        assert_eq!(mtu_discover(&conn), libc::IP_PMTUDISC_DONT);
        conn.send_raw(&[b'x'; 1473], &dest).await?;
        assert_eq!(mtu_discover(&conn), libc::IP_PMTUDISC_WANT);
        conn.send_raw(&[b'x'; 100], &dest).await?;
        assert_eq!(mtu_discover(&conn), libc::IP_PMTUDISC_DONT);
        Ok(())
    }
}
