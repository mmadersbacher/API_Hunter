use openssl::ssl::{SslConnector, SslMethod};
use std::net::ToSocketAddrs;

pub fn get_tls_issuer(host: &str) -> Option<String> {
    // Connect to host:443 and obtain certificate issuer CN
    let addr = format!("{}:443", host);
    let addrs = addr.to_socket_addrs().ok()?;
    let sock = addrs.into_iter().next()?;

    let connector = SslConnector::builder(SslMethod::tls()).ok()?.build();
    if let Ok(stream) = std::net::TcpStream::connect(sock) {
        if let Ok(mut ssl_stream) = connector.connect(host, stream) {
            if let Ok(cert) = ssl_stream.ssl().peer_certificate() {
                if let Some(issuer) = cert.issuer_name().entries().next() {
                    return issuer.data().as_utf8().ok().map(|s| s.to_string());
                }
            }
        }
    }
    None
}
