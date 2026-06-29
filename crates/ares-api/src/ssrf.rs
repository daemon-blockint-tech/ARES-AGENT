use std::net::IpAddr;

/// Validate a webhook URL to prevent SSRF attacks.
///
/// Checks:
/// 1. Scheme is http or https
/// 2. Host is not a literal internal/localhost IP
/// 3. DNS resolution does not resolve to internal/localhost IP (prevents DNS rebinding)
pub async fn validate_webhook_url(url: &str) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("Invalid URL: {}", e))?;

    match parsed.scheme() {
        "http" | "https" => {}
        other => return Err(format!("Webhook URL must be http or https, got: {}", other)),
    }

    let host = parsed.host_str().ok_or("URL has no host")?;

    // Check literal IP first (fast path)
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_internal_ip(&ip) {
            return Err(
                "Webhook URL must not point to internal or localhost addresses".to_string(),
            );
        }
        return Ok(());
    }

    // DNS resolution to prevent rebinding attacks
    let port = parsed.port_or_known_default().unwrap_or(80);
    let addr_str = format!("{}:{}", host, port);
    let addrs = tokio::net::lookup_host(&addr_str)
        .await
        .map_err(|e| format!("DNS resolution failed for {}: {}", host, e))?;

    for addr in addrs {
        let ip = addr.ip();
        if is_internal_ip(&ip) {
            return Err(format!(
                "Webhook URL host {} resolves to internal IP {} — SSRF blocked",
                host, ip
            ));
        }
    }

    Ok(())
}

/// Check if an IP address is internal/loopback/link-local.
fn is_internal_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.octets()[0] == 169 && v4.octets()[1] == 254 // 169.254.x.x
                || v4.octets()[0] == 100 && v4.octets()[1] >= 64 && v4.octets()[1] <= 127
            // CGNAT 100.64/10
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_internal_ipv4() {
        assert!(is_internal_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_internal_ip(&"10.0.0.1".parse().unwrap()));
        assert!(is_internal_ip(&"192.168.1.1".parse().unwrap()));
        assert!(is_internal_ip(&"172.16.0.1".parse().unwrap()));
        assert!(is_internal_ip(&"169.254.169.254".parse().unwrap()));
        assert!(is_internal_ip(&"0.0.0.0".parse().unwrap()));
        assert!(is_internal_ip(&"100.64.0.1".parse().unwrap()));

        assert!(!is_internal_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_internal_ip(&"1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn test_internal_ipv6() {
        assert!(is_internal_ip(&"::1".parse().unwrap()));
        assert!(is_internal_ip(&"fe80::1".parse().unwrap()));
        assert!(is_internal_ip(&"fc00::1".parse().unwrap()));

        assert!(!is_internal_ip(&"2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn test_is_internal_ip_broadcast() {
        assert!(is_internal_ip(&"255.255.255.255".parse().unwrap()));
    }
}
