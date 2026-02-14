//! Client IP extraction utilities
//!
//! Shared by device registration, login, and rate limiting.
//! Uses the most robust implementation with CF-Connecting-IP support
//! and rightmost non-private X-Forwarded-For parsing.

use axum::http::HeaderMap;

/// Log a startup warning about client IP header trust requirements.
///
/// Call this once during server initialization to remind operators that
/// the server trusts proxy-set headers for client IP extraction.
pub fn warn_if_no_trusted_proxy() {
    tracing::warn!(
        "Client IP extraction trusts CF-Connecting-IP, X-Real-IP, and X-Forwarded-For headers. \
         Ensure a reverse proxy (Cloudflare, nginx, etc.) strips or overwrites these headers \
         from raw client requests. Without a trusted proxy, clients can spoof their IP address."
    );
}

/// Extract client IP from request headers.
///
/// Priority: CF-Connecting-IP > X-Real-IP > X-Forwarded-For (rightmost non-private)
///
/// # Security
///
/// **WARNING**: This function trusts the values in proxy headers unconditionally.
/// If the server is exposed directly to clients without a reverse proxy that
/// strips/overwrites these headers, clients can spoof their IP address.
/// Always deploy behind a trusted reverse proxy in production.
pub fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    // Try CF-Connecting-IP (Cloudflare - most trusted)
    if let Some(cf_ip) = headers.get("cf-connecting-ip")
        && let Ok(value) = cf_ip.to_str()
    {
        let ip = value.trim();
        if is_valid_ip(ip) {
            return Some(ip.to_string());
        }
    }

    // Try X-Real-IP (nginx - single IP, trusted)
    if let Some(xri) = headers.get("x-real-ip")
        && let Ok(value) = xri.to_str()
    {
        let ip = value.trim();
        if is_valid_ip(ip) {
            return Some(ip.to_string());
        }
    }

    // Try X-Forwarded-For (take rightmost non-private IP for better security)
    // The rightmost IP is the one added by the closest trusted proxy
    if let Some(xff) = headers.get("x-forwarded-for")
        && let Ok(value) = xff.to_str()
    {
        // Split and reverse to get rightmost first
        for ip in value.split(',').rev() {
            let ip = ip.trim();
            if is_valid_ip(ip) && !is_private_ip(ip) {
                return Some(ip.to_string());
            }
        }
        // If all IPs are private, take the leftmost (original client)
        if let Some(ip) = value.split(',').next() {
            let ip = ip.trim();
            if is_valid_ip(ip) {
                return Some(ip.to_string());
            }
        }
    }

    None
}

/// Basic IP address validation
fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().is_ok()
}

/// Check if IP is a private/reserved address
fn is_private_ip(ip: &str) -> bool {
    if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
        match addr {
            std::net::IpAddr::V4(ipv4) => {
                ipv4.is_private()
                    || ipv4.is_loopback()
                    || ipv4.is_link_local()
                    || ipv4.is_unspecified()
            }
            std::net::IpAddr::V6(ipv6) => ipv6.is_loopback() || ipv6.is_unspecified(),
        }
    } else {
        false
    }
}
