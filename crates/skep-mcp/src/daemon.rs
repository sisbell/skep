//! The daemon side: the adapter's principal, its at-most-one live session
//! token, and the one resend. Every field is private. The endpoint and the
//! principal are set at construction and only read after it, so a token is
//! only ever sent to the address that issued it, for the principal it was
//! opened for. Only `open_session` stores a token and only `op` reads one,
//! to pass as the `Skepd-Session` header `Http::request` writes: no tool
//! answer or log line can carry it.

use serde_json::Value;

use crate::http::Http;

/// The daemon-side state: one principal, at most one live token. Every
/// method returns `Err(String)` ONLY when skepd could not be reached;
/// whatever document the daemon answered — rejections included — is an
/// `Ok` payload.
pub struct Skepd {
    http: Http,
    principal: u64,
    token: Option<String>,
}

impl Skepd {
    /// No session yet: the first write the daemon answers `unauthenticated`
    /// opens one.
    pub fn new(http: Http, principal: u64) -> Skepd {
        Skepd { http, principal, token: None }
    }

    /// The endpoint every exchange goes to, fixed for the adapter's life.
    pub fn http(&self) -> &Http {
        &self.http
    }

    /// The principal this adapter binds, fixed for the adapter's life.
    pub fn principal(&self) -> u64 {
        self.principal
    }

    /// POST one frame to `/op`; hand back the daemon's document verbatim.
    /// On `unauthenticated` — the daemon's own signal that this write needs
    /// a session the adapter doesn't hold (never opened, or the daemon
    /// restarted and the token died with the process) — open a session and
    /// resend once. The rejected attempt executed nothing, so the resend
    /// cannot double-apply; a second `unauthenticated` passes through as
    /// data like any other rejection. This is the only retry anywhere.
    pub fn op(&mut self, frame: &[u8]) -> Result<Vec<u8>, String> {
        let (_, body) = self.http.request("POST", "/op", self.token.as_deref(), frame)?;
        if !is_unauthenticated(&body) {
            return Ok(body);
        }
        self.open_session()?;
        let (_, body) = self.http.request("POST", "/op", self.token.as_deref(), frame)?;
        Ok(body)
    }

    /// `POST /session` for the configured principal. Local trust: the
    /// principal is named, not proven (wire.md §Identity).
    fn open_session(&mut self) -> Result<(), String> {
        let body = format!("{{\"principal\":{}}}", self.principal);
        let (status, resp) = self.http.request("POST", "/session", None, body.as_bytes())?;
        if status != 200 {
            return Err(format!(
                "session open for principal {} failed ({status}): {}",
                self.principal,
                String::from_utf8_lossy(&resp)
            ));
        }
        let v: Value = serde_json::from_slice(&resp)
            .map_err(|e| format!("session response is not JSON: {e}"))?;
        let token =
            v["session"].as_str().ok_or_else(|| format!("session response has no token: {v}"))?;
        self.token = Some(token.to_string());
        eprintln!("skep-mcp: session opened (principal {})", self.principal);
        Ok(())
    }
}

/// The one response shape the adapter reads instead of forwarding blind:
/// the daemon's "you hold no live session" verdict, the cue to (re)open
/// and resend. Reads never carry it (they are principal-free), so no
/// read/write classification lives in this binary.
fn is_unauthenticated(body: &[u8]) -> bool {
    match serde_json::from_slice::<Value>(body) {
        Ok(v) => v["resp"] == "rejected" && v["code"] == "unauthenticated",
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The resend trigger is exact: the `unauthenticated` rejection and
    /// nothing else — not other rejections, not acks, not non-JSON.
    #[test]
    fn unauthenticated_detection_is_exact() {
        assert!(is_unauthenticated(
            br#"{"code":"unauthenticated","disposition":"permanent","op":"insert","resp":"rejected"}"#
        ));
        assert!(!is_unauthenticated(br#"{"at":7,"resp":"ack"}"#));
        assert!(!is_unauthenticated(
            br#"{"code":"not_owner","disposition":"permanent","op":"insert","resp":"rejected"}"#
        ));
        assert!(!is_unauthenticated(b"not json"));
    }
}
