//! A minimal HTTP/1.1 client over a Unix socket: enough for the VMM REST APIs,
//! which take small JSON bodies and answer one request per connection.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crate::error::{Error, Result};

/// Largest response body accepted (API errors are a few hundred bytes).
const MAX_BODY: u64 = 1 << 20;
/// Largest status or header line accepted, and most headers.
const MAX_LINE: u64 = 8192;
const MAX_HEADERS: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Response {
    pub status: u16,
    pub body: String,
}

/// Sends one request with an optional JSON body and reads the response. A socket failure
/// (including the VMM closing the connection) is `Error::Io`; an answer that is not valid
/// HTTP is `Error::Http`.
pub(crate) fn request(socket: &Path, method: &str, path: &str, body: Option<&serde_json::Value>) -> Result<Response> {
    exchange(socket, method, path, body).map_err(|e| match e.kind() {
        io::ErrorKind::InvalidData => Error::Http(e.to_string()),
        _ => Error::Io(e),
    })
}

fn exchange(socket: &Path, method: &str, path: &str, body: Option<&serde_json::Value>) -> io::Result<Response> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let body = body.map(|b| b.to_string()).unwrap_or_default();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n");
    if !body.is_empty() {
        req.push_str("Content-Type: application/json\r\n");
    }
    req.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    stream.write_all(req.as_bytes())?;
    read_response(BufReader::new(stream))
}

/// A response that is not valid HTTP (becomes `Error::Http`).
fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// The peer closed the connection mid-response (stays `Error::Io`: the VMM may have died).
fn closed(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, msg)
}

/// Reads one line of at most `MAX_LINE` bytes; a longer one is an error.
fn read_line(r: &mut impl BufRead, line: &mut String) -> io::Result<usize> {
    let n = (&mut *r).take(MAX_LINE).read_line(line)?;
    if n as u64 == MAX_LINE && !line.ends_with('\n') {
        return Err(bad("response line too long"));
    }
    Ok(n)
}

fn read_response(mut r: impl BufRead) -> io::Result<Response> {
    let mut line = String::new();
    if read_line(&mut r, &mut line)? == 0 {
        return Err(closed("connection closed before a response"));
    }
    let mut fields = line.split_whitespace();
    let status = fields
        .next()
        .filter(|v| v.starts_with("HTTP/1."))
        .and(fields.next())
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| bad(format!("bad status line {line:?}")))?;
    let mut length: Option<u64> = None;
    let mut headers = 0;
    loop {
        line.clear();
        if read_line(&mut r, &mut line)? == 0 {
            return Err(closed("connection closed in headers"));
        }
        let header = line.trim_end();
        if header.is_empty() {
            break;
        }
        headers += 1;
        if headers > MAX_HEADERS {
            return Err(bad("too many response headers"));
        }
        if let Some((_, value)) = header
            .split_once(':')
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        {
            length = Some(
                value
                    .trim()
                    .parse()
                    .map_err(|_| bad(format!("bad Content-Length {value:?}")))?,
            );
        }
    }
    let length = length.unwrap_or(0);
    if length > MAX_BODY {
        return Err(bad(format!("response body of {length} bytes")));
    }
    let mut body = Vec::with_capacity(length as usize);
    r.take(length).read_to_end(&mut body)?;
    if body.len() as u64 != length {
        return Err(closed("connection closed in body"));
    }
    Ok(Response {
        status,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn parses_status_headers_and_body() {
        let raw = b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\ncontent-length: 17\r\n\r\n{\"fault\":\"nope\"}\n";
        let r = read_response(&raw[..]).unwrap();
        assert_eq!((r.status, r.body.as_str()), (400, "{\"fault\":\"nope\"}\n"));
        let no_content = read_response(&b"HTTP/1.1 204 No Content\r\n\r\n"[..]).unwrap();
        assert_eq!((no_content.status, no_content.body.as_str()), (204, ""));
    }

    fn kind(raw: &[u8]) -> io::ErrorKind {
        read_response(raw).unwrap_err().kind()
    }

    #[test]
    fn a_closed_connection_is_an_io_error_and_bad_http_is_invalid_data() {
        use io::ErrorKind::{InvalidData, UnexpectedEof};
        assert_eq!(kind(b""), UnexpectedEof);
        assert_eq!(
            kind(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort"),
            UnexpectedEof
        );
        assert_eq!(kind(b"HTTP/1.1 200 OK\r\nContent-Le"), UnexpectedEof);
        assert_eq!(kind(b"garbage\r\n\r\n"), InvalidData);
        assert_eq!(kind(b"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n"), InvalidData);
        assert_eq!(
            kind(b"HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n"),
            InvalidData
        );
    }

    #[test]
    fn request_maps_protocol_errors_to_http_and_socket_errors_to_io() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("api.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            // First connection: not HTTP. Second: closed without an answer.
            let (mut s, _) = listener.accept().unwrap();
            let mut req = [0u8; 1024];
            let _ = s.read(&mut req).unwrap();
            s.write_all(b"not http\r\n\r\n").unwrap();
            drop(s);
            drop(listener.accept().unwrap());
        });
        let err = request(&sock, "GET", "/", None).unwrap_err();
        assert!(matches!(&err, Error::Http(m) if m.contains("bad status line")), "{err}");
        let err = request(&sock, "GET", "/", None).unwrap_err();
        assert!(matches!(err, Error::Io(_)), "{err}");
        server.join().unwrap();
        let err = request(&dir.path().join("missing.sock"), "GET", "/", None).unwrap_err();
        assert!(matches!(err, Error::Io(_)), "{err}");
    }

    #[test]
    fn rejects_truncated_and_oversized_responses() {
        assert!(read_response(&b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort"[..]).is_err());
        assert!(read_response(&b"HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n"[..]).is_err());
        assert!(read_response(&b"garbage\r\n\r\n"[..]).is_err());
        assert!(read_response(&b"garbage 200 OK\r\n\r\n"[..]).is_err());
        let long = format!("HTTP/1.1 200 OK\r\nX: {}\r\n\r\n", "a".repeat(9000));
        assert!(read_response(long.as_bytes()).is_err());
        let many = format!("HTTP/1.1 200 OK\r\n{}\r\n", "X: 1\r\n".repeat(101));
        assert!(read_response(many.as_bytes()).is_err());
        let ok = format!("HTTP/1.1 200 OK\r\n{}\r\n", "X: 1\r\n".repeat(100));
        assert!(read_response(ok.as_bytes()).is_ok());
    }

    #[test]
    fn sends_the_request_over_a_unix_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("api.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut req = vec![0u8; 4096];
            let n = s.read(&mut req).unwrap();
            s.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();
            String::from_utf8_lossy(&req[..n]).into_owned()
        });
        let r = request(
            &sock,
            "PUT",
            "/actions",
            Some(&serde_json::json!({"action_type": "InstanceStart"})),
        )
        .unwrap();
        assert_eq!(r.status, 204);
        let req = server.join().unwrap();
        assert!(req.starts_with("PUT /actions HTTP/1.1\r\n"), "{req}");
        assert!(req.ends_with("\r\n\r\n{\"action_type\":\"InstanceStart\"}"), "{req}");
        assert!(req.contains("Content-Length: 31\r\n"), "{req}");
    }
}
