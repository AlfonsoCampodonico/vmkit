//! A minimal HTTP/1.1 client over a Unix socket: enough for the VMM REST APIs,
//! which take small JSON bodies and answer one request per connection.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Largest response body accepted (API errors are a few hundred bytes).
const MAX_BODY: u64 = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Response {
    pub status: u16,
    pub body: String,
}

/// Sends one request with an optional JSON body and reads the response.
pub(crate) fn request(
    socket: &Path,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
) -> io::Result<Response> {
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

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn read_response(mut r: impl BufRead) -> io::Result<Response> {
    let mut line = String::new();
    r.read_line(&mut line)?;
    let status = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| bad(format!("bad status line {line:?}")))?;
    let mut length: Option<u64> = None;
    loop {
        line.clear();
        if r.read_line(&mut line)? == 0 {
            return Err(bad("connection closed in headers"));
        }
        let header = line.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
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
        return Err(bad("connection closed in body"));
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

    #[test]
    fn rejects_truncated_and_oversized_responses() {
        assert!(read_response(&b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort"[..]).is_err());
        assert!(read_response(&b"HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n"[..]).is_err());
        assert!(read_response(&b"garbage\r\n\r\n"[..]).is_err());
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
