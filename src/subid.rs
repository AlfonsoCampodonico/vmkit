//! Subordinate id ranges: `/etc/subuid` and `/etc/subgid` (subuid(5)).

/// `count` ids from `start`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Range {
    pub start: u32,
    pub count: u32,
}

/// The first range of `user` (named, or by numeric `uid`) holding at least `count` ids;
/// the result is its first `count` ids.
pub(crate) fn find(text: &str, user: &str, uid: u32, count: u32) -> Result<Range, String> {
    let mut short = None;
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split(':');
        let (Some(owner), Some(start), Some(n)) = (fields.next(), fields.next(), fields.next()) else {
            continue;
        };
        if owner != user && owner.parse::<u32>().ok() != Some(uid) {
            continue;
        }
        let (Ok(start), Ok(n)) = (start.parse::<u32>(), n.parse::<u32>()) else {
            continue;
        };
        if n >= count {
            return Ok(Range { start, count });
        }
        short = Some(n);
    }
    Err(match short {
        Some(n) => format!("the range for {user} holds {n} ids; at least {count} are needed"),
        None => format!("no range for {user}"),
    })
}

/// The name of `uid` in passwd(5) text.
pub(crate) fn user_name(passwd: &str, uid: u32) -> Option<String> {
    passwd.lines().find_map(|l| {
        let mut f = l.split(':');
        let name = f.next()?;
        (f.nth(1)?.parse::<u32>().ok()? == uid).then(|| name.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_match_by_name_or_uid_and_must_be_large_enough() {
        let text = "bob:100000:65536\n# comment\nalice:200000:1000\n1000:300000:65536\n";
        assert_eq!(
            find(text, "bob", 501, 65536),
            Ok(Range {
                start: 100000,
                count: 65536
            })
        );
        assert_eq!(
            find(text, "carol", 1000, 65536),
            Ok(Range {
                start: 300000,
                count: 65536
            })
        );
        assert!(find(text, "alice", 502, 65536).unwrap_err().contains("at least 65536"));
        assert!(find(text, "dave", 503, 1).unwrap_err().contains("no range for dave"));
        assert!(find("bob:x:1\n", "bob", 501, 1).is_err());
    }

    #[test]
    fn the_name_comes_from_passwd_by_uid() {
        let passwd = "root:x:0:0::/root:/bin/sh\nalfonso:x:501:1000::/home/alfonso:/bin/bash\n";
        assert_eq!(user_name(passwd, 501).as_deref(), Some("alfonso"));
        assert_eq!(user_name(passwd, 7), None);
    }
}
