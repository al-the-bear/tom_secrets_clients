// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

//! RFC 3339 times as the protocol writes them (`2026-11-13T09:00:00Z`,
//! fractions and offsets allowed), read into [`SystemTime`].

use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn digits(s: &[u8], from: usize, n: usize) -> Option<i64> {
    let part = s.get(from..from + n)?;
    if !part.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(part).ok()?.parse().ok()
}

/// Days from 1970-01-01 to `y-m-d` (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// The time `text` names, or None when it is no RFC 3339 date-time.
pub(crate) fn parse_time(text: &str) -> Option<SystemTime> {
    let s = text.as_bytes();
    let year = digits(s, 0, 4)?;
    let month = digits(s, 5, 2)?;
    let day = digits(s, 8, 2)?;
    let hour = digits(s, 11, 2)?;
    let minute = digits(s, 14, 2)?;
    let second = digits(s, 17, 2)?;
    if s.get(4) != Some(&b'-')
        || s.get(7) != Some(&b'-')
        || !matches!(s.get(10), Some(b'T' | b't'))
        || s.get(13) != Some(&b':')
        || s.get(16) != Some(&b':')
    {
        return None;
    }
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let mut at = 19;
    let mut nanos: i64 = 0;
    if s.get(at) == Some(&b'.') {
        at += 1;
        let start = at;
        while s.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        if at == start {
            return None;
        }
        let fraction = std::str::from_utf8(&s[start..at.min(start + 9)]).ok()?;
        nanos = format!("{fraction:0<9}").parse().ok()?;
    }
    let offset_seconds = match s.get(at) {
        Some(b'Z' | b'z') if at + 1 == s.len() => 0,
        Some(sign @ (b'+' | b'-')) if at + 6 == s.len() && s[at + 3] == b':' => {
            let hours = digits(s, at + 1, 2)?;
            let minutes = digits(s, at + 4, 2)?;
            if minutes > 59 {
                return None;
            }
            let seconds = hours * 3600 + minutes * 60;
            if *sign == b'+' {
                seconds
            } else {
                -seconds
            }
        }
        _ => return None,
    };
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second
        - offset_seconds;
    Some(if seconds >= 0 {
        UNIX_EPOCH + Duration::new(seconds as u64, nanos as u32)
    } else {
        UNIX_EPOCH - Duration::from_secs((-seconds) as u64) + Duration::from_nanos(nanos as u64)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(t: SystemTime) -> u128 {
        t.duration_since(UNIX_EPOCH).unwrap().as_millis()
    }

    #[test]
    fn times() {
        assert_eq!(ms(parse_time("1970-01-01T00:00:00Z").unwrap()), 0);
        assert_eq!(
            ms(parse_time("2026-11-19T10:00:00Z").unwrap()),
            1_795_082_400_000
        );
        assert_eq!(
            ms(parse_time("2026-11-19T11:00:00.250+01:00").unwrap()),
            1_795_082_400_250
        );
        assert_eq!(
            ms(parse_time("2024-02-29t23:59:59.999999999-00:30").unwrap()),
            1_709_252_999_999
        );
        for bad in [
            "2026-02-29T00:00:00Z",
            "2026-11-19 10:00:00Z",
            "2026-11-19T24:00:00Z",
            "2026-11-19T10:00:00",
            "2026-11-19T10:00:00.Z",
            "2026-11-19T10:00:00+0100",
        ] {
            assert!(parse_time(bad).is_none(), "{bad}");
        }
    }
}
