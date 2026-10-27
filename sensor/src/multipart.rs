//! Multipart statistics from a bounded boundary scan.
//!
//! This never parses parts into structures and never allocates per part beyond a few short strings.
//! It only measures shape: how many parts, how much preamble, how deep the field names nest, how
//! many file parts are empty. Shape is what distinguishes a form post from a memory-corruption
//! probe, and it cannot be hidden by what the bytes claim to be.

use memchr::memmem;
use serde::Serialize;

#[derive(Serialize, Debug, Default, Clone)]
pub struct MultipartStats {
    pub boundary: String,
    pub parts: usize,
    pub preamble_len: Option<usize>,
    pub epilogue_len: Option<usize>,
    pub max_headers_in_part: usize,
    pub max_name_depth: usize,
    pub file_parts: usize,
    pub empty_file_parts: usize,
    pub session_upload_progress: bool,
    pub names_sample: Vec<String>,
}

/// Pull the boundary parameter out of a Content-Type value, quotes stripped.
pub fn boundary_of(ctype: &str) -> Option<String> {
    let lower = ctype.to_ascii_lowercase();
    let i = lower.find("boundary=")? + "boundary=".len();
    let rest = &ctype[i..];
    let rest = rest.trim_start_matches('"');
    let end = rest.find(['"', ';']).unwrap_or(rest.len());
    let b = rest[..end].trim();
    if b.is_empty() {
        None
    } else {
        Some(b.chars().take(80).collect())
    }
}

const MAX_PARTS_SCANNED: usize = 5000;
const MAX_NAMES: usize = 12;

pub fn stats(sample: &[u8], boundary: &str) -> MultipartStats {
    let delim = format!("--{boundary}").into_bytes();
    let finder = memmem::Finder::new(&delim);
    let offsets: Vec<usize> = finder.find_iter(sample).collect();
    let mut st = MultipartStats {
        boundary: boundary.to_string(),
        parts: offsets.len(),
        preamble_len: offsets.first().copied(),
        ..Default::default()
    };
    // Closing delimiter: last "--boundary--".
    let mut close = delim.clone();
    close.extend_from_slice(b"--");
    if let Some(end) = memmem::rfind(sample, &close) {
        st.epilogue_len = sample.len().checked_sub(end + close.len());
    }

    let name_finder = memmem::Finder::new(b"name=\"");
    let fname_finder = memmem::Finder::new(b"filename=\"");
    let sep_finder = memmem::Finder::new(b"\r\n\r\n");

    for (i, &start) in offsets.iter().enumerate().take(MAX_PARTS_SCANNED) {
        let begin = start + delim.len();
        let end = offsets.get(i + 1).copied().unwrap_or(sample.len());
        if begin > end {
            continue;
        }
        let part = &sample[begin..end];
        let (head, data) = match sep_finder.find(part) {
            Some(p) => (&part[..p], &part[p + 4..]),
            None => (part, &part[part.len()..]),
        };
        let hdr_count = head
            .split(|&b| b == b'\n')
            .filter(|l| !l.iter().all(|&b| b == b'\r' || b == b' ' || b == b'\t'))
            .count();
        st.max_headers_in_part = st.max_headers_in_part.max(hdr_count);

        if let Some(p) = name_finder.find(head) {
            let v = &head[p + 6..];
            let n = v
                .iter()
                .position(|&b| b == b'"')
                .unwrap_or(v.len().min(200));
            let name = String::from_utf8_lossy(&v[..n.min(200)]).into_owned();
            st.max_name_depth = st
                .max_name_depth
                .max(name.bytes().filter(|&b| b == b'[').count());
            if st.names_sample.len() < MAX_NAMES {
                st.names_sample.push(name.clone());
            }
            if name == "PHP_SESSION_UPLOAD_PROGRESS" {
                st.session_upload_progress = true;
            }
        }
        if fname_finder.find(head).is_some() {
            st.file_parts += 1;
            let trimmed = data
                .iter()
                .filter(|&&b| b != b'\r' && b != b'\n' && b != b'-')
                .count();
            if trimmed == 0 {
                st.empty_file_parts += 1;
            }
        }
    }
    st
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_boundary() {
        assert_eq!(
            boundary_of("multipart/form-data; boundary=abc"),
            Some("abc".into())
        );
        assert_eq!(
            boundary_of("multipart/form-data; boundary=\"q q\"; x=1"),
            Some("q q".into())
        );
        assert_eq!(boundary_of("text/plain"), None);
    }

    #[test]
    fn counts_shape() {
        let body = b"--X\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n1\r\n--X\r\nContent-Disposition: form-data; name=\"a[b][c]\"; filename=\"x\"\r\n\r\n\r\n--X--\r\n";
        let s = stats(body, "X");
        assert_eq!(s.parts, 3);
        assert_eq!(s.preamble_len, Some(0));
        assert!(s.session_upload_progress);
        assert_eq!(s.file_parts, 1);
        assert_eq!(s.empty_file_parts, 1);
        assert_eq!(s.max_name_depth, 2);
    }
}
