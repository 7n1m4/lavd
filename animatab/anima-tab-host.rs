use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

use scx_utils::anima_tab_sock;

fn main() -> io::Result<()> {
    let sock_path = anima_tab_sock();
    let mut stream = match UnixStream::connect(&sock_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[anima-tab-host] cannot connect to {sock_path:?}: {e}");
            std::process::exit(1);
        }
    };
    let mut stdin = io::stdin();
    let mut len_buf = [0u8; 4];

    loop {
        if stdin.read_exact(&mut len_buf).is_err() {
            return Ok(()); /* browser exit */
        }
        let len = u32::from_ne_bytes(len_buf) as usize;
        let mut msg = vec![0u8; len];
        if stdin.read_exact(&mut msg).is_err() {
            return Ok(());
        }

        let s = String::from_utf8_lossy(&msg);
        if let Some(pid) = parse_pid(&s) {
            if let Err(e) = stream.write_all(&pid.to_ne_bytes()) {
                eprintln!("[anima-tab-host] write failed: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn parse_pid(s: &str) -> Option<i32> {
    let key = "\"pid\"";
    let i = s.find(key)? + key.len();
    let rest = s[i..].trim_start_matches(|c: char| c == ' ' || c == ':');
    let digits: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    digits.parse().ok()
}
