use std::io::{self, BufRead, BufReader};
use regex::Regex;

enum StringType {
    JunkString,
    RegularString,
    IPv4String,
    IPv6String,
    PathString,
    FormatMessageString,
    SecretString
}
fn figure_out_string(line: &str) {
    // TBD
    
}

fn handle_line(line: &str) {
    println!("{}", line);
}
fn main() {
    let stdin = io::stdin();
    let reader = BufReader::with_capacity(4096 * 4096, stdin);

    for line in reader.lines() {
        match line {
            Ok(text) => handle_line(&text),
            Err(e) => eprintln!("Error: {}", e),
        }
    }
}
