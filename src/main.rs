use std::io::{self, BufRead, BufReader};


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
