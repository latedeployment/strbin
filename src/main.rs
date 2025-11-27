use std::io::{self, BufRead, BufReader};
use std::collections::{HashMap, HashSet};
use regex::Regex;
use once_cell::sync::Lazy;
use clap::{Parser, ValueEnum};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum StringType {
    JunkString,
    RegularString,
    IPv4String,
    IPv6String,
    PathString,
    FormatMessageString,
    SecretString,
    URLString,
    EmailString,
    UUIDString,
    MACAddressString,
    Base64String,
    HexString,
    GitHashString,
    JSONString,
    XMLString,
    TimestampString,
    SemVerString,
    CppTemplateString,
    CppExceptionString,
    CppRTTIString,
    PythonTracebackString,
    JavaStackTraceString,
    JavaScriptErrorString,
    GoPanicString,
    RustPanicString,
    SQLQueryString,
    SSHKeyString,
    MD5HashString,
    SHA1HashString,
    SHA256HashString,
    SHA512HashString,
}

impl StringType {
    fn as_str(&self) -> &str {
        match self {
            StringType::JunkString => "Junk",
            StringType::RegularString => "Regular",
            StringType::IPv4String => "IPv4",
            StringType::IPv6String => "IPv6",
            StringType::PathString => "Path",
            StringType::FormatMessageString => "FormatMessage",
            StringType::SecretString => "Secret",
            StringType::URLString => "URL",
            StringType::EmailString => "Email",
            StringType::UUIDString => "UUID",
            StringType::MACAddressString => "MACAddress",
            StringType::Base64String => "Base64",
            StringType::HexString => "Hex",
            StringType::GitHashString => "GitHash",
            StringType::JSONString => "JSON",
            StringType::XMLString => "XML",
            StringType::TimestampString => "Timestamp",
            StringType::SemVerString => "SemVer",
            StringType::CppTemplateString => "CppTemplate",
            StringType::CppExceptionString => "CppException",
            StringType::CppRTTIString => "CppRTTI",
            StringType::PythonTracebackString => "PythonTraceback",
            StringType::JavaStackTraceString => "JavaStackTrace",
            StringType::JavaScriptErrorString => "JavaScriptError",
            StringType::GoPanicString => "GoPanic",
            StringType::RustPanicString => "RustPanic",
            StringType::SQLQueryString => "SQLQuery",
            StringType::SSHKeyString => "SSHKey",
            StringType::MD5HashString => "MD5Hash",
            StringType::SHA1HashString => "SHA1Hash",
            StringType::SHA256HashString => "SHA256Hash",
            StringType::SHA512HashString => "SHA512Hash",
        }
    }

    // Types that are disabled by default (too noisy/large/false positives)
    fn default_disabled_types() -> Vec<StringType> {
        vec![
            StringType::RustPanicString,
            StringType::PythonTracebackString,
            StringType::JavaStackTraceString,
            StringType::JavaScriptErrorString,
            StringType::GoPanicString,
            StringType::CppExceptionString,
            StringType::Base64String,  // Too many false positives
            StringType::HexString,      // Too many false positives
            StringType::JSONString,     // Too many false positives (Rust closures, etc.)
            StringType::GitHashString,  // Too many false positives (random identifiers)
        ]
    }

    fn cpp_types() -> Vec<StringType> {
        vec![
            StringType::CppTemplateString,
            StringType::CppExceptionString,
            StringType::CppRTTIString,
        ]
    }

    fn error_types() -> Vec<StringType> {
        vec![
            StringType::CppExceptionString,
            StringType::PythonTracebackString,
            StringType::JavaStackTraceString,
            StringType::JavaScriptErrorString,
            StringType::GoPanicString,
            StringType::RustPanicString,
        ]
    }

    fn network_types() -> Vec<StringType> {
        vec![
            StringType::IPv4String,
            StringType::IPv6String,
            StringType::URLString,
            StringType::EmailString,
            StringType::MACAddressString,
        ]
    }

    fn identifier_types() -> Vec<StringType> {
        vec![
            StringType::UUIDString,
            StringType::MACAddressString,
            StringType::GitHashString,
        ]
    }

    fn data_format_types() -> Vec<StringType> {
        vec![
            StringType::JSONString,
            StringType::XMLString,
            StringType::Base64String,
            StringType::HexString,
        ]
    }
}
static IPV4_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap());
static IPV6_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b").unwrap());
static PATH_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?:[a-zA-Z]:[/\\]|/)(?:[a-zA-Z0-9_.\-]+[/\\])+[a-zA-Z0-9_.\-]+|(?:[a-zA-Z]:[/\\]|/)[a-zA-Z0-9_.\-]+\.[a-zA-Z0-9]+").unwrap());
static FORMAT_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"%[sdfx]|\{\}|\{[0-9]+\}").unwrap());
// Match JWT tokens and common API key patterns, but not random alphanumeric strings or mangled names
static SECRET_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?:ey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})|(?:AKIA[0-9A-Z]{16})|(?:(?:sk|pk|api|token)_[A-Za-z0-9]{32,})").unwrap());
static URL_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b(?:https?|ftp)://[^\s]+").unwrap());
static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap());
static UUID_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b").unwrap());
static MAC_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b").unwrap());
static BASE64_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[A-Za-z0-9+/]{20,}={0,2}\b").unwrap());
static HEX_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:0x)?[0-9a-fA-F]{16,}\b").unwrap());
static GIT_HASH_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[0-9a-f]{7,40}\b").unwrap());
static TIMESTAMP_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}").unwrap());
static SEMVER_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+)?(?:\+[0-9A-Za-z-]+)?\b").unwrap());
static CPP_TEMPLATE_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?:std::|boost::)[a-zA-Z_][a-zA-Z0-9_]*<.*>").unwrap());
static CPP_MANGLED_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"_Z[NKL][0-9a-zA-Z_]+").unwrap());
// Match actual SQL queries with more context - require SELECT/INSERT/UPDATE/DELETE followed by realistic SQL structure
static SQL_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b(?:SELECT\s+(?:\*|\w+).*\s+FROM\s+\w+|INSERT\s+INTO\s+\w+.*VALUES|UPDATE\s+\w+\s+SET|DELETE\s+FROM\s+\w+|CREATE\s+TABLE\s+\w+|DROP\s+TABLE\s+\w+)").unwrap());

// SSH keys - match public keys (ssh-rsa, ssh-ed25519, etc.) and private key headers
static SSH_KEY_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?:ssh-(?:rsa|dss|ed25519|ecdsa)\s+[A-Za-z0-9+/=]{50,}|-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+(?:PRIVATE|PUBLIC)\s+KEY-----)").unwrap());

// Hash detection - exact lengths for different hash types
static MD5_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[a-fA-F0-9]{32}\b").unwrap());
static SHA1_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[a-fA-F0-9]{40}\b").unwrap());
static SHA256_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[a-fA-F0-9]{64}\b").unwrap());
static SHA512_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[a-fA-F0-9]{128}\b").unwrap());

fn is_json(line: &str) -> bool {
    line.trim_start().starts_with('{') || line.trim_start().starts_with('[')
}

fn is_xml(line: &str) -> bool {
    line.trim_start().starts_with('<')
}

fn is_cpp_exception(line: &str) -> bool {
    line.contains("terminate called after throwing") ||
    line.contains("what():") ||
    line.contains("std::exception")
}

fn is_python_traceback(line: &str) -> bool {
    line.contains("Traceback (most recent call last)") ||
    line.contains("File \"") && line.contains(", line ") ||
    line.contains("Error:") && line.chars().next().map_or(false, |c| c.is_uppercase())
}

fn is_java_stacktrace(line: &str) -> bool {
    line.contains("at ") && line.contains(".java:") ||
    line.contains("Exception in thread") ||
    line.contains("Caused by:")
}

fn is_javascript_error(line: &str) -> bool {
    line.contains("Uncaught") ||
    line.contains("ReferenceError:") ||
    line.contains("TypeError:") ||
    (line.contains("at ") && line.contains(".js:"))
}

fn is_go_panic(line: &str) -> bool {
    line.contains("panic:") ||
    line.contains("goroutine ") ||
    line.contains("runtime error:")
}

fn is_rust_panic(line: &str) -> bool {
    line.contains("panicked at") ||
    line.contains("thread '") && line.contains("' panicked")
}

fn is_junk(line: &str) -> bool {
    let non_printable_count = line.chars()
        .filter(|c| c.is_control() && *c != '\t')
        .count();
    non_printable_count > line.len() / 4
}

fn extract_all_matches(line: &str) -> Vec<(StringType, String)> {
    use StringType::*;
    let mut matches = Vec::new();

    // Extract regex-based patterns
    for mat in URL_REGEX.find_iter(line) {
        matches.push((URLString, mat.as_str().to_string()));
    }
    for mat in EMAIL_REGEX.find_iter(line) {
        matches.push((EmailString, mat.as_str().to_string()));
    }
    for mat in UUID_REGEX.find_iter(line) {
        matches.push((UUIDString, mat.as_str().to_string()));
    }
    for mat in MAC_REGEX.find_iter(line) {
        matches.push((MACAddressString, mat.as_str().to_string()));
    }
    for mat in IPV4_REGEX.find_iter(line) {
        matches.push((IPv4String, mat.as_str().to_string()));
    }
    for mat in IPV6_REGEX.find_iter(line) {
        matches.push((IPv6String, mat.as_str().to_string()));
    }
    for mat in TIMESTAMP_REGEX.find_iter(line) {
        matches.push((TimestampString, mat.as_str().to_string()));
    }
    for mat in SEMVER_REGEX.find_iter(line) {
        matches.push((SemVerString, mat.as_str().to_string()));
    }
    for mat in GIT_HASH_REGEX.find_iter(line) {
        matches.push((GitHashString, mat.as_str().to_string()));
    }
    for mat in BASE64_REGEX.find_iter(line) {
        matches.push((Base64String, mat.as_str().to_string()));
    }
    for mat in HEX_REGEX.find_iter(line) {
        matches.push((HexString, mat.as_str().to_string()));
    }
    for mat in CPP_TEMPLATE_REGEX.find_iter(line) {
        matches.push((CppTemplateString, mat.as_str().to_string()));
    }
    for mat in CPP_MANGLED_REGEX.find_iter(line) {
        matches.push((CppRTTIString, mat.as_str().to_string()));
    }
    for mat in SQL_REGEX.find_iter(line) {
        matches.push((SQLQueryString, mat.as_str().to_string()));
    }
    for mat in PATH_REGEX.find_iter(line) {
        matches.push((PathString, mat.as_str().to_string()));
    }
    for mat in FORMAT_REGEX.find_iter(line) {
        matches.push((FormatMessageString, mat.as_str().to_string()));
    }
    for mat in SECRET_REGEX.find_iter(line) {
        matches.push((SecretString, mat.as_str().to_string()));
    }
    for mat in SSH_KEY_REGEX.find_iter(line) {
        matches.push((SSHKeyString, mat.as_str().to_string()));
    }

    // Hash detection - check in order of specificity (longest first to avoid shorter hashes matching longer ones)
    for mat in SHA512_REGEX.find_iter(line) {
        matches.push((SHA512HashString, mat.as_str().to_string()));
    }
    for mat in SHA256_REGEX.find_iter(line) {
        matches.push((SHA256HashString, mat.as_str().to_string()));
    }
    for mat in SHA1_REGEX.find_iter(line) {
        matches.push((SHA1HashString, mat.as_str().to_string()));
    }
    for mat in MD5_REGEX.find_iter(line) {
        matches.push((MD5HashString, mat.as_str().to_string()));
    }

    // For non-regex patterns that need full line context, add the full line
    if is_cpp_exception(line) {
        matches.push((CppExceptionString, line.to_string()));
    }
    if is_python_traceback(line) {
        matches.push((PythonTracebackString, line.to_string()));
    }
    if is_java_stacktrace(line) {
        matches.push((JavaStackTraceString, line.to_string()));
    }
    if is_javascript_error(line) {
        matches.push((JavaScriptErrorString, line.to_string()));
    }
    if is_go_panic(line) {
        matches.push((GoPanicString, line.to_string()));
    }
    if is_rust_panic(line) {
        matches.push((RustPanicString, line.to_string()));
    }
    if is_json(line) {
        matches.push((JSONString, line.to_string()));
    }
    if is_xml(line) {
        matches.push((XMLString, line.to_string()));
    }
    if is_junk(line) {
        matches.push((JunkString, line.to_string()));
    }

    // If no matches found, it's a regular string
    if matches.is_empty() {
        matches.push((RegularString, line.to_string()));
    }

    matches
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ValueEnum)]
#[clap(rename_all = "kebab-case")]
enum TypeFilter {
    Junk, Regular, Ipv4, Ipv6, Path, FormatMessage, Secret, Url, Email,
    Uuid, MacAddress, Base64, Hex, GitHash, Json, Xml, Timestamp, SemVer,
    CppTemplate, CppException, CppRtti, PythonTraceback, JavaStackTrace,
    JavascriptError, GoPanic, RustPanic, SqlQuery, SshKey, Md5, Sha1, Sha256, Sha512,
    // Group filters
    Cpp, Errors, Network, Identifiers, DataFormats,
}

impl TypeFilter {
    fn to_string_types(&self) -> Vec<StringType> {
        use StringType::*;
        match self {
            TypeFilter::Junk => vec![JunkString],
            TypeFilter::Regular => vec![RegularString],
            TypeFilter::Ipv4 => vec![IPv4String],
            TypeFilter::Ipv6 => vec![IPv6String],
            TypeFilter::Path => vec![PathString],
            TypeFilter::FormatMessage => vec![FormatMessageString],
            TypeFilter::Secret => vec![SecretString],
            TypeFilter::Url => vec![URLString],
            TypeFilter::Email => vec![EmailString],
            TypeFilter::Uuid => vec![UUIDString],
            TypeFilter::MacAddress => vec![MACAddressString],
            TypeFilter::Base64 => vec![Base64String],
            TypeFilter::Hex => vec![HexString],
            TypeFilter::GitHash => vec![GitHashString],
            TypeFilter::Json => vec![JSONString],
            TypeFilter::Xml => vec![XMLString],
            TypeFilter::Timestamp => vec![TimestampString],
            TypeFilter::SemVer => vec![SemVerString],
            TypeFilter::CppTemplate => vec![CppTemplateString],
            TypeFilter::CppException => vec![CppExceptionString],
            TypeFilter::CppRtti => vec![CppRTTIString],
            TypeFilter::PythonTraceback => vec![PythonTracebackString],
            TypeFilter::JavaStackTrace => vec![JavaStackTraceString],
            TypeFilter::JavascriptError => vec![JavaScriptErrorString],
            TypeFilter::GoPanic => vec![GoPanicString],
            TypeFilter::RustPanic => vec![RustPanicString],
            TypeFilter::SqlQuery => vec![SQLQueryString],
            TypeFilter::SshKey => vec![SSHKeyString],
            TypeFilter::Md5 => vec![MD5HashString],
            TypeFilter::Sha1 => vec![SHA1HashString],
            TypeFilter::Sha256 => vec![SHA256HashString],
            TypeFilter::Sha512 => vec![SHA512HashString],
            // Groups
            TypeFilter::Cpp => StringType::cpp_types(),
            TypeFilter::Errors => StringType::error_types(),
            TypeFilter::Network => StringType::network_types(),
            TypeFilter::Identifiers => StringType::identifier_types(),
            TypeFilter::DataFormats => StringType::data_format_types(),
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "strbin")]
#[command(about = "Classify and summarize strings from stdin", long_about = None)]
struct Args {
    // Output mode
    #[arg(long, help = "Only show counts and types, not full strings")]
    analyze: bool,

    #[arg(long, help = "Maximum number of items to show per type (0 = unlimited)")]
    max_items: Option<usize>,

    #[arg(long, help = "Disable default filters (by default, noisy error types like Rust/Python/Java/JS/Go panics and C++ exceptions are excluded)")]
    no_defaults: bool,

    #[arg(long, value_enum, help = "Include only these types (can be specified multiple times)")]
    with: Vec<TypeFilter>,

    #[arg(long, value_enum, help = "Exclude these types (can be specified multiple times)")]
    without: Vec<TypeFilter>,
}

impl Args {
    fn build_included_types(&self) -> Option<HashSet<StringType>> {
        if self.with.is_empty() {
            None
        } else {
            let mut included = HashSet::new();
            for filter in &self.with {
                included.extend(filter.to_string_types());
            }
            Some(included)
        }
    }

    fn build_excluded_types(&self) -> HashSet<StringType> {
        let mut excluded = HashSet::new();
        for filter in &self.without {
            excluded.extend(filter.to_string_types());
        }
        excluded
    }

    fn should_include_type(&self, string_type: StringType) -> bool {
        // If whitelist is specified, only include types in whitelist
        if let Some(included) = self.build_included_types() {
            return included.contains(&string_type);
        }

        // Build exclusion list (blacklist + defaults unless disabled)
        let mut excluded = self.build_excluded_types();

        // Add default disabled types unless --no-defaults is specified
        if !self.no_defaults {
            excluded.extend(StringType::default_disabled_types());
        }

        !excluded.contains(&string_type)
    }
}

fn print_summary(collections: &HashMap<StringType, HashSet<String>>, analyze: bool, max_items: Option<usize>) {
    let mut sorted_types: Vec<_> = collections.iter().collect();
    sorted_types.sort_by_key(|(t, _)| t.as_str());

    for (string_type, strings) in sorted_types {
        if !strings.is_empty() {
            println!("\n{} [{}]:", string_type.as_str(), strings.len());

            if !analyze {
                let limit = max_items.unwrap_or(0);
                let mut count = 0;

                for s in strings {
                    if limit > 0 && count >= limit {
                        println!("  ... ({} more)", strings.len() - limit);
                        break;
                    }
                    println!("  {}", s);
                    count += 1;
                }
            }
        }
    }
}

fn print_final_summary(collections: &HashMap<StringType, HashSet<String>>) {
    let mut all_types: Vec<_> = collections.keys().collect();
    all_types.sort_by_key(|t| t.as_str());

    if !all_types.is_empty() {
        println!("\n\n=== Summary ===");
        println!("Detected types: {}", all_types.iter().map(|t| t.as_str()).collect::<Vec<_>>().join(", "));
        println!("\nTo filter, use:");
        println!("  --with <type>     (include only specific types, can repeat)");
        println!("  --without <type>  (exclude specific types, can repeat)");
        println!("  --analyze         (show only counts)");
        println!("  --max-items N     (limit items per type)");
        println!("  --no-defaults     (disable default filters)");
        println!("\nExamples:");
        println!("  --with url --with email");
        println!("  --without errors --without cpp");
    }
}

fn main() {
    let args = Args::parse();

    let stdin = io::stdin();
    let reader = BufReader::with_capacity(4096 * 4096, stdin);
    let mut collections: HashMap<StringType, HashSet<String>> = HashMap::new();

    for line in reader.lines() {
        match line {
            Ok(text) => {
                // Extract all matches from this line
                let matches = extract_all_matches(&text);

                for (string_type, matched_text) in matches {
                    // Skip if this type should not be included
                    if !args.should_include_type(string_type) {
                        continue;
                    }

                    collections
                        .entry(string_type)
                        .or_insert_with(HashSet::new)
                        .insert(matched_text);
                }
            }
            Err(e) => eprintln!("Error: {}", e),
        }
    }

    print_summary(&collections, args.analyze, args.max_items);
    print_final_summary(&collections);
}
