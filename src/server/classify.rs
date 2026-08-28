//! Coarse classifications used by `survey_binary`.

use serde_json::Value;
use std::fmt;

/// Coarse shape of a function, for `survey_binary`'s ranked listing.
///
/// First match wins, and the order encodes what a reader most wants to know:
/// a tiny function is a thunk whatever its call count, a function that calls
/// nothing is a leaf, and a function with many callees is a dispatcher worth
/// reading early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FunctionKind {
    Thunk,
    Leaf,
    Hub,
    Normal,
}

impl FunctionKind {
    pub(crate) fn classify(size: usize, outgoing_calls: u64) -> Self {
        const THUNK_MAX_BYTES: usize = 8;
        const HUB_MIN_CALLEES: u64 = 8;
        if size <= THUNK_MAX_BYTES {
            Self::Thunk
        } else if outgoing_calls == 0 {
            Self::Leaf
        } else if outgoing_calls >= HUB_MIN_CALLEES {
            Self::Hub
        } else {
            Self::Normal
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Thunk => "thunk",
            Self::Leaf => "leaf",
            Self::Hub => "hub",
            Self::Normal => "normal",
        }
    }
}

impl fmt::Display for FunctionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub(crate) fn survey_function_kind(size: usize, outgoing_calls: u64) -> &'static str {
    FunctionKind::classify(size, outgoing_calls).as_str()
}

/// Naive, first-match-wins bucketing of an import name.
///
/// Deliberately shallow. The job is to make a 2000-row import table skimmable
/// in one screen — "this binary talks to sockets and touches the registry" —
/// not to be right about every symbol. Order is load-bearing: `dlopen` is
/// process work rather than file I/O, so `process` is tested before `file_io`,
/// and `strdup` is string work rather than allocation, so `memory` is tested
/// before `string` only for the names `memory` matches outright.
///
/// Leading `_`, `.` and `@` are stripped first so Mach-O and ELF decoration
/// does not defeat the anchored patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImportCategory {
    Crypto,
    Network,
    Registry,
    Process,
    FileIo,
    Memory,
    String,
    Time,
    Other,
}

impl ImportCategory {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Crypto => "crypto",
            Self::Network => "network",
            Self::Registry => "registry",
            Self::Process => "process",
            Self::FileIo => "file_io",
            Self::Memory => "memory",
            Self::String => "string",
            Self::Time => "time",
            Self::Other => "other",
        }
    }
}

impl From<&str> for ImportCategory {
    fn from(name: &str) -> Self {
        static CATEGORIES: std::sync::LazyLock<Vec<(ImportCategory, regex::Regex)>> =
            std::sync::LazyLock::new(|| {
                [
                    (
                        ImportCategory::Crypto,
                        r"crypt|cipher|aes|blowfish|rc4|sha1|sha256|sha512|md5|hmac|rsa|ecdsa|curve25519|ssl|tls|x509|cert|entropy|random|digest",
                    ),
                    (
                        ImportCategory::Network,
                        r"socket|connect|listen|accept|sendto|recvfrom|send|recv|http|url|curl|inet_|dns|getaddrinfo|gethostby|winsock|ws2_|wsa|ftp|smtp|tcp|udp",
                    ),
                    (
                        ImportCategory::Registry,
                        r"^reg(open|close|set|get|query|create|delete|enum|flush)|hkey",
                    ),
                    (
                        ImportCategory::Process,
                        r"exec|fork|spawn|system|popen|process|thread|clone|waitpid|kill|signal|ptrace|dlopen|dlsym|dlclose|loadlibrary|getprocaddress|virtualalloc|virtualprotect|mmap|munmap|mprotect|exit|abort",
                    ),
                    (
                        ImportCategory::FileIo,
                        r"fopen|fclose|fread|fwrite|fseek|ftell|fflush|fcntl|open|close|read|write|creat|unlink|remove|rename|stat|lseek|mkdir|rmdir|opendir|readdir|chdir|chmod|chown|access|dir|path|file",
                    ),
                    (
                        ImportCategory::Memory,
                        r"malloc|calloc|realloc|free|memcpy|memmove|memset|memcmp|memchr|alloca|heap",
                    ),
                    (
                        ImportCategory::String,
                        r"^str|^wcs|^mbs|sprintf|snprintf|printf|scanf|iconv|locale|gettext|textdomain",
                    ),
                    (
                        ImportCategory::Time,
                        r"time|clock|date|sleep|gmtime|localtime|mktime|strftime",
                    ),
                ]
                .into_iter()
                .map(|(category, pattern)| {
                    let regex = regex::Regex::new(pattern).unwrap_or_else(|error| {
                        panic!("import category {}: {error}", category.as_str())
                    });
                    (category, regex)
                })
                .collect()
            });

        let normalized = name.trim_start_matches(['_', '.', '@']).to_lowercase();
        CATEGORIES
            .iter()
            .find(|(_, regex)| regex.is_match(&normalized))
            .map_or(Self::Other, |(category, _)| *category)
    }
}

impl fmt::Display for ImportCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub(crate) fn import_category(name: &str) -> &'static str {
    ImportCategory::from(name).as_str()
}

/// Read a non-empty string field out of the `idb_meta` payload.
pub(crate) fn meta_string(meta: &Value, key: &str) -> Option<String> {
    meta.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}
