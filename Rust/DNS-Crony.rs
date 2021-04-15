use dns_lookup::lookup_addr;

let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
let host = lookup_addr(&ip).unwrap();

// The string "localhost" on unix, and the hostname on Windows.
