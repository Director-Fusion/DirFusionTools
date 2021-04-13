use dns_lookup::getnameinfo;
use std::net::{IpAddr, SocketAddr};

    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let port = 0;
    let socket: SocketAddr = (ip, port).into();

    let (name, service) = match getnameinfo(&socket, 0) {
      Ok((n, s)) => (n, s),
      Err(e) => panic!("Failed to lookup socket {:?}", e),
    };

println!("{:?} {:?}", name, service);
    let _ = (name, service);