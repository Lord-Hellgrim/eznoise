use std::net::TcpListener;

use eznoise::*;




pub fn main() {
    let s = KeyPair::random();
    let mut handshakestate = HandshakeState::Initialize(false, &[], s, KeyPair::empty(), None, None);
    let listener = TcpListener::bind("127.0.0.1:5000").unwrap();
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        let mut connection = establish_connection(&mut handshakestate, stream).unwrap();
        let data = connection.receive().unwrap();
        println!("{:x?}", data);
        connection.send("HELLO!!!!".as_bytes()).unwrap();
    }
}