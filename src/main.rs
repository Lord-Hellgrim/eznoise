use std::net::TcpListener;

use eznoise::*;




pub fn main() {
    let s = KeyPair::random();
    let listener = TcpListener::bind("127.0.0.1:5000").unwrap();
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        let mut connection = ESTABLISH_CONNECTION(stream, s.clone()).unwrap();
        let handle = std::thread::spawn(move || {

            let data = connection.RECEIVE_C1().unwrap();
            println!("{:x?}", data);
            connection.SEND_C1("HELLO!!!!".as_bytes()).unwrap();
        });
        handle.join().unwrap();
        println!("connection closed");
    }
}