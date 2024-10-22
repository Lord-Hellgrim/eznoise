use std::net::TcpListener;

use eznoise::*;




pub fn main() {
    let s = KeyPair::random();
    let listener = TcpListener::bind("127.0.0.1:5000").unwrap();
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        let mut connection = establish_connection(stream, s.clone()).unwrap();
        let handle = std::thread::spawn(move || {

            let data = connection.receive_c1().unwrap();
            println!("{:x?}", data);
            connection.send_c1("HELLO!!!!".as_bytes()).unwrap();
        });
        handle.join().unwrap();
        println!("connection closed");
    }
}