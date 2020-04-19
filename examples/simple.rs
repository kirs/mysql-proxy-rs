//! MySQL Proxy Server
extern crate mysql_proxy;
use mysql_proxy::protocol::*;

#[macro_use]
extern crate log;
extern crate env_logger;
extern crate futures;
#[macro_use]
extern crate tokio_core;
extern crate byteorder;

use std::env;
use std::net::SocketAddr;
use std::rc::Rc;

use futures::stream::Stream;
use futures::{Async, Future, Poll};
use tokio_core::net::{TcpListener, TcpStream};
use tokio_core::reactor::Core;

use std::io::{self, Error, ErrorKind, Read, Write};
// use std::net::Shutdown;

// extern crate byteorder;
use byteorder::{LittleEndian, WriteBytesExt};

// use std::rc::Rc;

// use byteorder::*;
// use tokio_core::net::TcpStream;

/// Handlers return a variant of this enum to indicate how the proxy should handle the packet.
// #[derive(Debug, PartialEq)]

/// Packet handlers need to implement this trait
// pub trait PacketHandler {
//     fn handle_request(&mut self, p: &Packet) -> Action;
//     fn handle_response(&mut self, p: &Packet) -> Action;
// }

/// A packet is just a wrapper for a Vec<u8>
#[derive(Debug, PartialEq)]
pub struct Packet {
    pub bytes: Vec<u8>,
}

impl Packet {
    /// Create an error packet
    pub fn error_packet(code: u16, state: [u8; 5], msg: String) -> Self {
        // start building payload
        let mut payload: Vec<u8> = Vec::with_capacity(9 + msg.len());
        payload.push(0xff); // packet type
        payload.write_u16::<LittleEndian>(code).unwrap(); // error code
        payload.extend_from_slice("#".as_bytes()); // sql_state_marker
        payload.extend_from_slice(&state); // SQL STATE
        payload.extend_from_slice(msg.as_bytes());

        // create header with length and sequence id
        let mut header: Vec<u8> = Vec::with_capacity(4 + 9 + msg.len());
        header
            .write_u32::<LittleEndian>(payload.len() as u32)
            .unwrap();
        header.pop(); // we need 3 byte length, so discard last byte
        header.push(1); // sequence_id

        // combine the vectors
        header.extend_from_slice(&payload);

        // now move the vector into the packet
        Packet { bytes: header }
    }

    pub fn sequence_id(&self) -> u8 {
        self.bytes[3]
    }

    /// Determine the type of packet
    pub fn packet_type(&self) -> Result<PacketType, Error> {
        match self.bytes[4] {
            0x00 => Ok(PacketType::ComSleep),
            0x01 => Ok(PacketType::ComQuit),
            0x02 => Ok(PacketType::ComInitDb),
            0x03 => Ok(PacketType::ComQuery),
            0x04 => Ok(PacketType::ComFieldList),
            0x05 => Ok(PacketType::ComCreateDb),
            0x06 => Ok(PacketType::ComDropDb),
            0x07 => Ok(PacketType::ComRefresh),
            0x08 => Ok(PacketType::ComShutdown),
            0x09 => Ok(PacketType::ComStatistics),
            0x0a => Ok(PacketType::ComProcessInfo),
            0x0b => Ok(PacketType::ComConnect),
            0x0c => Ok(PacketType::ComProcessKill),
            0x0d => Ok(PacketType::ComDebug),
            0x0e => Ok(PacketType::ComPing),
            0x0f => Ok(PacketType::ComTime),
            0x10 => Ok(PacketType::ComDelayedInsert),
            0x11 => Ok(PacketType::ComChangeUser),
            0x12 => Ok(PacketType::ComBinlogDump),
            0x13 => Ok(PacketType::ComTableDump),
            0x14 => Ok(PacketType::ComConnectOut),
            0x15 => Ok(PacketType::ComRegisterSlave),
            0x16 => Ok(PacketType::ComStmtPrepare),
            0x17 => Ok(PacketType::ComStmtExecute),
            0x18 => Ok(PacketType::ComStmtSendLongData),
            0x19 => Ok(PacketType::ComStmtClose),
            0x1a => Ok(PacketType::ComStmtReset),
            0x1d => Ok(PacketType::ComDaemon),
            0x1e => Ok(PacketType::ComBinlogDumpGtid),
            0x1f => Ok(PacketType::ComResetConnection),
            _ => Err(Error::new(ErrorKind::Other, "Invalid packet type")),
        }
    }
}

#[derive(Copy, Clone)]
pub enum PacketType {
    ComSleep = 0x00,
    ComQuit = 0x01,
    ComInitDb = 0x02,
    ComQuery = 0x03,
    ComFieldList = 0x04,
    ComCreateDb = 0x05,
    ComDropDb = 0x06,
    ComRefresh = 0x07,
    ComShutdown = 0x08,
    ComStatistics = 0x09,
    ComProcessInfo = 0x0a,
    ComConnect = 0x0b,
    ComProcessKill = 0x0c,
    ComDebug = 0x0d,
    ComPing = 0x0e,
    ComTime = 0x0f,
    ComDelayedInsert = 0x10,
    ComChangeUser = 0x11,
    ComBinlogDump = 0x12,
    ComTableDump = 0x13,
    ComConnectOut = 0x14,
    ComRegisterSlave = 0x15,
    ComStmtPrepare = 0x16,
    ComStmtExecute = 0x17,
    ComStmtSendLongData = 0x18,
    ComStmtClose = 0x19,
    ComStmtReset = 0x1a,
    ComDaemon = 0x1d,
    ComBinlogDumpGtid = 0x1e,
    ComResetConnection = 0x1f,
}

/// Wrapper for TcpStream with some built-in buffering
struct ConnReader {
    stream: Rc<TcpStream>,
    packet_buf: Vec<u8>,
    read_buf: Vec<u8>,
}

/// Wrapper for TcpStream with some built-in buffering
struct ConnWriter {
    stream: Rc<TcpStream>,
    write_buf: Vec<u8>,
    // sequence: u8,
}

impl ConnReader {
    fn new(stream: Rc<TcpStream>) -> Self {
        ConnReader {
            stream: stream,
            packet_buf: Vec::with_capacity(4096),
            read_buf: vec![0_u8; 4096],
        }
    }

    /// Read from the socket until the status is NotReady
    fn read(&mut self) -> Poll<(), io::Error> {
        debug!("read()");
        loop {
            match self.stream.poll_read() {
                Async::Ready(_) => {
                    let n = try_nb!((&*self.stream).read(&mut self.read_buf[..]));
                    if n == 0 {
                        return Err(Error::new(ErrorKind::Other, "connection closed"));
                    }
                    self.packet_buf.extend_from_slice(&self.read_buf[0..n]);
                }
                _ => return Ok(Async::NotReady),
            }
        }
    }

    fn next(&mut self) -> Option<Packet> {
        debug!("next()");
        // do we have a header
        if self.packet_buf.len() > 3 {
            let l = parse_packet_length(&self.packet_buf);
            // do we have the whole packet?
            let s = 4 + l;
            if self.packet_buf.len() >= s {
                let p = Packet {
                    bytes: self.packet_buf.drain(0..s).collect(),
                };
                Some(p)
            } else {
                None
            }
        } else {
            None
        }
    }
}

impl ConnWriter {
    fn new(stream: Rc<TcpStream>) -> Self {
        ConnWriter {
            stream: stream,
            write_buf: Vec::with_capacity(4096),
            // sequence: 0,
        }
    }

    /// Write a packet to the write buffer
    fn push(&mut self, p: &Packet) {
        // debug!("push() capacity: {} packet_size: {}",
        //         self.write_buf.capacity(), p.bytes.len());

        debug!("start push()");
        print_packet_chars(&p.bytes);

        self.write_buf.extend_from_slice(&p.bytes);
        debug!("end push()");
    }

    /// Writes the contents of the write buffer to the socket
    fn write(&mut self, sequence : u8) -> Poll<(), io::Error> {
        debug!("write()");

        let packet_len = self.write_buf.len();

        // data[1] = byte(length >> 8)
        // data[2] = byte(length >> 16)

        let mut prefix = [packet_len as u8, (packet_len >>8) as u8, (packet_len >> 16) as u8, sequence as u8].to_vec();
        prefix.extend_from_slice(&self.write_buf);
        self.write_buf = prefix;

        println!("writing:");
        print_packet_bytes(&self.write_buf);

        while self.write_buf.len() > 0 {
            match self.stream.poll_write() {
                Async::Ready(_) => {
                    let s = (&*self.stream).write(&self.write_buf[..])?;
                    let _: Vec<u8> = self.write_buf.drain(0..s).collect();
                }
                _ => return Ok(Async::NotReady),
            }
        }
        // self.sequence += 1;
        return Ok(Async::Ready(()));
    }
}

pub struct Pipe {
        client_reader: ConnReader,
        client_writer: ConnWriter,
    // server_reader: ConnReader,
    // server_writer: ConnWriter,
    //     handler: H,
}

impl Pipe {
    pub fn new(client: Rc<TcpStream>) -> Pipe {
        Pipe {
            client_reader: ConnReader::new(client.clone()),
            client_writer: ConnWriter::new(client),
            // server_reader: ConnReader::new(server.clone()),
            // server_writer: ConnWriter::new(server),
            // handler: handler,
        }
    }
}

impl Future for Pipe {
    // type Item = ();
    // type Error = Error;

    type Item = ();
    type Error = Error;

    fn poll(&mut self) -> Poll<(), Error> {
        // loop {
            self.client_writer.push(&Packet { bytes: send_server_handshake_packet() });
            let client_write = self.client_writer.write(0);

            let client_read = self.client_reader.read();
            while let Some(request) = self.client_reader.next() {
              print_packet_bytes(&request.bytes);
            }

            self.client_writer.push(&Packet { bytes: ok_packet() });
            let client_write = self.client_writer.write(2);

            // try_ready!(client_write);
            // try_ready!(client_read);

            Ok(Async::Ready(()))
        // }
    }
}

/// Parse the MySQL packet length (3 byte little-endian)
fn parse_packet_length(header: &[u8]) -> usize {
    (((header[2] as u32) << 16) | ((header[1] as u32) << 8) | header[0] as u32) as usize
}

fn main() {
    env_logger::init().unwrap();

    // determine address for the proxy to bind to
    let bind_addr = env::args().nth(1).unwrap_or("127.0.0.1:3306".to_string());
    let bind_addr = bind_addr.parse::<SocketAddr>().unwrap();

    // determine address of the MySQL instance we are proxying for
    // let mysql_addr = env::args().nth(2).unwrap_or("127.0.0.1:3306".to_string());
    // let mysql_addr = mysql_addr.parse::<SocketAddr>().unwrap();

    // Create the tokio event loop that will drive this server
    let mut l = Core::new().unwrap();

    // Get a reference to the reactor event loop
    let handle = l.handle();

    // Create a TCP listener which will listen for incoming connections
    let socket = TcpListener::bind(&bind_addr, &l.handle()).unwrap();
    println!("Listening on: {}", bind_addr);

    let done = socket.incoming().for_each(move |(socket, _)| {
      // create a future to serve requests
      let future = Pipe::new(Rc::new(socket));

      // tell the tokio reactor to run the future
      handle.spawn(future.map_err(|err| {
          println!("Failed to spawn future: {:?}", err);
      }));

      // everything is great!
      Ok(())
    });
    l.run(done).unwrap();
}

#[allow(dead_code)]
pub fn print_packet_chars(buf: &[u8]) {
    print!("[");
    for i in 0..buf.len() {
        print!("{} ", buf[i] as char);
    }
    println!("]");
}

#[allow(dead_code)]
pub fn print_packet_bytes(buf: &[u8]) {
    print!("[");
    for i in 0..buf.len() {
        if i % 8 == 0 {
            println!("");
        }
        print!("{:#04x} ", buf[i]);
    }
    println!("]");
}


