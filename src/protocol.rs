use std::str;

extern crate bytes;
use self::bytes::{BytesMut, BufMut};

iota! {
pub const CLIENT_LONG_PASSWORD: u32 = 1 << iota;
	,CLIENT_FOUND_ROWS
	,CLIENT_LONG_FLAG
	,CLIENT_CONNECT_WITH_DB
	,CLIENT_NO_SCHEMA
	,CLIENT_COMPRESS
	,CLIENT_ODBC
	,CLIENT_LOCAL_FILES
	,CLIENT_IGNORE_SPACE
	,CLIENT_PROTOCOL_41
	,CLIENT_INTERACTIVE
	,CLIENT_SSL
	,CLIENT_IGNORE_SIGPIPE
	,CLIENT_TRANSACTIONS
	,CLIENT_RESERVED
	,CLIENT_SECURE_CONNECTION
	,CLIENT_MULTI_STATEMENTS
	,CLIENT_MULTI_RESULTS
	,CLIENT_PS_MULTI_RESULTS
	,CLIENT_PLUGIN_AUTH
	,CLIENT_CONNECT_ATTRS
	,CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
}

const DEFAULT_CAPABILITY: u32 = CLIENT_LONG_PASSWORD | CLIENT_LONG_FLAG |
CLIENT_CONNECT_WITH_DB | CLIENT_PROTOCOL_41 |
CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION;

extern crate byteorder;
use self::byteorder::{LittleEndian, WriteBytesExt};

pub fn ok_packet() -> Vec<u8> {
  // if r == nil {
	// 	r = &Result{Status: c.status}
	// }
	// data := make([]byte, 4, 32)

  let mut buf = BytesMut::with_capacity(128);

  const OK_HEADER :u8 = 0;
  // data = append(data, OK_HEADER)
  buf.put_u8(OK_HEADER);

  // data = append(data, PutLengthEncodedInt(r.AffectedRows)...)
  buf.put_u8(0);
  // data = append(data, PutLengthEncodedInt(r.InsertId)...)
  buf.put_u8(0);

	// if c.capability&CLIENT_PROTOCOL_41 > 0 {
  // 	data = append(data, byte(r.Status), byte(r.Status>>8))
  const SERVER_STATUS_AUTOCOMMIT : u16 = 0x0002;

  let status = SERVER_STATUS_AUTOCOMMIT;
  buf.put_u8(status as u8);
  buf.put_u8((status>>8) as u8);

  // warnings
  buf.put_u8(0);

  return buf.to_vec();
	// 	data = append(data, 0, 0)
	// }
}

/**
  sends a server handshake initialization packet, the very first packet
  after the connection was established

  Packet format:

    Bytes       Content
    -----       ----
    1           protocol version (always 10)
    n           server version string, \0-terminated
    4           thread id
    8           first 8 bytes of the plugin provided data (scramble)
    1           \0 byte, terminating the first part of a scramble
    2           server capabilities (two lower bytes)
    1           server character set
    2           server status
    2           server capabilities (two upper bytes)
    1           length of the scramble
    10          reserved, always 0
    n           rest of the plugin provided data (at least 12 bytes)
    1           \0 byte, terminating the second part of a scramble

  @retval 0 ok
  @retval 1 error
*/

pub fn send_server_handshake_packet() -> Vec<u8> {
  // return [
  //   0x0a, // version
  //   0x35, 0x2e, 0x36, 0x2e, 0x34, 0x30, 0x2d, 0x38, 0x34, 0x2e, 0x30, 0x00, // user-agent
  //   0x02, 0x00, 0x00, 0x00, // conn id
  //   0x73, 0x64, 0x79, 0x53, 0x72, 0x63, 0x7c, 0x65, 0x00, // salt
  //   0xff, 0xf7, // server capabilities
  //   0x08, // lang
  //   0x02, 0x00, // status
  //   0x7f, 0x80, // extended cap
  //   0x15, // auth len
  //   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 10 emoty
  //   0x64, 0x45, 0x6e, 0x77, 0x2d, 0x78, 0x36, 0x42, 0x29, 0x45, 0x61, 0x39, 0x00, //rest of salt

  //   // auth plugin and shit
  //   0x6d, 0x79, 0x73, 0x71, 0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00
  // ].to_vec();

  let mut buf = BytesMut::new();

  //version 10
  buf.put_u8(10);
  // data = append(data, 10)

  buf.put_slice("v5.0.0-shitty-rust-proxy".as_bytes());
  buf.put_u8('\0' as u8);

  //connection id
  let conn_id: u32 = 3;
  // buf.put_u32(conn_id);
  buf.put_u8(conn_id as u8);
  buf.put_u8(0);//(conn_id as u8)>>8);
  buf.put_u8(0);//(conn_id as u8)>>16);
  buf.put_u8(0);//(conn_id as u8)>>24);
  // data = append(data, byte(c.connectionId), byte(c.connectionId>>8), byte(c.connectionId>>16), byte(c.connectionId>>24))

  // //auth-plugin-data-part-1

  buf.put_slice(&[0x73, 0x64, 0x79, 0x53, 0x72, 0x63, 0x7c, 0x65, 0x00]);
  // let salt = [117, 41, 65, 18, 17, 39, 40, 50, 97, 103, 46, 122, 74, 5, 93, 115, 13, 75, 33, 91];
  // buf.put_slice(&salt[0..7]);
  // buf.put_u8('\0' as u8);
  // data = append(data, c.salt[0:8]...)

  // //filter [00]
  // data = append(data, 0)
  // buf.put_u8(0);

  // //capability flag lower 2 bytes, using default capability here
  // data = append(data, byte(DEFAULT_CAPABILITY), byte(DEFAULT_CAPABILITY>>8))

  buf.put_u8(0xff);
  buf.put_u8(0xf7);
  // buf.put_u8(DEFAULT_CAPABILITY as u8);
  // buf.put_u8((DEFAULT_CAPABILITY>>8) as u8);

  const DEFAULT_COLLATION_ID:u8 = 33;
  // //charset, utf-8 default
  // data = append(data, uint8(DEFAULT_COLLATION_ID))
  buf.put_u8(DEFAULT_COLLATION_ID);

  const SERVER_STATUS_AUTOCOMMIT : u16 = 0x0002;

  let status = SERVER_STATUS_AUTOCOMMIT;
  // //status
  // data = append(data, byte(c.status), byte(c.status>>8))

  buf.put_u8(status as u8);
  buf.put_u8((status>>8) as u8);
  // let mut wtr = vec![];
  // wtr.write_u16::<LittleEndian>(status).unwrap();
  // buf2.put_slice(&wtr);

  // //below 13 byte may not be used
  // //capability flag upper 2 bytes, using default capability here
  // extendes server caps
  buf.put_u8((DEFAULT_CAPABILITY>>16) as u8);
  buf.put_u8((DEFAULT_CAPABILITY>>24) as u8);

  // buf.put_slice(&[0x7f, 0x80]);
  // data = append(data, byte(DEFAULT_CAPABILITY>>16), byte(DEFAULT_CAPABILITY>>24))

  // //filter [0x15], for wireshark dump, value is 0x15
  // data = append(data, 0x15)
  buf.put_u8(0x15);

  // //reserved 10 [00]
  // data = append(data, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
  for _ in 0..10 {
    buf.put_u8(0)
  }

  // //auth-plugin-data-part-2
  // data = append(data, c.salt[8:]...)
  buf.put_slice(&[0x64, 0x45, 0x6e, 0x77, 0x2d, 0x78, 0x36, 0x42, 0x29, 0x45, 0x61, 0x39, 0x00]);
  // buf.put_u8('\0' as u8);

  // //filter [00]
  // data = append(data, 0)
  buf.put_u8(0);

  return buf.to_vec();
}

pub fn print_packet_chars(buf: &[u8]) {
  print!("[");
  for i in 0..buf.len() {
      print!("{} ", buf[i] as char);
  }
  println!("]");
}

