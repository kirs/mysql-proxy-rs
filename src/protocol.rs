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

pub const DEFAULT_CAPABILITY: u32 = CLIENT_LONG_PASSWORD
    | CLIENT_LONG_FLAG
    | CLIENT_CONNECT_WITH_DB
    | CLIENT_PROTOCOL_41
    | CLIENT_TRANSACTIONS
    | CLIENT_SECURE_CONNECTION;

extern crate byteorder;
use self::byteorder::{LittleEndian, ReadBytesExt};

// pub trait ReadMysqlExt: ReadBytesExt {
//     /// Reads MySql's length-encoded integer.
//     fn read_lenenc_int(&mut self) -> io::Result<u64> {
//         match self.read_u8()? {
//             x if x < 0xfc => Ok(x.into()),
//             0xfc => self.read_uint::<LE>(2),
//             0xfd => self.read_uint::<LE>(3),
//             0xfe => self.read_uint::<LE>(8),
//             0xff => Err(io::Error::new(
//                 io::ErrorKind::Other,
//                 "Invalid length-encoded integer value",
//             )),
//             _ => unreachable!(),
//         }
//     }
// }

pub fn ok_packet(capability : u32) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();

    const OK_HEADER: u8 = 0;
    // data = append(data, OK_HEADER)
    buf.push(OK_HEADER);

    // data = append(data, PutLengthEncodedInt(r.AffectedRows)...)
    buf.push(0);
    // data = append(data, PutLengthEncodedInt(r.InsertId)...)
    buf.push(0);

    if capability&CLIENT_PROTOCOL_41 > 0 {
    // 	data = append(data, byte(r.Status), byte(r.Status>>8))
        const SERVER_STATUS_AUTOCOMMIT: u16 = 0x0002;
        let status = SERVER_STATUS_AUTOCOMMIT;
        buf.push(status as u8);
        buf.push((status >> 8) as u8);

        // warnings
        buf.push(0);
        buf.push(0);
    }

    // if capability & CLIENT_SESSION_TRACK > 0 {
    //     panic!("session track not supported!");
    // }

    // if capability & CLIENT_SESSION_TRACK > 0 {
    //     panic!("session track not supported!");
    // }

    return buf.to_vec();
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

pub fn server_handshake_packet(capability : u32) -> Vec<u8> {
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

    let mut buf: Vec<u8> = Vec::new();

    //version 10
    buf.push(10);

    buf.extend_from_slice("v5.0.0-shitty-rust-proxy".as_bytes());
    buf.push('\0' as u8);

    //connection id
    let conn_id: u32 = 3;
    buf.push(conn_id as u8);
    buf.push((conn_id >> 8) as u8);
    buf.push((conn_id >> 16) as u8);
    buf.push((conn_id >> 24) as u8);
    // data = append(data, byte(c.connectionId), byte(c.connectionId>>8), byte(c.connectionId>>16), byte(c.connectionId>>24))

    // //auth-plugin-data-part-1

    let salt = [
        117, 41, 65, 18, 17, 39, 40, 50, 97, 103, 46, 122, 74, 5, 93, 115, 13, 75, 33, 91,
    ];
    buf.extend_from_slice(&salt[0..8]);
    buf.push('\0' as u8);
    // data = append(data, c.salt[0:8]...)

    // //filter [00]
    // data = append(data, 0)
    // buf.push(0);

    // //capability flag lower 2 bytes, using default capability here
    // data = append(data, byte(DEFAULT_CAPABILITY), byte(DEFAULT_CAPABILITY>>8))

    // buf.push(0xff);
    // buf.push(0xf7);

    buf.push(capability as u8);
    buf.push((capability >> 8) as u8);
    // buf.push(DEFAULT_CAPABILITY as u8);
    // buf.push((DEFAULT_CAPABILITY>>8) as u8);

    const DEFAULT_COLLATION_ID: u8 = 33;
    // //charset, utf-8 default
    // data = append(data, uint8(DEFAULT_COLLATION_ID))
    buf.push(DEFAULT_COLLATION_ID);

    const SERVER_STATUS_AUTOCOMMIT: u16 = 0x0002;

    let status = SERVER_STATUS_AUTOCOMMIT;
    // //status
    // data = append(data, byte(c.status), byte(c.status>>8))

    buf.push(status as u8);
    buf.push((status >> 8) as u8);
    // let mut wtr = vec![];
    // wtr.write_u16::<LittleEndian>(status).unwrap();
    // buf2.extend_from_slice(&wtr);

    // //below 13 byte may not be used
    // //capability flag upper 2 bytes, using default capability here
    // extendes server caps
    buf.push((DEFAULT_CAPABILITY >> 16) as u8);
    buf.push((DEFAULT_CAPABILITY >> 24) as u8);

    // buf.extend_from_slice(&[0x7f, 0x80]);
    // data = append(data, byte(DEFAULT_CAPABILITY>>16), byte(DEFAULT_CAPABILITY>>24))

    // //filter [0x15], for wireshark dump, value is 0x15
    // data = append(data, 0x15)
    buf.push(0x15);

    // //reserved 10 [00]
    // data = append(data, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    for _ in 0..10 {
        buf.push(0)
    }

    // //auth-plugin-data-part-2
    // data = append(data, c.salt[8:]...)
    buf.extend_from_slice(&salt[8..]);
    buf.push('\0' as u8);

    return buf.to_vec();
}

pub fn print_packet_chars(buf: &[u8]) {
    print!("[");
    for i in 0..buf.len() {
        print!("{} ", buf[i] as char);
    }
    println!("]");
}

pub struct ClientHandshake {
    // pub bytes: Vec<u8>,
    pub capability: u32,
    pub collation : u8,
    pub max_packet_size : u32,
    pub username: String,
    // pub auth: Vec<u8>,
    pub database: String,
    pub client_plugin_name: String,
}

// impl<T> ClientHandshake<T> {
//     pub fn new() -> ClientHandshake<T> {
//         return ClientHandshake {
//             capability: 0,
//             collation: 0,
//             max_packet_size: 0,
//             username:
//         }
//     }
// }

use std::io::Cursor;
use std::io::Read;

pub fn parse_client_handshake(buf: &[u8]) -> Result<ClientHandshake, &'static str> {
    let mut pos : usize = 0;
    let mut cur = Cursor::new(buf);

	//capability
// 	c.capability = binary.LittleEndian.Uint32(data[:4])
// 	pos += 4

    let capability = cur.read_u32::<LittleEndian>().unwrap();

    // let ext_capability = cur.read_u16::<LittleEndian>().unwrap();

    let max_packet_size = cur.read_u32::<LittleEndian>().unwrap();
    // _ = cur.take(4)
// 	//skip max packet size
    pos += cur.position() as usize;

    let collation :u8 = buf[pos];
    pos += 1;

// 	//charset, skip, if you want to use another charset, use set names
// 	//c.collation = CollationId(data[pos])
// 	pos++

// 	//skip reserved 23[00]
	pos += 23;

// 	//user name

    let mut username : Vec<char> = Vec::new();
    while buf[pos] != '\0' as u8 {
        username.push(buf[pos] as char);
        pos += 1;
    }
    pos += 1;

    // let username = buf[pos..]
// 	c.user = string(data[pos : pos+bytes.IndexByte(data[pos:], 0)])
// 	pos += len(c.user) + 1

    // auth length and auth
    let authLen = buf[pos] as usize;
    if authLen > 0 {
        panic!("auth response more than zero");
    }
    // 	pos++
    pos += 1;
    // let auth : Vec<u8> = buf[pos..(pos+authLen)].to_vec();
    // pos += authLen;

// 	// auth := data[pos : pos+authLen]

// 	// checkAuth := CalcPassword(c.salt, []byte(c.server.cfg.Password))

// 	// if !bytes.Equal(auth, checkAuth) {
// 	// 	return NewDefaultError(ER_ACCESS_DENIED_ERROR, c.c.RemoteAddr().String(), c.user, "Yes")
// 	// }

// 	pos += authLen

    let mut hs = ClientHandshake {
        capability: capability,
        max_packet_size: max_packet_size,
        collation: collation,
        username: username.into_iter().collect(),
        database: String::new(),
        client_plugin_name: String::new(),
    };

    if buf[pos..].len() == 0 {
        return Ok(hs);
    }

	if (capability & CLIENT_CONNECT_WITH_DB) > 0 {
        let mut database : Vec<char> = Vec::new();
        while buf[pos] != '\0' as u8 {
            database.push(buf[pos] as char);
            pos += 1;
        }
        pos += 1;
        hs.database = database.into_iter().collect();
    }

	if (capability & CLIENT_PLUGIN_AUTH) > 0 {
        let mut client_plugin_name : Vec<char> = Vec::new();
        while buf[pos] != '\0' as u8 {
            client_plugin_name.push(buf[pos] as char);
            pos += 1;
        }
        pos += 1;
        hs.client_plugin_name = client_plugin_name.into_iter().collect();
    }

    return Ok(hs);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_client_handshake_simple() {
        // wiresharked
        let sample = [
            // 0x26, 0x00, 0x00, 0x01,  // packet meta
            0x05, 0xa6, 0xff, 0x01, 0x00, 0x00, 0x00, 0x01, 0x21,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x72, 0x6f, 0x6f, 0x74, 0x00, 0x00];

        let hs = parse_client_handshake(&sample).unwrap();

        assert_eq!(0x01ffa605, hs.capability);
        assert_eq!(33, hs.collation);
        assert_eq!(16777216, hs.max_packet_size);

        assert_eq!("root", hs.username);
        assert_eq!("", hs.database);
    }

    #[test]
    fn test_parse_client_handshake_eight() {
        let sample = [
            0x05, 0xa6, 0xff, 0x01, 0x00, 0x00, 0x00, 0x01, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x72, 0x6f, 0x6f, 0x74, 0x00, 0x00, 0x6d, 0x79, 0x73, 0x71, 0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69,
            0x76, 0x65, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00, 0x69, 0x03, 0x5f, 0x6f,
            0x73, 0x08, 0x6f, 0x73, 0x78, 0x31, 0x30, 0x2e, 0x31, 0x35, 0x0c, 0x5f, 0x63, 0x6c, 0x69, 0x65,
            0x6e, 0x74, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x08, 0x6c, 0x69, 0x62, 0x6d, 0x79, 0x73, 0x71, 0x6c,
            0x04, 0x5f, 0x70, 0x69, 0x64, 0x05, 0x33, 0x32, 0x37, 0x37, 0x34, 0x0f, 0x5f, 0x63, 0x6c, 0x69,
            0x65, 0x6e, 0x74, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x06, 0x35, 0x2e, 0x37, 0x2e,
            0x32, 0x38, 0x09, 0x5f, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x06, 0x78, 0x38, 0x36,
            0x5f, 0x36, 0x34, 0x0c, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x5f, 0x6e, 0x61, 0x6d, 0x65,
            0x05, 0x6d, 0x79, 0x73, 0x71, 0x6c,
        ];

        let hs = parse_client_handshake(&sample).unwrap();

        assert_eq!(0x01ffa605, hs.capability);
        assert_eq!(33, hs.collation);
        assert_eq!(16777216, hs.max_packet_size);

        assert_eq!("root", hs.username);
        assert_eq!("", hs.database);
        assert_eq!("mysql_native_password", hs.client_plugin_name);
        // assert_eq!(0, hs.auth.len());
    }
    #[test]
    fn test_parse_client_handshake_eight_with_db() {
        let sample = [
            0x0d, 0xa6, 0xff, 0x01, 0x00, 0x00, 0x00, 0x01, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x72, 0x6f, 0x6f, 0x74, 0x00, 0x00, 0x6d, 0x79, 0x73, 0x71, 0x6c, 0x00, 0x6d, 0x79, 0x73, 0x71,
            0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72,
            0x64, 0x00, 0x69, 0x03, 0x5f, 0x6f, 0x73, 0x08, 0x6f, 0x73, 0x78, 0x31, 0x30, 0x2e, 0x31, 0x35,
            0x0c, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x08, 0x6c, 0x69,
            0x62, 0x6d, 0x79, 0x73, 0x71, 0x6c, 0x04, 0x5f, 0x70, 0x69, 0x64, 0x05, 0x35, 0x31, 0x30, 0x38,
            0x39, 0x0f, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f,
            0x6e, 0x06, 0x35, 0x2e, 0x37, 0x2e, 0x32, 0x38, 0x09, 0x5f, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f,
            0x72, 0x6d, 0x06, 0x78, 0x38, 0x36, 0x5f, 0x36, 0x34, 0x0c, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61,
            0x6d, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x05, 0x6d, 0x79, 0x73, 0x71, 0x6c,
        ];

        let hs = parse_client_handshake(&sample).unwrap();

        assert_eq!(0x01ffa60d, hs.capability);
        assert_eq!(33, hs.collation);
        assert_eq!(16777216, hs.max_packet_size);

        assert_eq!("root", hs.username);
        assert_eq!("mysql", hs.database);
        assert_eq!("mysql_native_password", hs.client_plugin_name);
    }

    #[test]
    fn test_ok_packet() {
        let buf = ok_packet(DEFAULT_CAPABILITY);

        let expected = [
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        ].to_vec();
        assert_eq!(expected, buf);
    }
}
