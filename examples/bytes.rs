extern crate mysql_proxy;
use mysql_proxy::*;
use mysql_proxy::protocol::*;

use std::str;

fn main() {
  // let ok = ;
  print_packet_bytes(&ok_packet())
}

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
