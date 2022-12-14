use std::io::prelude::*;
use std::io;
pub enum State {
    SynRcvd,
    Estab,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header
}

struct SendSequenceSpace {
    // send unacknowledged
    una: u32,
    // send next
    nxt: u32,
    // send window
    wnd: u16,
    // send urgent pointer
    up: bool,
    // segment sequence number used for last window update 
    wl1: usize,
    // segment aknowledgment number used for last window update 
    wl2: usize,
    // initial send sequence number
    iss: u32
}

struct RecvSequenceSpace {
    // receive next
    nxt: u32,
    // receive window
    wnd: u16,
    // receive urgent pointer
    up: bool,
    // initial receive sequence number
    irs: u32
}


impl Connection {
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>, 
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a[u8]) -> io::Result<usize>{
            let mut buf = [0u8; 1500];
            if !tcph.syn() {
                // Only expected syn packet
                return Ok(None);
            }
            
            let iss = 0;
            let mut c = Connection{
                state: State:: SynRcvd,
                send: SendSequenceSpace { 
                    // decide on stuff we're sending
                    iss,
                    una: iss,
                    nxt: iss + 1,
                    wnd: 10,
                    up: false,
                    wl1: 0,
                    wl2: 0
                },
                recv: RecvSequenceSpace { 
                    // keep track of sender info
                    irs: tcph.sequence_number(),
                    nxt: tcph.sequence_number() + 1,
                    wnd: tcph.window_size(),
                    up: false,
                },
                ip: etherparse::Ipv4Header::new(
                    0, 
                    64,
                    etherparse::IpTrafficClass::Tcp,
                    [
                        iph.destination()[0],
                        iph.destination()[1],
                        iph.destination()[2],
                        iph.destination()[3]
                    ],
                    [
                        iph.source()[0],
                        iph.source()[1],
                        iph.source()[2],
                        iph.source()[3]
                    ]
                    )
            };

            // need to start establishing a connection
            let mut syn_ack = etherparse::TcpHeader::new (
                tcph.destination_port(), 
                tcph.source_port(),
                c.send.iss,
                c.send.wnd);
            syn_ack.acknowledgment_number = c.recv.nxt;
            syn_ack.syn = true;
            syn_ack.ack = true;
            let unwritten = {
                let mut unwritten = &mut buf[..];
                c.ip.write(&mut unwritten);
                syn_ack.write(&mut unwritten);
                unwritten.len();
            };
            
            nic.send(&buf[..unwritten])?;
            Ok(Some(c))
        }
    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a[u8]
    ) -> io::Result<()>{
        match self.state {
            State::SynRcvd => {
                //expect to get an ACK for our SYN 
            }
            State::Estab => {
                unimplemented!() 
            }
        }
    }
}