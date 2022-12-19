use std::io::prelude::*;
use std::cmp::{Ord, Ordering};
use std::{io, usize};
use std::io::Write;

use etherparse::TcpHeaderSlice;
pub enum State {
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    TimeWait
}

impl State {
    fn is_synchronized(&self) -> bool {
        match *self {
            State:: SynRcvd => false,
            State:: Estab => true,
            State:: FinWait1 => true,
            State:: FinWait2 => true,
            State:: TimeWait => true
        }
    }
    
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader
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
    fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
        match start.cmp(&x) {
            Ordering::Equal => false,
            Ordering::Less => {
                // check is violated iff end is between start and x
                !(end >= start && end <= x)
            },
            Ordering::Greater => {
                // check is ok iff n is between u and a
                end < start && end > x
            }
        }
    }
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>, 
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a[u8]) -> io::Result<Option<Self>>{
            let mut buf = [0u8; 1500];
            if !tcph.syn() {
                // Only expected syn packet
                return Ok(None);
            }
            
            let iss = 0;
            let wnd = 10;
            let mut c = Connection{
                state: State:: SynRcvd,
                send: SendSequenceSpace { 
                    // decide on stuff we're sending
                    iss,
                    una: iss,
                    nxt: iss + 1,
                    wnd: wnd,
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
                tcp: etherparse::TcpHeader::new (
                    tcph.destination_port(), 
                    tcph.source_port(),
                    iss,
                    wnd),
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
            
            // syn_ack.acknowledgment_number = c.recv.nxt;
            c.tcp.syn = true;
            c.tcp.ack = true;
            c.write(nic, &[])?;
            // c.ip.set_payload_len(syn_ack.header_len() as usize + 0);
            // let unwritten = {
            //     let mut unwritten = &mut buf[..];
            //     c.ip.write(&mut unwritten);
            //     syn_ack.write(&mut unwritten);
            //     unwritten.len();
            // };
            
            // nic.send(&buf[..buf.len() - unwritten])?;
            Ok(Some(c))
        }
    
    fn write(
        &mut self,
        nic: &mut tun_tap::Iface,
        payload: &[u8]) -> io::Result<usize> {
            let mut buf = [0u8; 1500];
            self.tcp.sequence_number = self.send.nxt;
            self.tcp.acknowledgment_number = self.recv.nxt;
            let size = std::cmp::min(
                buf.len(), 
                self.tcp.header_len() as usize + self.ip.header_len() as usize + payload.len() as usize);
            self.ip.set_payload_len(self.tcp.header_len() as usize + payload.len());


            let mut unwritten = &mut buf[..];
            self.ip.write(&mut unwritten);
            self.tcp.write(&mut unwritten);
            let payload_bytes = unwritten.write(payload)?;
            let unwritten_len = unwritten.len();
            self.send.nxt = self.send.nxt.wrapping_add(payload_bytes as u32) ;
            if self.tcp.syn {
                self.send.nxt = self.send.nxt.wrapping_add(1);
                self.tcp.syn = false;
            }
            if self.tcp.fin {
                self.send.nxt = self.send.nxt.wrapping_add(1);
                self.tcp.fin = false;
            }
             
            nic.send(&buf[..buf.len() - unwritten_len])?;
            Ok(payload_bytes)
    }

    
    // fn send(
    //     &mut self,  
    //     nic: &mut tun_tap::Iface, 
    //     payload: &[u8]) -> io::Result<()> {
    //         self.tcp.sequence_number = self.send.nxt;
    //         self.tcp.acknowledgment_number = self.recv.nxt;
    //         self.ip.set_payload_len(self.tcp.header_len()) + payload.len();
    // }
    fn send_rst(
            &mut self,
            nic: &mut tun_tap::Iface,
        ) -> io::Result<()> {
            self.tcp.rst = true;
            // TODO: fix sequence numbers here
            // TODO: handle synchronized Reset
            self.tcp.sequence_number = 0;
            self.tcp.acknowledgment_number = 0;
            self.ip.set_payload_len(self.tcp.header_len() as usize);
            self.write(nic,&[])?;
            Ok(()) 
        }
    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a[u8]
    ) -> io::Result<()>{
        let ackn = tcph.acknowledgment_number();
        if !Self::is_between_wrapped(
            self.send.una, 
            ackn, 
            self.send.nxt.wrapping_add(1)) {
            if !self.state.is_synchronized() {
                // according to Reset Generation, we should send a RST
                self.send_rst(nic);
            }
            return Ok(())
        }
        self.send.una = ackn;
        let seqn = tcph.sequence_number();
        let mut slen = data.len() as u32;
        if tcph.fin() {
            slen += 1;
        };
        if tcph.syn() {
            slen += 1;
        };
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        let okay = if slen == 0 {
            // zero length-segment has seperate rules for acceptance
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    false
                } else {
                    true
                }
            } else if !Self::is_between_wrapped(
                self.recv.nxt.wrapping_sub(1), 
                seqn, 
                wend) {
                false
            } else {
                true
            } 
        } else {
            if self.recv.wnd == 0 {
                false
            } else if !Self::is_between_wrapped(self.recv.nxt.wrapping_sub(1), 
                seqn,
                wend) &&
                !Self::is_between_wrapped(self.recv.nxt.wrapping_sub(1), 
                seqn.wrapping_add(slen - 1),
                wend) {
                    false
                } else {
                    true
                }       
        };

        if !okay {
            self.write(nic, &[]);
            return Ok(());
        }
        // valid segment check

        self.recv.nxt = seqn.wrapping_add(slen);
        if !tcph.ack() {
            return Ok(())
        }

        let ackn = tcph.acknowledgment_number();
        if let State::SynRcvd = self.state {
            if Self::is_between_wrapped(
                self.send.una.wrapping_sub(1), 
                ackn, 
                self.send.nxt.wrapping_add(1)) {
                    self.state = State::Estab;
                } else {
                    // TODO: RST: <SEQ=SEG.ACK><CTL=RST>

                }
            //expect to get an ACK for our SYN 
            if !tcph.ack() {
                return Ok(())
            }
            // must have ACKed our SYN, since we detected at least one acked byte, and have
            // only sent one byte (the SYN)
            self.state = State::Estab;
            
            // now let's terminate the connection
            // TODO: needs to be stored in the retransmission queue
            self.tcp.fin = true;
            self.write(nic, &[])?;
            self.state = State::FinWait1;
        }
        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            if !Self::is_between_wrapped(
                self.send.una, 
                ackn, 
                self.send.nxt.wrapping_add(1)) {
                return Ok(())
            }
            self.send.una = ackn;
            // TODO
            assert!(data.is_empty());

            // TODO: needs to be stored in the retransmission queue

            if let State::Estab = self.state {
                self.tcp.fin = true;
                self.write(nic, &[])?;
                self.state = State::FinWait1;
            }


        }
        
        if let  State::FinWait1 = self.state {
            if !tcph.fin() || !data.is_empty() {

            }
        }

        if tcph.fin() {
            match self.state {
                State::FinWait2 => {
                    self.write(nic, &[])?;
                    self.state = State::TimeWait;
                }
                _ => unimplemented!()
            }
        }
        
        // State::Closing => {
        //     if !tcph.fin() || data.is_empty() {
        //         unimplemented!()
        //     }

        //     self.tcp.fin = false;
        //     self.write(nic, &[]);
        //     self.state = State::Closing;
        // }
    

        Ok(())
    }
    
}