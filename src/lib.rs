use std::collections::{HashMap, VecDeque};
use::std::io::prelude::*;
use::std::io;
use std::sync::{Arc, Mutex, Condvar};
use std::thread;

use tcp::Quad;

mod tcp;

const SENDQUEUE_SIZE: usize = 1024; 

#[derive(Default)]
struct Foobar{
    manager: Mutex<ConnectionManager>,
    pending_var: Condvar,
    rcv_var: Condvar
}

type InterfaceHandle = Arc<Foobar>;
pub struct TcpStream{
    quad: Quad, 
    h: InterfaceHandle}

// enum InterfaceRequest {
//     Write{
//         quad: tcp::Quad,
//         bytes: Vec<u8>, 
//         ack: mpsc::Sender<usize>
//     },
//     Flush{
//         quad: tcp::Quad,
//         ack: mpsc::Sender<()>
//     },
//     Bind{
//         quad: tcp::Quad,
//         port: u16,
//         ack: mpsc::Sender<()>
//     },
    
//     Unbind,
//     Read{
//         quad: tcp::Quad,
//         max_length: usize,
//         read: mpsc::Sender<Vec<u8>>
//     },
//     Accept{
//         port: u16,
//         ack: mpsc::Sender<tcp::Quad>
//     },
// }

#[derive(Default)]
struct ConnectionManager {
    terminate: bool,
    connections: HashMap<tcp::Quad, tcp::Connection>,
    pending: HashMap<u16, VecDeque<Quad>>,
}

fn packet_loop(mut nic: tun_tap::Iface, ih: InterfaceHandle) -> io::Result<()>{
    let mut buf = [0u8; 1504];
    loop {
        // TODO: set a timeout for this recv for TCP timers or ConnectionManager::terminate

        let nbytes = nic.recv(&mut buf[..])?;

        // TODO: if self.terminate && Arc.get_stro

        // let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);
        // if eth_proto != 0x0800 {
        //     // not ipv4
        //     continue;
        // }

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[..nbytes]){
            Ok(iph) => {
                let src = iph.source_addr();
                let dst = iph.destination_addr();
                if iph.protocol() != 0x06 {
                    eprintln!("BAD PROTOCOL");
                    // not tcp
                    continue;
                }
                match etherparse::TcpHeaderSlice::from_slice(
                    &buf[iph.slice().len()..nbytes]) {
                    Ok(tcph) => {
                        use std::collections::hash_map::Entry; 
                        let datai = iph.slice().len() + tcph.slice().len();
                        let mut cmg = ih.manager.lock().unwrap();
                        let mut cm = &mut *cmg;
                        let q = tcp::Quad{
                            src: (src, tcph.source_port()),
                            dst: (dst, tcph.destination_port())
                        };
                        match cm.connections.entry(q){
                            Entry::Occupied(mut c) 
                            => {
                                let a =  c.get_mut().on_packet(
                                    &mut nic, 
                                    iph, 
                                    tcph, 
                                    &buf[datai..nbytes]
                                )?;
                                // TODO: compare before/after
                                drop(cmg);
                                if a.contains(tcp::Available::READ) {
                                    ih.rcv_var.notify_all()
                                }
                                if a.contains(tcp::Available::WRITE) {
                                    ih.rcv_var.notify_all()
                                }
                                
                            },
                            Entry::Vacant(e) => {
                                if let Some(pending) = cm
                                .pending
                                .get_mut(&tcph.destination_port()) {
                                    if let Some(c) = tcp::Connection::accept(
                                        &mut nic, 
                                        iph, 
                                        tcph, 
                                        &buf[datai..nbytes],
                                    )? {
                                        e.insert(c);
                                        pending.push_back(q);
                                        drop(cmg);
                                        ih.pending_var.notify_all()
                                        //TODO: wake up pending accept
                                    }
                                }
 
                            } 
                        }
                    },
                    Err(e) => {
                        eprintln!("ignoring weird tcp packet {:?}", e);
                    }
                }

            }
            Err(e) => {
                eprintln!("ignoring weird packet {:?}", e);
            }
        }
    }
}

pub struct Interface{
    ih: Option<InterfaceHandle>,
    jh: Option <thread::JoinHandle<io::Result<()>>>
}


impl Drop for Interface {
    fn drop(&mut self) {
        self.ih.as_mut().unwrap().manager.lock().unwrap().terminate = true;
        drop(self.ih.take());
        self.jh.
            take().
            expect("interface dropped more than once").
            join().
            unwrap().
            unwrap();
    }
}

impl Interface {
    pub fn new() -> io::Result<Self>  {
        let nic = tun_tap::Iface::without_packet_info(
            "tun0", 
            tun_tap::Mode::Tun)?;
        let ih: InterfaceHandle = Arc::default();
        let jh = {
            let ih = ih.clone();
            thread::spawn(move || {
            packet_loop(nic, ih)
        })};
         
        Ok (Interface {
            ih: Some(ih),
            jh: Some(jh),
        })
        
    }

    pub fn bind(&mut self, port: u16) -> io::Result<TcpListener> {
        use std::collections::hash_map::Entry;
        let mut cm = self.ih.as_mut().unwrap().manager.lock().unwrap();
        match cm.pending.entry(port) {
            Entry::Vacant(v) => {
                v.insert(VecDeque::new());
            },
            Entry::Occupied(_) => {
                return Err(io::Error::new(
                            io::ErrorKind::AddrInUse, 
                            "port already bound"
                        ));
            }
        }
        // TODO: something to start accepting SYN packets on `port`
        drop(cm);
        Ok(TcpListener
            {
                port, 
                h: self.ih.as_mut().unwrap().clone()
            })
    }
}

pub struct TcpListener{
    port: u16, 
    h: InterfaceHandle
    }

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut cm = self.h.manager.lock().unwrap();
        let pending = cm.
        pending.
        remove(&self.port).
        expect("port closed while listener still active");
        for quad in pending {
            //TODO: terminate cm.connections[quad]
            unimplemented!()
        }
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize>{   
        let mut cm = self.h.manager.lock().unwrap();
        let c = cm.connections.
                                get_mut(&self.quad).
                                ok_or_else(|| 
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "stream was terminated unexpectedly")
            )?;
        if c.unacked.len() >= SENDQUEUE_SIZE {
            // TODO: block
            return 
            Err(io::
                Error::new
                (io::ErrorKind::WouldBlock, "too many bytes buffered"
            ));
        }

        let nwrite = std::cmp::min(
                            buf.len(), 
                            SENDQUEUE_SIZE - c.unacked.len());
        c.unacked.extend(buf[..nwrite].iter());

        // TODO: wake up a writer

        Ok(nwrite)
    }
    fn flush(&mut self) -> io::Result<()>{ 
        let mut cm = self.h.manager.lock().unwrap();
        let c = cm.connections.
            get_mut(&self.quad).ok_or_else(|| 
            io::Error::new(
                io::ErrorKind::ConnectionAborted, 
                "stream was terminated unexpectedly")
            )?;
        if c.unacked.is_empty() {
            // TODO: block
            Ok(())
        }
        else {
            Err(io::
                Error::new
                (io::ErrorKind::WouldBlock, 
                "too many bytes buffered"
            ))
        }

     }

}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut[u8]) -> io::Result<usize>{ 
        let mut cm = self.h.manager.lock().unwrap();
        loop {
            let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "stream was terminated unexpectedly",
                )
            })?;

            if c.is_rcv_closed() && c.incoming.is_empty() {
                // no more data to read, and no need to block, because there won't be any more
                return Ok(0);
            }

            if !c.incoming.is_empty() {
                let mut nread = 0;
                let (head, tail) = c.incoming.as_slices();
                let hread = std::cmp::min(buf.len(), head.len());
                buf.copy_from_slice(&head[..hread]);
                nread += hread;
                let tread = std::cmp::min(buf.len() - nread, tail.len());
                buf.copy_from_slice(&tail[..tread]);
                nread += tread;
                drop(c.incoming.drain(..nread));
                return Ok(nread);
            }

            cm = self.h.rcv_var.wait(cm).unwrap();
        }


     }

}

impl TcpListener {
    pub fn accept(&mut self) -> io::Result<TcpStream> {
        let mut cm = self.h.manager.lock().unwrap();
        loop {
            if let Some(quad) = cm
            .pending
            .get_mut(&self.port)
            .expect("port closed while listener still active")
            .pop_front() {
                return Ok(TcpStream{
                    quad: quad, 
                    h: self.h.clone()
                });
            }
            cm = self.h.pending_var.wait(cm).unwrap();

        }

    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let mut cm = self.h.manager.lock().unwrap();
        if let Some(c) = cm.
        connections.
        remove(&self.quad){
            //TODO: send FIN on cm.connections[quad]
            unimplemented!()
        }
    }
}

impl TcpStream {
    pub fn shutdown (&self, how: std::net::Shutdown) -> io::Result<()> {
        unimplemented!()
    }
}