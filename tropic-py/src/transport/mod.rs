use std::fmt;

pub mod model_server;
pub mod usb_dongle;

use tropic_rs::transport::spi;

#[derive(Debug)]
pub enum Error {
    ModelServer(model_server::Error),
    UsbDongle(usb_dongle::Error),
}

impl spi::Error for Error {
    fn kind(&self) -> spi::ErrorKind {
        match self {
            Error::ModelServer(_) => spi::ErrorKind::Other,
            Error::UsbDongle(_) => spi::ErrorKind::Other,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ModelServer(e) => write!(f, "ModelServer error: {}", e),
            Error::UsbDongle(e) => write!(f, "Usb Dongle error: {}", e),
        }
    }
}

impl From<model_server::Error> for Error {
    fn from(err: model_server::Error) -> Self {
        Error::ModelServer(err)
    }
}

impl From<usb_dongle::Error> for Error {
    fn from(err: usb_dongle::Error) -> Self {
        Error::UsbDongle(err)
    }
}

pub struct StdDelay {}

impl tropic_rs::transport::DelayNs for StdDelay {
    fn delay_ns(&mut self, ns: u32) {
        std::thread::sleep(std::time::Duration::from_nanos(ns as u64));
    }
}

pub enum PyTropicTransport {
    UsbDongle(tropic_rs::transport::SpiDeviceTransport<usb_dongle::UsbDongleTransport, StdDelay>),
    ModelServer(tropic_rs::transport::SpiDeviceTransport<model_server::TcpTransport, StdDelay>),
}

impl PyTropicTransport {
    pub fn new_usb_dongle(port: &str, baud_rate: u32) -> Result<Self, Error> {
        let delay = StdDelay {};
        let usb_dongle_transport = usb_dongle::UsbDongleTransport::new(port, baud_rate)?;

        Ok(PyTropicTransport::UsbDongle(
            tropic_rs::transport::SpiDeviceTransport::new(usb_dongle_transport, delay),
        ))
    }

    pub fn new_model_server(ip_addr: std::net::IpAddr, port: u16) -> Result<Self, Error> {
        let delay = StdDelay {};
        let model_srv_tcp_transport = model_server::TcpTransport::connect(ip_addr, port)?;

        Ok(PyTropicTransport::ModelServer(
            tropic_rs::transport::SpiDeviceTransport::new(model_srv_tcp_transport, delay),
        ))
    }
}

impl tropic_rs::transport::TropicTransport for PyTropicTransport {
    fn transfer_in_place(&mut self, buf: &mut [u8]) -> Result<(), tropic_rs::transport::Error> {
        match self {
            Self::UsbDongle(t) => t.transfer_in_place(buf),
            Self::ModelServer(t) => t.transfer_in_place(buf),
        }
    }

    fn write(&mut self, req: &[u8]) -> Result<(), tropic_rs::transport::Error> {
        match self {
            Self::UsbDongle(t) => t.write(req),
            Self::ModelServer(t) => t.write(req),
        }
    }

    fn read<const N: usize>(
        &mut self,
    ) -> Result<tropic_rs::l1::Response<N>, tropic_rs::transport::Error> {
        match self {
            Self::UsbDongle(t) => t.read(),
            Self::ModelServer(t) => t.read(),
        }
    }
}
