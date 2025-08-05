use std::{time::Duration, vec};

use nusb::{
    io::{EndpointRead, EndpointWrite},
    transfer::{Bulk, Direction, In, Out, Recipient},
    Device,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

// Bring in your shared protocol constants
pub const VENDOR_ID: u16 = 0x1234; //
pub const PRODUCT_ID: u16 = 0x5678; //

pub const CUSTOM_INTERFACE_NUMBER: u8 = 0;

pub const EP_IN_ADDRESS: u8 = 0x81;
pub const EP_OUT_ADDRESS: u8 = 0x01;

pub const MAX_PACKET_SIZE: u16 = 64;

#[derive(thiserror::Error, Debug)]
pub enum UsbCommunicationError {
    #[error("Device not found")]
    DeviceNotFound,
    #[error("USB communication error: {0}")]
    NusbError(#[from] nusb::Error),
    #[error("IO error")]
    Io(#[from] std::io::Error),
    // Add other specific errors if needed
}

pub struct RawUsbDevice {
    device: Device,
    endpoint_in: EndpointRead<Bulk>,
    endpoint_out: EndpointWrite<Bulk>,
}

impl std::fmt::Debug for RawUsbDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MyUsbDevice")
            .field("device", &self.device)
            .finish()
    }
}

impl RawUsbDevice {
    pub async fn connect() -> Result<Self, UsbCommunicationError> {
        let devices = nusb::list_devices().await?;

        for info in devices {
            println!("Device: {:?}", info);
            if info.vendor_id() == VENDOR_ID && info.product_id() == PRODUCT_ID {
                println!("Found device: {:?}", info);
                let device = info.open().await?;
                let interface = device.claim_interface(CUSTOM_INTERFACE_NUMBER).await?;

                let endpoint_in = interface
                    .endpoint::<Bulk, In>(EP_IN_ADDRESS)?
                    .reader(MAX_PACKET_SIZE as usize)
                    .with_num_transfers((MAX_PACKET_SIZE / 16) as usize);
                let endpoint_out = interface
                    .endpoint::<Bulk, Out>(EP_OUT_ADDRESS)?
                    .writer(MAX_PACKET_SIZE as usize)
                    .with_num_transfers((MAX_PACKET_SIZE / 16) as usize);

                return Ok(RawUsbDevice {
                    device,
                    endpoint_in,
                    endpoint_out,
                });
            }
        }

        Err(UsbCommunicationError::DeviceNotFound)
    }

    /// Sends raw bytes to the device via the OUT endpoint.
    pub async fn write_bytes(&mut self, data: &[u8]) -> Result<usize, UsbCommunicationError> {
        if data.is_empty() {
            return Ok(0);
        }
        self.endpoint_out.write_all(data).await?;
        Ok(data.len())
    }

    /// Reads raw bytes from the device via the IN endpoint.
    ///
    /// `buffer_size`: The maximum number of bytes to read in this transfer.
    ///                Should typically be `MAX_PACKET_SIZE` or a multiple thereof.
    pub async fn read_bytes(
        &mut self,
        buffer_size: usize,
    ) -> Result<Vec<u8>, UsbCommunicationError> {
        let mut buf = vec![0u8; buffer_size];

        let _count = self.endpoint_in.read_exact(&mut buf).await?;
        Ok(buf)
    }

    // pub async fn wait_closed(&self) {
    //     self.device
    // }

    // You could add higher-level functions here that use your `Command` enum
    pub async fn send_command(&self, command: &str) -> Result<(), UsbCommunicationError> {
        todo!();
        Ok(())
    }
}
