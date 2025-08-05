use usb_device::{
    bus::InterfaceNumber,
    class::{ControlIn, ControlOut, UsbClass},
    control,
    descriptor::DescriptorWriter,
    endpoint::{EndpointIn, EndpointOut},
};

pub use usb_device::{
    bus::UsbBusAllocator,
    prelude::{UsbDeviceBuilder, UsbVidPid},
};

use super::consts::MAX_PACKET_SIZE;

///
pub struct RawUsbClass<'a, B: usb_device::bus::UsbBus> {
    raw_if: InterfaceNumber,
    in_endpoint: EndpointIn<'a, B>,
    out_endpoint: EndpointOut<'a, B>,
}

impl<'a, B: usb_device::bus::UsbBus> RawUsbClass<'a, B> {
    pub fn new<'alloc: 'a>(alloc: &'alloc UsbBusAllocator<B>) -> Self {
        RawUsbClass {
            raw_if: alloc.interface(),
            in_endpoint: alloc.bulk(MAX_PACKET_SIZE),
            out_endpoint: alloc.bulk(MAX_PACKET_SIZE),
        }
    }

    pub fn write(&self, data: &[u8]) -> usb_device::Result<usize> {
        self.in_endpoint.write(data)
    }

    pub fn read(&self, buf: &mut [u8]) -> usb_device::Result<usize> {
        self.out_endpoint.read(buf)
    }
}

impl<B: usb_device::bus::UsbBus> UsbClass<B> for RawUsbClass<'_, B> {
    fn get_configuration_descriptors(
        &self,
        writer: &mut DescriptorWriter,
    ) -> usb_device::Result<()> {
        writer.interface(self.raw_if, 0xFF, 0x00, 0x00)?;
        writer.endpoint(&self.in_endpoint)?;
        writer.endpoint(&self.out_endpoint)?;
        Ok(())
    }

    fn control_in(&mut self, xfer: ControlIn<B>) {
        let req = xfer.request();
        if req.request_type == control::RequestType::Standard {
            xfer.reject().ok();
        } else if req.request_type == control::RequestType::Vendor {
            xfer.reject().ok();
        } else {
            xfer.reject().ok();
        }
    }

    fn control_out(&mut self, xfer: ControlOut<B>) {
        let req = xfer.request();
        if req.request_type == control::RequestType::Standard {
            xfer.reject().ok();
        } else if req.request_type == control::RequestType::Vendor {
            xfer.reject().ok();
        } else {
            xfer.reject().ok();
        }
    }
}
