#![no_std]

pub extern crate rp235x_hal as hal;

use hal::rom_data::sys_info_api::ChipInfo;

hal::bsp_pins! {
    Gpio16 {
        name: miso,
        aliases: { FunctionSpi, PullNone: MisoPin }
    }
    Gpio17 {
        name: cs,
        aliases: { FunctionSpi, PullNone: CsPin }
    }
    Gpio18 {
        name: sclk,
        aliases: { FunctionSpi, PullNone: SclkPin }
    }
    Gpio19 {
        name: mosi,
        aliases: { FunctionSpi, PullNone: MosiPin }
    }

    Gpio25 {
        name: led,
        aliases: { FunctionPio0, PullNone: LedPin }
    }


}

pub fn get_unique_id() -> Option<u64> {
    let chip_info = rp235x_hal::rom_data::sys_info_api::chip_info()
        .unwrap()
        .map(|info| {
            // convert
            ((info.device_id as u64) << 32) | (info.wafer_id as u64)
        });
    chip_info
}

pub fn get_chip_info() -> Option<ChipInfo> {
    rp235x_hal::rom_data::sys_info_api::chip_info().unwrap()
}
