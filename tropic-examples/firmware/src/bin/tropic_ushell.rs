#![no_std]
#![no_main]

use firmware::get_chip_info;

use rp235x_hal as hal;

// Some things we need
use core::fmt::Write;

use hal::clocks::Clock;
use hal::fugit::RateExtU32;

// USB Device support
use usb_device::{class_prelude::*, prelude::*};

// USB Communications Class Device support
use usbd_serial::SerialPort;

// loggings
use defmt::{error, info, unwrap};
use defmt_rtt as _; // Import this to link the RTT logger
use panic_probe as _; // The panic handler for defmt

// serial shell
use ushell;

use tropic_rs::Tropic01;

/// Tell the Boot ROM about our application
#[link_section = ".start_block"]
#[used]
pub static IMAGE_DEF: hal::block::ImageDef = hal::block::ImageDef::secure_exe();

// External high-speed crystal on the Raspberry Pi Pico 2 board is 12 MHz.
/// Adjust if your board has a different frequency
const XTAL_FREQ_HZ: u32 = 12_000_000u32;

/// Ushell stuff
const USHELL_PROMPT: &str = "#> ";
const USHELL_CR: &str = "\r\n";
const USHELL_AUTOCOMPLETE: [&str; 10] = [
    "ping",
    "rp235x-chip-id",
    "tropic-chip-id",
    "tropic-chip-status",
    "tropic-riscv-fw",
    "tropic-spect-fw",
    "tropic-riscv-fw-log",
    "tropic-cert-store",
    "clear",
    "help",
];
const USHELL_HELP: &str = "\r\n\
\x1b[32mTropic Shell\x1b[0m v0.1\r\n\r\n\
USAGE:\r\n\
\tcommand [arg]\r\n\r\n\
RP235X COMMANDS:\r\n\
\tping                 Ping the device\r\n\
\trp235x-chip-id       Get chip ID\r\n\r\n\
Tropic COMMANDS:\r\n\
\ttropic-chip-status   Get chip status\r\n\
\ttropic-chip-id       Get chip ID\r\n\
\ttropic-riscv-fw      Get riscv firmware version\r\n\
\ttropic-spect-fw      Get spect firmware version\r\n\
\ttropic-riscv-fw-log  Get riscv firmware log\r\n
\ttropic-cert-store    Get cert store log\r\n\r\n\
COMMANDS:\r\n\
\tclear     Clear the screen\r\n\
\thelp      Print this message\r\n\r\n
";
// CONTROL KEYS:\r\n\
// \tCtrl+D    Start animation\r\n\
// \tCtrl+C    Stop animation\r\n\
// \tCtrl+S    Increment animation frequency\r\n\
// \tCtrl+X    Decrement animation frequency\r\n\

fn format_text_block<const N: usize>(text: &str) -> heapless::String<N> {
    let mut formatted_text = heapless::String::new();

    // Iterate over the bytes of the string
    for b in text.chars() {
        formatted_text.push(b).ok();
        if b == '\n' {
            // If we see a newline, write a carriage return first
            formatted_text.push_str("\r").ok();
        }
    }
    formatted_text
}

#[hal::entry]
fn main() -> ! {
    // Grab our singleton objects
    let mut pac = unwrap!(hal::pac::Peripherals::take());

    // Set up the watchdog driver - needed by the clock setup code
    let mut watchdog = hal::Watchdog::new(pac.WATCHDOG);

    // Configure the clocks
    let clocks = unwrap!(hal::clocks::init_clocks_and_plls(
        XTAL_FREQ_HZ,
        pac.XOSC,
        pac.CLOCKS,
        pac.PLL_SYS,
        pac.PLL_USB,
        &mut pac.RESETS,
        &mut watchdog,
    ));

    let timer = hal::Timer::new_timer0(pac.TIMER0, &mut pac.RESETS, &clocks);

    // Set up the USB driver
    let usb_bus = UsbBusAllocator::new(hal::usb::UsbBus::new(
        pac.USB,
        pac.USB_DPRAM,
        clocks.usb_clock,
        true,
        &mut pac.RESETS,
    ));

    // Set up the USB Communications Class Device driver
    let serial = SerialPort::new(&usb_bus);

    info!("setting up gpio");
    // The single-cycle I/O block controls our GPIO pins
    let sio = hal::Sio::new(pac.SIO);

    // Set the pins to their default state
    let pins = hal::gpio::Pins::new(
        pac.IO_BANK0,
        pac.PADS_BANK0,
        sio.gpio_bank0,
        &mut pac.RESETS,
    );

    info!("setting up spi");
    // These are implicitly used by the spi driver if they are in the correct mode
    let spi_mosi = pins.gpio19.into_function::<hal::gpio::FunctionSpi>();
    let spi_miso = pins.gpio16.into_function::<hal::gpio::FunctionSpi>();
    let spi_sclk = pins.gpio18.into_function::<hal::gpio::FunctionSpi>();
    let spi_bus = hal::spi::Spi::<_, _, _, 8>::new(pac.SPI0, (spi_mosi, spi_miso, spi_sclk));

    let mut cs_pin = pins.gpio17.into_push_pull_output();

    // Exchange the uninitialised SPI driver for an initialised one
    let spi_bus = spi_bus.init(
        &mut pac.RESETS,
        clocks.peripheral_clock.freq(),
        5.MHz(),
        embedded_hal::spi::MODE_0,
    );

    // Wrap the SPI bus and CS pin in a SpiDevice for embedded-hal compatibility
    let spi_device =
        embedded_hal_bus::spi::ExclusiveDevice::new(spi_bus, &mut cs_pin, timer).unwrap();

    info!("setting up tropci_01");
    let mut tropci_01 =
        Tropic01::<_, _, tropic_cert_store::nom_decoder::NomDecoder>::new(spi_device, timer);

    // Create a USB device with a fake VID and PID
    let mut usb_dev = UsbDeviceBuilder::new(&usb_bus, UsbVidPid(0x16c0, 0x27dd))
        .strings(&[StringDescriptors::default()
            .manufacturer("Craft")
            .product("Tropic Shell")
            .serial_number("TEST")])
        .unwrap()
        .max_packet_size_0(64)
        .unwrap()
        .device_class(2) // from: https://www.usb.org/defined-class-codes
        .build();

    let mut ping_cnt = 0;

    info!("setting up ushell");
    let autocomplete = ushell::autocomplete::StaticAutocomplete(USHELL_AUTOCOMPLETE);
    let history: ushell::history::LRUHistory<32, 4> = ushell::history::LRUHistory::default();
    let mut shell = ushell::UShell::new(serial, autocomplete, history);

    loop {
        if usb_dev.poll(&mut [&mut shell]) {
            match shell.poll() {
                Ok(Some(ushell::Input::Command((cmd, args)))) => {
                    match cmd {
                        "ping" => {
                            ping_cnt += 1;
                            write!(shell, "{0:}pong {ping_cnt}{0:}", USHELL_CR).ok();
                        }
                        "rp235x-chip-id" => {
                            if let Some(chip_info) = get_chip_info() {
                                write!(
                                    shell,
                                    "{0:}device_id: {1:?}{0:}wafer_id: {2:?}{0:}",
                                    USHELL_CR, chip_info.device_id, chip_info.wafer_id,
                                )
                                .ok();
                            } else {
                                write!(shell, "{0:}no chip info{0:}", USHELL_CR).ok();
                            }
                        }
                        "tropic-chip-status" => match tropci_01.get_chip_status() {
                            Ok(status) => {
                                let _ = write!(
                                    shell,
                                    "{0:}tropic chip status: {status:?}{0:}",
                                    USHELL_CR,
                                );
                            }
                            Err(e) => {
                                write!(shell, "{0:}error: {e:?}{0:}", USHELL_CR).ok();
                            }
                        },
                        "tropic-chip-id" => match tropci_01.get_chip_id() {
                            Ok(chip_id) => {
                                write!(
                                    shell,
                                    "{0:}tropic chip_id information:{0:}{chip_id}{0:}",
                                    USHELL_CR,
                                )
                                .ok();
                            }
                            Err(e) => {
                                error!("unable to get chip id");
                                write!(shell, "{0:}error: {e:?}{0:}", USHELL_CR).ok();
                            }
                        },
                        "tropic-cert-store" => {
                            let mut cert_buffer = [0_u8; tropic_rs::l2::CERT_BUFFER_LEN];
                            match tropci_01.get_x509_certificate(&mut cert_buffer) {
                                Ok(cert_store) => {
                                    write!(
                                        shell,
                                        "{0:}tropic cvertificate:{0:}{cert_store:?}{0:}",
                                        USHELL_CR,
                                    )
                                    .ok();
                                }
                                Err(e) => {
                                    error!("unable to get x509 certificate");
                                    write!(shell, "{0:}error: {e:?}{0:}", USHELL_CR).ok();
                                }
                            }
                        }
                        "tropic-riscv-fw" => match tropci_01.get_riscv_firmware_version() {
                            Ok(version) => {
                                write!(
                                    shell,
                                    "{0:}tropic riscv firmware version: {version:?}{0:}",
                                    USHELL_CR
                                )
                                .ok();
                            }
                            Err(e) => {
                                error!("unable to get riscv firmware version");
                                write!(shell, "{0:}error: {e:?}{0:}", USHELL_CR).ok();
                            }
                        },
                        "tropic-spect-fw" => match tropci_01.get_spect_firmware_version() {
                            Ok(version) => {
                                write!(
                                    shell,
                                    "{0:}tropic spect firmware version: {version:?}{0:}",
                                    USHELL_CR
                                )
                                .ok();
                            }
                            Err(e) => {
                                error!("unable to get spect firmware version");
                                write!(shell, "{0:}error: {e:?}{0:}", USHELL_CR).ok();
                            }
                        },
                        "tropic-riscv-fw-log" => match tropci_01.get_riscv_firmware_log() {
                            Ok(log) => {
                                // write!(shell, "{0:}tropic log: {log:?}{0:}", USHELL_CR).ok();

                                let mut unformatted = heapless::String::<255>::new();
                                write!(unformatted, "{log}").ok();
                                let formatted_log = format_text_block::<280>(&unformatted);

                                write!(shell, "{0:}tropic log:{0:}{formatted_log}{0:}", USHELL_CR)
                                    .ok();
                            }
                            Err(e) => {
                                error!("unable to get log");
                                write!(shell, "{0:}error: {e:?}{0:}", USHELL_CR).ok();
                            }
                        },
                        "help" | "?" => {
                            shell.write_str(USHELL_HELP).ok();
                        }
                        "clear" => {
                            shell.clear().ok();
                        }
                        "" => {
                            shell.write_str(USHELL_CR).ok();
                        }
                        _ => {
                            write!(shell, "{0:}unsupported command{0:}", USHELL_CR).ok();
                        }
                    }
                    shell.write_str(USHELL_PROMPT).ok();
                }
                Err(ushell::ShellError::WouldBlock) => continue,
                _ => {}
            }
        }
    }
}

/// Program metadata for `picotool info`
#[link_section = ".bi_entries"]
#[used]
pub static PICOTOOL_ENTRIES: [hal::binary_info::EntryAddr; 5] = [
    hal::binary_info::rp_cargo_bin_name!(),
    hal::binary_info::rp_cargo_version!(),
    hal::binary_info::rp_program_description!(c"Tropic Shell Example"),
    hal::binary_info::rp_cargo_homepage_url!(),
    hal::binary_info::rp_program_build_attribute!(),
];
