#![no_std]
#![no_main]

// Some things we need
use core::fmt::Write;

use embedded_hal::delay::DelayNs;
use firmware::get_chip_info;

use rp235x_hal::{self as hal};

use hal::clocks::Clock;
use hal::fugit::RateExtU32;

// USB Device support
use usb_device::{class_prelude::*, prelude::*};

// USB Communications Class Device support
use usbd_serial::SerialPort;

// Secure RNG
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use rand_core_compat::Rng06;

// loggings
use defmt::{error, info, unwrap};
use defmt_rtt as _; // Import this to link the RTT logger
use panic_probe as _; // The panic handler for defmt

use tropic_rs::{
    common::config::{Debug, Sensor, StartUp},
    Tropic01,
};

const AUTOCOMPLETE_LEN: usize = 15;
const CMD_LEN: usize = 64;

type UsbUshell<'a> = ushell::UShell<
    SerialPort<'a, rp235x_hal::usb::UsbBus>,
    ushell::autocomplete::StaticAutocomplete<AUTOCOMPLETE_LEN>,
    ushell::history::LRUHistory<CMD_LEN, 4>,
    CMD_LEN,
>;
type TropicInst<'a> = Tropic01<
    embedded_hal_bus::spi::ExclusiveDevice<
        rp235x_hal::Spi<
            rp235x_hal::spi::Enabled,
            rp235x_hal::pac::SPI0,
            (
                rp235x_hal::gpio::Pin<
                    rp235x_hal::gpio::bank0::Gpio19,
                    rp235x_hal::gpio::FunctionSpi,
                    rp235x_hal::gpio::PullDown,
                >,
                rp235x_hal::gpio::Pin<
                    rp235x_hal::gpio::bank0::Gpio16,
                    rp235x_hal::gpio::FunctionSpi,
                    rp235x_hal::gpio::PullDown,
                >,
                rp235x_hal::gpio::Pin<
                    rp235x_hal::gpio::bank0::Gpio18,
                    rp235x_hal::gpio::FunctionSpi,
                    rp235x_hal::gpio::PullDown,
                >,
            ),
        >,
        &'a mut rp235x_hal::gpio::Pin<
            rp235x_hal::gpio::bank0::Gpio17,
            rp235x_hal::gpio::FunctionSio<rp235x_hal::gpio::SioOutput>,
            rp235x_hal::gpio::PullDown,
        >,
        rp235x_hal::Timer<rp235x_hal::timer::CopyableTimer0>,
    >,
    rp235x_hal::Timer<rp235x_hal::timer::CopyableTimer0>,
    tropic_cert_store::nom_decoder::NomDecoder,
>;
type TropicCertStore<'a> =
    tropic_rs::cert_store::CertStore<tropic_cert_store::nom_decoder::NomCertificate<'a>>;

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
const USHELL_AUTOCOMPLETE: [&str; AUTOCOMPLETE_LEN] = [
    "rp235x-ping",
    "rp235x-chip-id",
    "tropic-chip-id",
    "tropic-chip-status",
    "tropic-riscv-fw",
    "tropic-spect-fw",
    "tropic-riscv-fw-log",
    "tropic-restart",
    "tropic-cert-store",
    "tropic-session-create",
    "tropic-ping",
    "tropic-pairing-key-read",
    "tropic-config-read",
    "clear",
    "help",
];
const USHELL_HELP: &str = "\r\n\
\x1b[32mTropic Shell\x1b[0m v0.1\r\n\r\n\
USAGE:\r\n\
\tcommand [arg]\r\n\r\n\
RP235X COMMANDS:\r\n\
\trp235x-ping                 Ping the device\r\n\
\trp235x-chip-id       Get chip ID\r\n\r\n\
Tropic COMMANDS:\r\n\
\ttropic-chip-status               Get chip status\r\n\
\ttropic-chip-id                   Get chip ID\r\n\
\ttropic-riscv-fw                  Get riscv firmware version\r\n\
\ttropic-spect-fw                  Get spect firmware version\r\n\
\ttropic-riscv-fw-log              Get riscv firmware log\r\n\
\ttropic-restart <mode>            Restartr tropic chip, modes: 0 = reboot, 1 = maintanance \r\n\
\ttropic-cert-store                Load tropic certificate store\r\n\
\r\n\
Tropic session COMMANDS:\r\n\
\ttropic-session-create   <key-slot>   Create a new session\r\n\
\ttropic-ping                          Ping tropic chip\r\n\
\ttropic-pairing-key-read <key-slot>   Read pairing key\r\n\
\ttropic-config-read      <reg-addr>   Read config object\r\n\r\n\
\r\n\
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

    let mut timer = hal::Timer::new_timer0(pac.TIMER0, &mut pac.RESETS, &clocks);

    // setup cryptographically secure rng
    let rosc_unitialized = rp235x_hal::rosc::RingOscillator::new(pac.ROSC);
    let mut rosc = rosc_unitialized.initialize();
    let mut rosc_compat = Rng06(&mut rosc);
    let mut seed = [0u8; 32];
    rosc_compat.fill_bytes(&mut seed);
    let mut rng = ChaCha20Rng::from_seed(seed);

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

    let mut cert_buf = [0_u8; tropic_rs::l2::CERT_BUFFER_LEN];
    let mut cert_store_opt = None;
    let mut session_opt = None;

    info!("setting up ushell");
    let autocomplete = ushell::autocomplete::StaticAutocomplete(USHELL_AUTOCOMPLETE);
    let history: ushell::history::LRUHistory<CMD_LEN, 4> = ushell::history::LRUHistory::default();
    let mut shell = ushell::UShell::new(serial, autocomplete, history);

    loop {
        if usb_dev.poll(&mut [&mut shell]) {
            match shell.poll() {
                Ok(Some(ushell::Input::Command((cmd, args)))) => {
                    // move args into a buffer that has a contained lifetime
                    // otherwhise passing args to the handlers will confuse the borrow checker
                    let mut args_buf = heapless::String::<CMD_LEN>::new();
                    args_buf.push_str(args).ok();
                    match cmd {
                        "m0" => {
                            // macro 0
                            handle_tropic_restart(&mut shell, &mut tropci_01, 0.into())
                                .map_err(|err| {
                                    error!("error while callingrestart handler");
                                    write!(shell, "{0:}error: {err}{0:}", USHELL_CR).ok();
                                })
                                .ok();
                            timer.delay_ms(100u32);

                            cert_store_opt = None;
                            handle_tropic_cert_store(
                                &mut shell,
                                &mut tropci_01,
                                &mut cert_buf,
                                &mut cert_store_opt,
                            )
                            .map_err(|err| {
                                error!("error while calling cert store handler");
                                write!(shell, "{0:}error: {err}{0:}", USHELL_CR).ok();
                            })
                            .ok();
                            timer.delay_ms(100u32);

                            handle_tropic_session_create(
                                &mut shell,
                                &mut tropci_01,
                                &mut rng,
                                &mut cert_store_opt,
                                &mut session_opt,
                                0.into(),
                            )
                            .map_err(|err| {
                                error!("error while calling session create handler");
                                write!(shell, "{0:}error: {err}{0:}", USHELL_CR).ok();
                            })
                            .ok();
                            timer.delay_ms(100u32);

                            handle_tropic_ping(
                                &mut shell,
                                &mut tropci_01,
                                &mut session_opt,
                                args_buf,
                            )
                            .map_err(|err| {
                                error!("error while calling ping handler");
                                write!(shell, "{0:}error: {err}{0:}", USHELL_CR).ok();
                            })
                            .ok();
                        }
                        "rp235x-ping" => handle_ping(&mut shell, &mut ping_cnt),
                        "rp235x-chip-id" => handle_rp235x_chip_id(&mut shell),
                        "tropic-chip-status" => {
                            handle_tropic_chip_status(&mut shell, &mut tropci_01)
                                .map_err(|err| {
                                    error!("error while calling chip status handler");
                                    write!(shell, "{0:}error: {err}{0:}", USHELL_CR).ok();
                                })
                                .ok();
                        }
                        "tropic-chip-id" => {
                            handle_tropic_chip_id(&mut shell, &mut tropci_01)
                                .map_err(|err| {
                                    error!("error while calling chip id handler");
                                    write!(shell, "{0:}error: {err}{0:}", USHELL_CR).ok();
                                })
                                .ok();
                        }
                        "tropic-cert-store" => {
                            cert_store_opt = None;
                            handle_tropic_cert_store(
                                &mut shell,
                                &mut tropci_01,
                                &mut cert_buf,
                                &mut cert_store_opt,
                            )
                            .map_err(|err| {
                                error!("error while calling cert store handler");
                                write!(shell, "{0:}error: {err}{0:}", USHELL_CR).ok();
                            })
                            .ok();
                        }
                        "tropic-riscv-fw" => {
                            handle_tropic_riscv_fw(&mut shell, &mut tropci_01)
                                .map_err(|err| {
                                    error!("error while calling riscv fw handler");
                                    write!(shell, "{0:}error: {err}{0:}", USHELL_CR).ok();
                                })
                                .ok();
                        }
                        "tropic-spect-fw" => {
                            handle_tropic_spect_fw(&mut shell, &mut tropci_01)
                                .map_err(|err| {
                                    error!("error while calling spect fw handler");
                                    write!(shell, "{0:}error: {err}{0:}", USHELL_CR).ok();
                                })
                                .ok();
                        }
                        "tropic-riscv-fw-log" => {
                            handle_tropic_riscv_fw_log(&mut shell, &mut tropci_01)
                                .map_err(|err| {
                                    error!("error while calling riscv fw log handler");
                                    write!(shell, "{0:}error: {err}{0:}", USHELL_CR).ok();
                                })
                                .ok();
                        }
                        "tropic-restart" => {
                            handle_tropic_restart(&mut shell, &mut tropci_01, args_buf)
                                .map_err(|err| {
                                    error!("error while calling restart handler");
                                    write!(shell, "{0:}error: {err}{0:}", USHELL_CR).ok();
                                })
                                .ok();
                        }
                        "tropic-session-create" => {
                            handle_tropic_session_create(
                                &mut shell,
                                &mut tropci_01,
                                &mut rng,
                                &mut cert_store_opt,
                                &mut session_opt,
                                args_buf,
                            )
                            .map_err(|err| {
                                error!("error while calling restart handler");
                                write!(shell, "{0:}error: {err}{0:}", USHELL_CR).ok();
                            })
                            .ok();
                        }
                        "tropic-ping" => {
                            handle_tropic_ping(
                                &mut shell,
                                &mut tropci_01,
                                &mut session_opt,
                                args_buf,
                            )
                            .map_err(|err| {
                                error!("error while calling ping handler");
                                write!(shell, "{0:}error: {err}{0:}", USHELL_CR).ok();
                            })
                            .ok();
                        }
                        "tropic-pairing-key-read" => {
                            handle_tropic_pairing_key_read(
                                &mut shell,
                                &mut tropci_01,
                                &mut session_opt,
                                args_buf,
                            )
                            .map_err(|err| {
                                error!("error while calling payring_key_read handler");
                                write!(shell, "{0:}error: {err}{0:}", USHELL_CR).ok();
                            })
                            .ok();
                        }
                        "tropic-config-read" => {
                            handle_tropic_config_read(
                                &mut shell,
                                &mut tropci_01,
                                &mut session_opt,
                                args_buf,
                            )
                            .map_err(|err| {
                                error!("error while calling config_read handler");
                                write!(shell, "{0:}error: {err}{0:}", USHELL_CR).ok();
                            })
                            .ok();
                        }
                        "help" | "?" => handle_help(&mut shell),
                        "clear" => handle_clear(&mut shell),
                        "" => handle_empty(&mut shell),
                        _ => handle_unsupported(&mut shell),
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

enum Error {
    NoSession,
    NoCertStore,
    ArgMissing,
    WrongArg,
    Tropic(tropic_rs::Error),
    CertStore(tropic_rs::cert_store::CertStoreError),
    Utf8(core::str::Utf8Error),
    Fmt(core::fmt::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::NoSession => write!(f, "session not intialized"),
            Error::NoCertStore => write!(f, "cert store not intialized"),
            Error::ArgMissing => write!(f, "argument missing"),
            Error::WrongArg => write!(f, "wrong argument"),
            Error::Tropic(e) => write!(f, "{e:?}"),
            Error::CertStore(e) => write!(f, "{e:?}"),
            Error::Utf8(e) => write!(f, "{e:?}"),
            Error::Fmt(e) => write!(f, "{e:?}"),
        }
    }
}

impl From<tropic_rs::Error> for Error {
    fn from(e: tropic_rs::Error) -> Self {
        Error::Tropic(e)
    }
}

impl From<tropic_rs::cert_store::CertStoreError> for Error {
    fn from(e: tropic_rs::cert_store::CertStoreError) -> Self {
        Error::CertStore(e)
    }
}

impl From<core::str::Utf8Error> for Error {
    fn from(e: core::str::Utf8Error) -> Self {
        Error::Utf8(e)
    }
}

impl From<core::fmt::Error> for Error {
    fn from(e: core::fmt::Error) -> Self {
        Error::Fmt(e)
    }
}

// Handlers
fn handle_ping(shell: &mut UsbUshell, ping_cnt: &mut u32) {
    *ping_cnt += 1;
    write!(shell, "{0:}pong {1}{0:}", USHELL_CR, ping_cnt).ok();
}

fn handle_rp235x_chip_id(shell: &mut UsbUshell) {
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

fn handle_tropic_chip_status(
    shell: &mut UsbUshell,
    tropci_01: &mut TropicInst,
) -> Result<(), Error> {
    let status = tropci_01.get_chip_status()?;
    write!(shell, "{0:}tropic chip status: {status:?}{0:}", USHELL_CR,).ok();
    Ok(())
}

fn handle_tropic_chip_id(shell: &mut UsbUshell, tropci_01: &mut TropicInst) -> Result<(), Error> {
    let chip_id = tropci_01.get_chip_id()?;
    write!(shell, "{0:}tropic chip_id: {chip_id}{0:}", USHELL_CR).ok();
    Ok(())
}

fn handle_tropic_cert_store<'a>(
    shell: &mut UsbUshell,
    tropci_01: &mut TropicInst,
    cert_buf: &'a mut [u8; tropic_rs::l2::CERT_BUFFER_LEN],
    cert_store_opt: &mut Option<TropicCertStore<'a>>,
) -> Result<(), Error> {
    *cert_store_opt = None;
    let cert_store = tropci_01.get_cert_store(cert_buf)?;
    *cert_store_opt = Some(cert_store);
    write!(shell, "{0:}tropic certificate stored:{0:}", USHELL_CR).ok();
    Ok(())
}

fn handle_tropic_riscv_fw(shell: &mut UsbUshell, tropci_01: &mut TropicInst) -> Result<(), Error> {
    let version = tropci_01.get_riscv_firmware_version()?;
    write!(
        shell,
        "{0:}tropic riscv firmware version: {version:?}{0:}",
        USHELL_CR
    )
    .ok();
    Ok(())
}

fn handle_tropic_spect_fw(shell: &mut UsbUshell, tropci_01: &mut TropicInst) -> Result<(), Error> {
    let version = tropci_01.get_spect_firmware_version()?;
    write!(
        shell,
        "{0:}tropic spect firmware version: {version:?}{0:}",
        USHELL_CR
    )
    .ok();
    Ok(())
}

fn handle_tropic_riscv_fw_log(
    shell: &mut UsbUshell,
    tropci_01: &mut TropicInst,
) -> Result<(), Error> {
    let log = tropci_01.get_riscv_firmware_log()?;

    // write log into a fixed 255 byte string buffer
    // l2 packet payload 252 bytes nax
    let mut unformatted = heapless::String::<255>::new();
    write!(unformatted, "{log}").ok();

    let formatted_log = format_text_block::<280>(&unformatted);
    write!(shell, "{0:}tropic log:{0:}{formatted_log}{0:}", USHELL_CR).ok();
    Ok(())
}

fn handle_tropic_restart(
    shell: &mut UsbUshell,
    tropci_01: &mut TropicInst,
    args: heapless::String<CMD_LEN>,
) -> Result<(), Error> {
    let mode = match args.as_str() {
        "0" => tropic_rs::l2::restart::RestartMode::Reboot,
        "1" => tropic_rs::l2::restart::RestartMode::Maintanance,
        "" => return Err(Error::ArgMissing),
        _ => return Err(Error::WrongArg),
    };

    let status = tropci_01.restart(mode)?;
    write!(
        shell,
        "{0:}tropic restart requested: resp status: {status:?}{0:}",
        USHELL_CR
    )
    .ok();
    Ok(())
}

fn handle_tropic_session_create(
    shell: &mut UsbUshell,
    tropci_01: &mut TropicInst,
    rng: &mut ChaCha20Rng,
    cert_store_opt: &mut Option<TropicCertStore>,
    session_opt: &mut Option<tropic_rs::l3::EncSession>,
    args: heapless::String<CMD_LEN>,
) -> Result<(), Error> {
    let key = match args.as_str() {
        "0" => tropic_rs::l3::keys::SamplePairingKey::Sample0,
        "1" => tropic_rs::l3::keys::SamplePairingKey::AttestSlot,
        "2" => tropic_rs::l3::keys::SamplePairingKey::ReadSerial,
        "3" => tropic_rs::l3::keys::SamplePairingKey::App,
        "" => return Err(Error::ArgMissing),
        _ => return Err(Error::WrongArg),
    };

    let cert_store = match cert_store_opt {
        Some(cert_store) => cert_store,
        None => return Err(Error::NoCertStore),
    };

    let st_pubkey = cert_store.get_pubkey(tropic_rs::cert_store::CertKind::Device)?;
    let session = tropci_01.create_session(
        rng,
        &key.to_x25519_secret(),
        tropic_rs::common::PairingKeySlot::Index0,
        &st_pubkey,
    )?;
    *session_opt = Some(session);
    write!(shell, "{0:}tropic session created {0:}", USHELL_CR).ok();
    Ok(())
}

fn handle_tropic_ping(
    shell: &mut UsbUshell,
    tropci_01: &mut TropicInst,
    session_opt: &mut Option<tropic_rs::l3::EncSession>,
    args: heapless::String<CMD_LEN>,
) -> Result<(), Error> {
    let session = match session_opt {
        Some(session) => session,
        None => return Err(Error::NoSession),
    };

    if args.is_empty() {
        return Err(Error::ArgMissing);
    }
    let msg = args.as_bytes();

    let resp = tropci_01.ping(session, msg)?;
    let resp_string = core::str::from_utf8(resp.msg())?;
    write!(shell, "{0:}pong: {resp_string}{0:}", USHELL_CR)?;
    Ok(())
}

fn handle_tropic_pairing_key_read(
    shell: &mut UsbUshell,
    tropci_01: &mut TropicInst,
    session_opt: &mut Option<tropic_rs::l3::EncSession>,
    args: heapless::String<CMD_LEN>,
) -> Result<(), Error> {
    let session = match session_opt {
        Some(session) => session,
        None => return Err(Error::NoSession),
    };

    let slot = match args.as_str() {
        "0" => tropic_rs::common::PairingKeySlot::Index0,
        "1" => tropic_rs::common::PairingKeySlot::Index1,
        "2" => tropic_rs::common::PairingKeySlot::Index2,
        "3" => tropic_rs::common::PairingKeySlot::Index3,
        "" => return Err(Error::ArgMissing),
        _ => return Err(Error::WrongArg),
    };

    let resp = tropci_01.pairing_key_read(session, slot)?;
    write!(shell, "{0:}payring_key: {resp}{0:}", USHELL_CR)?;
    Ok(())
}

fn handle_tropic_config_read(
    shell: &mut UsbUshell,
    tropci_01: &mut TropicInst,
    session_opt: &mut Option<tropic_rs::l3::EncSession>,
    args: heapless::String<CMD_LEN>,
) -> Result<(), Error> {
    let session = match session_opt {
        Some(session) => session,
        None => return Err(Error::NoSession),
    };

    match args.as_str() {
        "start-up" => {
            let resp = tropci_01.config_read(session, StartUp)?;
            write!(shell, "{0:}config_read: {resp}{0:}", USHELL_CR)?;
        }
        "sensors" => {
            let resp = tropci_01.config_read(session, Sensor)?;
            write!(shell, "{0:}config_read: {resp}{0:}", USHELL_CR)?;
        }
        "debug" => {
            let resp = tropci_01.config_read(session, Debug)?;
            write!(shell, "{0:}config_read: {resp}{0:}", USHELL_CR)?;
        }
        "" => return Err(Error::ArgMissing),
        _ => return Err(Error::WrongArg),
    };
    Ok(())
}

fn handle_help(shell: &mut UsbUshell) {
    shell.write_str(USHELL_HELP).ok();
}

fn handle_clear(shell: &mut UsbUshell) {
    shell.clear().ok();
}

fn handle_empty(shell: &mut UsbUshell) {
    shell.write_str(USHELL_CR).ok();
}

fn handle_unsupported(shell: &mut UsbUshell) {
    write!(shell, "{0:}unsupported command{0:}", USHELL_CR).ok();
}
