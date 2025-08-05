#![no_std]
#![no_main]

use core::fmt::Write;
use core::mem::MaybeUninit;

use embedded_cli::cli::CliHandle;
use embedded_hal::digital::OutputPin;
use embedded_io::Write as _;
use heapless::String;
use panic_halt as _;
use panic_halt as _;
use rtic_monotonics::rp235x::prelude::*;
use rtic_sync::arbiter::{spi::ArbiterDevice, Arbiter};
use usb_device::bus::UsbBusAllocator;
use usb_device::{
    device::{UsbDeviceBuilder, UsbVidPid},
    LangID,
};

use embedded_hal::spi::{self, SpiBus};
use hal::fugit::RateExtU32;
use rp235x_hal::Clock as _;
use tropic_rs::Tropic01;

use common::{
    usb::consts::{PRODUCT_ID, VENDOR_ID},
    Commands, SysCmd,
};

use firmware::{
    get_chip_info,
    hal::{self, clocks::init_clocks_and_plls, watchdog::Watchdog, Sio},
};

// Tell the Boot ROM about our application
// This is critical for the RP235x to boot your application correctly.
#[link_section = ".start_block"]
#[used]
pub static IMAGE_DEF: hal::block::ImageDef = hal::block::ImageDef::secure_exe();

rp235x_timer_monotonic!(Mono);

type TropicSpiBus = hal::spi::Spi<
    rp235x_hal::spi::Enabled,
    rp235x_hal::pac::SPI0,
    (
        rp235x_hal::gpio::Pin<
            rp235x_hal::gpio::bank0::Gpio19,
            rp235x_hal::gpio::FunctionSpi,
            rp235x_hal::gpio::PullNone,
        >,
        rp235x_hal::gpio::Pin<
            rp235x_hal::gpio::bank0::Gpio16,
            rp235x_hal::gpio::FunctionSpi,
            rp235x_hal::gpio::PullNone,
        >,
        rp235x_hal::gpio::Pin<
            rp235x_hal::gpio::bank0::Gpio18,
            rp235x_hal::gpio::FunctionSpi,
            rp235x_hal::gpio::PullNone,
        >,
    ),
>;
type TropicSpiCS = rp235x_hal::gpio::Pin<
    rp235x_hal::gpio::bank0::Gpio17,
    rp235x_hal::gpio::FunctionSio<rp235x_hal::gpio::SioOutput>,
    rp235x_hal::gpio::PullDown,
>;

type TropicArbiterSpiBus = Arbiter<TropicSpiBus>;
type TropicArbiterSpiDevice =
    Arbiter<embedded_hal_bus::spi::ExclusiveDevice<TropicArbiterSpiBus, TropicSpiCS, Mono>>;

type TropicArbiterDevice = ArbiterDevice<'static, TropicSpiBus, TropicSpiCS, Mono>;

#[rtic::app(device = hal::pac, peripherals = true, dispatchers = [UART0_IRQ])]
mod app {

    use super::*;

    // use fugit::ExtU64;

    const XOSC_CRYSTAL_FREQ: u32 = 12_000_000;

    #[shared]
    struct Shared {
        led: hal::gpio::Pin<
            hal::gpio::bank0::Gpio25,
            hal::gpio::FunctionSioOutput,
            hal::gpio::PullDown,
        >,

        ping_cnt: u32,

        usb_dev: usb_device::device::UsbDevice<'static, rp235x_hal::usb::UsbBus>,
        // serial: usbd_serial::SerialPort<'static, rp235x_hal::usb::UsbBus>,
        serial_reader: usbd_serial::SerialReader<'static, rp235x_hal::usb::UsbBus>,
        serial_writer: usbd_serial::SerialWriter<'static, rp235x_hal::usb::UsbBus>,
        // embedded_cli: embedded_cli::cli::Cli<
        //     usbd_serial::SerialWriter<'static, rp235x_hal::usb::UsbBus>,
        //     <usbd_serial::SerialWriter<'static, rp235x_hal::usb::UsbBus> as usbd_serial::embedded_io::ErrorType>::Error,
        //     [u8; 40],
        //     [u8; 100],
        // >,
        // tropic: Tropic01<
        //     embedded_hal_bus::spi::ExclusiveDevice<
        //         hal::spi::Spi<_, _, _, 8>,
        //         hal::gpio::Pin<
        //             hal::gpio::bank0::Gpio17,
        //             hal::gpio::FunctionSpi,
        //             hal::gpio::PullNone,
        //         >,
        //         Mono,
        //     >,
        // >,
        // tropic: Tropic01<
        //     embedded_hal_bus::spi::ExclusiveDevice<
        //         rp235x_hal::Spi<
        //             rp235x_hal::spi::Enabled,
        //             you_must_enable_the_rt_feature_for_the_pac_in_your_cargo_toml::SPI0,
        //             (
        //                 rp235x_hal::gpio::Pin<
        //                     rp235x_hal::gpio::bank0::Gpio19,
        //                     rp235x_hal::gpio::FunctionSpi,
        //                     rp235x_hal::gpio::PullNone,
        //                 >,
        //                 rp235x_hal::gpio::Pin<
        //                     rp235x_hal::gpio::bank0::Gpio16,
        //                     rp235x_hal::gpio::FunctionSpi,
        //                     rp235x_hal::gpio::PullNone,
        //                 >,
        //                 rp235x_hal::gpio::Pin<
        //                     rp235x_hal::gpio::bank0::Gpio18,
        //                     rp235x_hal::gpio::FunctionSpi,
        //                     rp235x_hal::gpio::PullNone,
        //                 >,
        //             ),
        //         >,
        //         rp235x_hal::gpio::Pin<
        //             rp235x_hal::gpio::bank0::Gpio17,
        //             rp235x_hal::gpio::FunctionSio<rp235x_hal::gpio::SioOutput>,
        //             rp235x_hal::gpio::PullDown,
        //         >,
        //         Mono,
        //     >,
        // >,
    }

    #[local]
    struct Local {
        tropic: Tropic01<TropicArbiterDevice>,
    }

    #[init(local = [
        usb_bus: Option<usb_device::bus::UsbBusAllocator<rp235x_hal::usb::UsbBus>> = None,
        CLI_COMMAND_BUFFER: [u8; 40] = [0; 40],
        CLI_HISTORY_BUFFER: [u8; 41] = [0; 41],

        spi_bus_arbiter: MaybeUninit<TropicArbiterSpiBus> = MaybeUninit::uninit(),
        spi_device_arbiter: MaybeUninit<TropicArbiterSpiDevice> = MaybeUninit::uninit(),
        ])]
    fn init(cx: init::Context) -> (Shared, Local) {
        // Soft-reset does not release the hardware spinlocks
        // Release them now to avoid a deadlock after debug or watchdog reset
        unsafe {
            hal::sio::spinlock_reset();
        }
        let mut resets = cx.device.RESETS;
        let mut watchdog = Watchdog::new(cx.device.WATCHDOG);
        let clocks = init_clocks_and_plls(
            XOSC_CRYSTAL_FREQ,
            cx.device.XOSC,
            cx.device.CLOCKS,
            cx.device.PLL_SYS,
            cx.device.PLL_USB,
            &mut resets,
            &mut watchdog,
        )
        .ok()
        .unwrap();

        Mono::start(cx.device.TIMER0, &mut resets);

        let sio = Sio::new(cx.device.SIO);
        let pins = firmware::Pins::new(
            cx.device.IO_BANK0,
            cx.device.PADS_BANK0,
            sio.gpio_bank0,
            &mut resets,
        );

        let mut led = pins.led.into_push_pull_output();
        led.set_low().unwrap();

        // Initialize USB bus
        let usb_bus: &'static _ =
            cx.local
                .usb_bus
                .insert(UsbBusAllocator::new(rp235x_hal::usb::UsbBus::new(
                    cx.device.USB,
                    cx.device.USB_DPRAM,
                    clocks.usb_clock,
                    true,
                    &mut resets,
                )));

        let read_buffer = usbd_serial::DefaultBufferStore::default();
        let write_buffer = usbd_serial::DefaultBufferStore::default();

        let serial = usbd_serial::SerialPort::new_with_store(usb_bus, read_buffer, write_buffer);

        let (serial_reader, serial_writer) = serial.split();

        let usb_descriptors = [usb_device::device::StringDescriptors::new(LangID::EN_US)
            .manufacturer("Tropic")
            .product("RP2350 Raw USB API")
            .serial_number("001")];

        // Configure USB device
        let usb_dev = UsbDeviceBuilder::new(usb_bus, UsbVidPid(0x16c0, 0x27dd))
            // .device_class(0xFF) // Vendor-specific class
            .device_class(2) // see: https://www.usb.org/defined-class-codes
            .strings(&usb_descriptors)
            .unwrap()
            .build();

        // let usb_dev = UsbDeviceBuilder::new(usb_bus, UsbVidPid(VENDOR_ID, PRODUCT_ID))
        //     // .device_class(0xFF) // Vendor-specific class
        //     .device_class(2) // see: https://www.usb.org/defined-class-codes
        //     .strings(&usb_descriptors)
        //     .unwrap()
        //     .build();

        let command_buffer: &'static _ = cx.local.CLI_COMMAND_BUFFER;
        let history_buffer: &'static _ = cx.local.CLI_HISTORY_BUFFER;

        // let embedded_cli = embedded_cli::cli::CliBuilder::default()
        //     .writer(serial_writer)
        //     // .command_buffer(*command_buffer)
        //     // .history_buffer(*history_buffer)
        //     .build()
        //     .unwrap();

        // let miso = cx.device.
        // let mosi = p.PIN_19;
        // let clk = p.PIN_18;
        // let cs = p.PIN_17;

        let spi_mosi: hal::gpio::Pin<_, hal::gpio::FunctionSpi, hal::gpio::PullNone> =
            pins.mosi.reconfigure();
        let spi_miso: hal::gpio::Pin<_, hal::gpio::FunctionSpi, hal::gpio::PullNone> =
            pins.miso.reconfigure();
        let spi_sclk: hal::gpio::Pin<_, hal::gpio::FunctionSpi, hal::gpio::PullNone> =
            pins.sclk.reconfigure();
        let spi_cs: rp235x_hal::gpio::Pin<
            rp235x_hal::gpio::bank0::Gpio17,
            rp235x_hal::gpio::FunctionSio<rp235x_hal::gpio::SioOutput>,
            rp235x_hal::gpio::PullDown,
        > = pins.cs.into_push_pull_output();

        let spi_bus =
            hal::spi::Spi::<_, _, _, 8>::new(cx.device.SPI0, (spi_mosi, spi_miso, spi_sclk));

        let spi_bus = spi_bus.init(
            &mut resets,
            clocks.peripheral_clock.freq(),
            16.MHz(),
            &embedded_hal::spi::MODE_0,
        );

        let spi_bus_arbiter = cx.local.spi_bus_arbiter.write(Arbiter::new(spi_bus));
        let a = cx.local.spi_bus_arbiter.as_ptr();

        let spi_device = embedded_hal_bus::spi::ExclusiveDevice::new(a, spi_cs, Mono).unwrap();

        let spi_device_arbiter = cx.local.spi_device_arbiter.write(Arbiter::new(spi_device));

        let tropic = Tropic01::new(spi_device_arbiter);

        let ping_cnt = 0;

        blink_led::spawn().ok();
        (
            Shared {
                led,
                ping_cnt,
                usb_dev,
                // serial,
                serial_reader,
                serial_writer,
                // embedded_cli,
                // tropic,
            },
            Local { tropic },
        )
    }

    #[task(
        shared = [led],
        local = [tog: bool = true],
    )]
    async fn blink_led(mut cx: blink_led::Context) {
        loop {
            if *cx.local.tog {
                cx.shared.led.lock(|l| l.set_high().unwrap());
            } else {
                cx.shared.led.lock(|l| l.set_low().unwrap());
            }
            *cx.local.tog = !*cx.local.tog;

            Mono::delay(500.millis()).await;
        }
    }

    #[task(binds = USBCTRL_IRQ, local = [tropic], shared = [ping_cnt, usb_dev, serial_reader, serial_writer])]
    fn usb_interrupt(cx: usb_interrupt::Context) {
        let ping_cnt = cx.shared.ping_cnt;
        let usb_dev = cx.shared.usb_dev;
        // let serial = cx.shared.serial;
        let serial_reader = cx.shared.serial_reader;
        let serial_writer = cx.shared.serial_writer;
        // let mut embedded_cli = cx.shared.embedded_cli;
        // let mut tropic = cx.shared.tropic;

        // Handle USB interrupts

        (ping_cnt, usb_dev, serial_reader, serial_writer).lock(
            |ping_cnt_a, usb_dev_a, serial_reader_a, serial_writer_a| {
                if usb_dev_a.poll(&mut [serial_reader_a]) {
                    let mut buf = [0u8; 64];

                    // let a = embedded_cli_a.write(|w| uwriteln!(w, "input"));
                    // let a = embedded_cli_a.write(|w| w.writeln_str("data received"));

                    // match serial_reader_a.read(&mut buf) {
                    //     Ok(0) => {
                    //         // let _ =
                    //         // embedded_cli_a.write(|writer| ufmt::uwriteln!(writer, "no data"));
                    //     }
                    //     Ok(count) => {
                    //         for byte in buf.into_iter().take(count) {
                    //             let _ = embedded_cli_a
                    //                 .process_byte::<common::Commands, _>(
                    //                     byte,
                    //                     &mut common::Commands::processor(|cli, command| {
                    //                         match command {
                    //                             Commands::System(sys_cmd) => match sys_cmd {
                    //                                 SysCmd::Ping => {
                    //                                     *ping_cnt_a += 1;
                    //                                     let pong: u32 = *ping_cnt_a;
                    //                                     ufmt::uwriteln!(cli.writer(), "pong",)
                    //                                         .unwrap();
                    //                                 }
                    //                             },
                    //                             Commands::Chip(chip) => {}
                    //                         }
                    //                         Ok(())
                    //                     }),
                    //                 )
                    //                 .unwrap();
                    //         }
                    //     }
                    //     Err(_) => {}
                    // }

                    let mut resp_buf = String::<128>::new();

                    match serial_reader_a.read(&mut buf) {
                        Ok(0) => {
                            // let _ = serial_writer_a.write(b"no data\r\n");
                        }
                        Ok(_count) => {
                            let _ = match &buf[0] {
                                b'p' => {
                                    *ping_cnt_a += 1;
                                    let pong: u32 = *ping_cnt_a;
                                    let _ = write!(serial_writer_a, "pong {} \r\n", pong);
                                }
                                b'i' => {
                                    if let Some(chip_info) = get_chip_info() {
                                        let _ = write!(
                                            resp_buf,
                                            "device_id: {:?}\r\nwafer_id: {:?}\r\n",
                                            chip_info.device_id, chip_info.wafer_id,
                                        );
                                    } else {
                                        let _ = write!(serial_writer_a, "no chip info\r\n");
                                    }
                                }
                                // b't' => {
                                //     (tropic).lock(|tropic_a| match tropic_a.get_chip_status() {
                                //         Ok(s) => {
                                //             let _ = write!(resp_buf, "tropic status: {:?}", s);
                                //         }
                                //         Err(e) => {
                                //             let _ = write!(resp_buf, "error: {e:?}");
                                //         }
                                //     })
                                // }
                                _ => {
                                    let _ = serial_writer_a.write(b"unknown command\r\n");
                                }
                            };
                        }
                        Err(e) => {
                            write!(resp_buf, "error: {e:?}").unwrap();
                        }
                    }

                    let bytes = resp_buf.as_bytes();
                    let mut bytes_sent = 0;
                    while bytes_sent < bytes.len() {
                        if let Ok(count) = serial_writer_a.write(&bytes[bytes_sent..]) {
                            bytes_sent += count;
                        }
                    }
                    if let Err(e) = serial_writer_a.flush() {
                        let mut formatted_error: String<64> = String::new();
                        if write!(formatted_error, "error: {e:?}").is_ok() {
                            let _ = serial_writer_a.write(formatted_error.as_bytes());
                        }
                    }
                }
            },
        );
    }
}
