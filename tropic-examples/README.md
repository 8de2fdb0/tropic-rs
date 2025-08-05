# Example code for use with `tropic-rs` crate.

## Structure

- common
    - holds common code, in the moment raw usb bus implementation for rp235x (WIP)

- firmware
    - holds a serial ushell that can be used to interacet with the secure element
    - rtic code for a raw usb API (WIP)

- host
    - host cali for the raw usb API (WIP)


## Dependencies

To use the USB devices copy the udev rules under `./udev` `/etc/udev/rules.d/`.

- `69-probe-rs.rules` probe-rs rules for [Raspberry Pi Debug Probe](https://www.raspberrypi.com/documentation/microcontrollers/debug-probe.html) debugger/programmer.
- `99-picotool.rules` rules for [picotool](https://github.com/raspberrypi/picotool) programmer.
- `99-tropic-example.rules` rules for the usb devices created by the example firmeware code.


## Dev Environment

Have a look at the folder `.devcontainer` in the root directory, it shows how to setup a dev environment.
Build the firmware:

```shell
cd tropic-examples/firmware

cargo build --bin tropic_ushell
```

And then load the firmware:

With picotool:

```shell
picotool load -f -u -v -x -t elf tropic-examples/firmware/target/thumbv8m.main-none-eabihf/debug/tropic_ushell
```

Or with (probe-rs)[https://probe.rs]

```shell
probe-rs run --chip RP235x tropic-examples/firmware/target/thumbv8m.main-none-eabihf/debug/tropic_ushell
```

Or use the [VS Code extensin for probe-rs](https://marketplace.visualstudio.com/items?itemName=probe-rs.probe-rs-debugger), 
see `.vscode/launch.json` in the root directory.
