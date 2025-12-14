use pyo3::prelude::*;
use pyo3::exceptions::PyException;
use pyo3::types::PyDict;
use std::sync::Mutex;

use tropic_rs::{
    Tropic01,
    l2::info::{BankId, FirmwareType},
    l2::sleep::SleepKind,
    l2::startup::RestartMode,
    common::PairingKeySlot,
    cert_store::CERT_BUFFER_LEN,
};
use tropic_cert_store::nom_decoder::NomDecoder;

mod transport;
use transport::UsbDongleTransport;

// Error wrapper for Python
#[derive(Debug)]
struct TropicError(String);

impl From<tropic_rs::tropic::Error> for TropicError {
    fn from(err: tropic_rs::tropic::Error) -> Self {
        TropicError(format!("{:?}", err))
    }
}

impl From<TropicError> for PyErr {
    fn from(err: TropicError) -> PyErr {
        PyException::new_err(err.0)
    }
}

impl From<transport::Error> for PyErr {
    fn from(err: transport::Error) -> PyErr {
        PyException::new_err(format!("{:?}", err))
    }
}

fn json_error_to_pyerr(err: serde_json::Error) -> PyErr {
    PyException::new_err(format!("JSON error: {}", err))
}

/// Python wrapper for Tropic01 with USB dongle transport
#[pyclass]
struct PyTropic01 {
    tropic: Mutex<Tropic01<UsbDongleTransport, NomDecoder>>,
}

#[pymethods]
impl PyTropic01 {
    /// Create a new Tropic01 instance connected via USB dongle
    /// 
    /// Args:
    ///     port (str): Serial port path (e.g., "/dev/ttyACM0")
    ///     baud_rate (int): Baud rate (default: 115200)
    #[new]
    #[pyo3(signature = (port, baud_rate=115200))]
    fn new(port: &str, baud_rate: u32) -> PyResult<Self> {
        let transport = UsbDongleTransport::new(port, baud_rate)?;
        let tropic = Tropic01::<_, NomDecoder>::new(transport);
        Ok(Self {
            tropic: Mutex::new(tropic),
        })
    }

    /// Get the chip status
    /// 
    /// Returns:
    ///     dict: Chip status with 'ready', 'alarm', and 'chip_mode' fields
    fn get_chip_status(&self) -> PyResult<PyObject> {
        let mut tropic = self.tropic.lock().unwrap();
        let status = tropic.get_chip_status().map_err(TropicError::from)?;
        
        Python::with_gil(|py| {
            let dict = PyDict::new_bound(py);
            dict.set_item("ready", status.ready)?;
            dict.set_item("alarm", status.alarm)?;
            dict.set_item("chip_mode", format!("{:?}", status.chip_mode()))?;
            Ok(dict.into())
        })
    }

    /// Get the chip ID
    /// 
    /// Returns:
    ///     str: JSON string with chip ID information
    fn get_chip_id(&self) -> PyResult<String> {
        let mut tropic = self.tropic.lock().unwrap();
        let chip_id = tropic.get_chip_id().map_err(TropicError::from)?;
        let json = serde_json::to_string_pretty(&chip_id).map_err(json_error_to_pyerr)?;
        Ok(json)
    }

    /// Get firmware version
    /// 
    /// Args:
    ///     fw_type (str): Firmware type ("Riscv", "Spect")
    /// 
    /// Returns:
    ///     str: Firmware version as hex string
    fn get_firmware_version(&self, fw_type: &str) -> PyResult<String> {
        let mut tropic = self.tropic.lock().unwrap();
        let fw_type = match fw_type {
            "Riscv" | "RiscV" => FirmwareType::Riscv,
            "Spect" => FirmwareType::Spect,
            _ => return Err(PyException::new_err("Invalid firmware type")),
        };
        
        let version = tropic.get_firmware_version(fw_type).map_err(TropicError::from)?;
        // Convert version data to hex string
        Ok(hex::encode(&version.version))
    }

    /// Get firmware boot header for a specific bank
    /// 
    /// Args:
    ///     bank_id (int): Bank ID (1, 2, 17, or 18)
    /// 
    /// Returns:
    ///     str: JSON string with boot header information
    fn get_firmware_boot_header(&self, bank_id: u8) -> PyResult<String> {
        let mut tropic = self.tropic.lock().unwrap();
        let bank = match bank_id {
            1 => BankId::FwBankFw1,
            2 => BankId::FwBankFw2,
            17 => BankId::FwBankSpect1,
            18 => BankId::FwBankSpect2,
            _ => return Err(PyException::new_err("Invalid bank ID")),
        };
        
        let header = tropic.get_firmware_boot_header(bank).map_err(TropicError::from)?;
        let json = serde_json::to_string_pretty(&header).map_err(json_error_to_pyerr)?;
        Ok(json)
    }

    /// Get RISC-V firmware log
    /// 
    /// Returns:
    ///     str: Firmware log as string
    fn get_riscv_firmware_log(&self) -> PyResult<String> {
        let mut tropic = self.tropic.lock().unwrap();
        let log = tropic.get_riscv_firmware_log().map_err(TropicError::from)?;
        Ok(format!("{}", log))
    }

    /// Get certificate store
    /// 
    /// Returns:
    ///     str: JSON string with certificate store
    fn get_cert_store(&self) -> PyResult<String> {
        let mut tropic = self.tropic.lock().unwrap();
        let mut cert_buf = [0u8; CERT_BUFFER_LEN];
        let cert_store = tropic.get_cert_store(&mut cert_buf).map_err(TropicError::from)?;
        let json = serde_json::to_string_pretty(&cert_store).map_err(json_error_to_pyerr)?;
        Ok(json)
    }

    /// Put device to sleep
    /// 
    /// Args:
    ///     kind (str): Sleep kind - "Regular" or "Deep"
    fn sleep(&self, kind: &str) -> PyResult<()> {
        let mut tropic = self.tropic.lock().unwrap();
        let sleep_kind = match kind {
            "Regular" => SleepKind::Regular,
            "Deep" => SleepKind::Deep,
            _ => return Err(PyException::new_err("Invalid sleep kind")),
        };
        
        tropic.sleep(sleep_kind).map_err(TropicError::from)?;
        Ok(())
    }

    /// Restart the device
    /// 
    /// Args:
    ///     mode (str): Restart mode - "Reboot" or "Maintanance"
    fn restart(&self, mode: &str) -> PyResult<()> {
        let mut tropic = self.tropic.lock().unwrap();
        let restart_mode = match mode {
            "Reboot" => RestartMode::Reboot,
            "Maintanance" => RestartMode::Maintanance,
            _ => return Err(PyException::new_err("Invalid restart mode")),
        };
        
        tropic.restart(restart_mode).map_err(TropicError::from)?;
        Ok(())
    }

    /// Get handshake response
    /// 
    /// Args:
    ///     pairing_key_slot (int): Pairing key slot (0-3)
    /// 
    /// Returns:
    ///     str: JSON string with handshake data
    fn get_handshake(&self, pairing_key_slot: u8) -> PyResult<String> {
        let mut tropic = self.tropic.lock().unwrap();
        let slot = PairingKeySlot::try_from(pairing_key_slot)
            .map_err(|e| PyException::new_err(format!("{:?}", e)))?;
        
        let (handshake_resp, static_secret) = tropic
            .get_handshake(rand::rng(), slot)
            .map_err(TropicError::from)?;
        
        // Create a wrapper type for serialization
        #[derive(serde::Serialize)]
        struct HandshakeData {
            et_pubkey: String,
            auth_tag: String,
            static_secret: String,
        }
        
        let data = HandshakeData {
            et_pubkey: hex::encode(handshake_resp.et_pubkey.as_bytes()),
            auth_tag: hex::encode(handshake_resp.auth_tag),
            static_secret: hex::encode(static_secret.to_bytes()),
        };
        
        let json = serde_json::to_string_pretty(&data).map_err(json_error_to_pyerr)?;
        Ok(json)
    }

    /// Abort the current session
    fn abort_session(&self) -> PyResult<()> {
        let mut tropic = self.tropic.lock().unwrap();
        tropic.abort_session().map_err(TropicError::from)?;
        Ok(())
    }
}

/// Python module for tropic-rs
#[pymodule]
fn _tropic_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyTropic01>()?;
    Ok(())
}
