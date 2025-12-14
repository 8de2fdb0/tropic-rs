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
    
    /// Ping the device
    /// 
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    ///     message (bytes): Message to send
    /// 
    /// Returns:
    ///     bytes: Response message
    fn ping(&self, session: &PyEncSession, message: &[u8]) -> PyResult<Vec<u8>> {
        let mut tropic = self.tropic.lock().unwrap();
        let mut sess = session.session.lock().unwrap();
        
        let resp = tropic.ping(&mut *sess, message).map_err(TropicError::from)?;
        Ok(resp.msg().to_vec())
    }
    
    /// Read pairing key public key
    /// 
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    ///     slot (int): Pairing key slot (0-3)
    /// 
    /// Returns:
    ///     str: Public key as hex string
    fn pairing_key_read(&self, session: &PyEncSession, slot: u8) -> PyResult<String> {
        let mut tropic = self.tropic.lock().unwrap();
        let mut sess = session.session.lock().unwrap();
        
        let pairing_slot = PairingKeySlot::try_from(slot)
            .map_err(|e| PyException::new_err(format!("{:?}", e)))?;
        
        let resp = tropic.pairing_key_read(&mut *sess, pairing_slot).map_err(TropicError::from)?;
        Ok(hex::encode(&resp.s_hipub))
    }
    
    /// Write pairing key public key
    /// 
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    ///     slot (int): Pairing key slot (0-3)
    ///     pubkey_hex (str): Public key as hex string (32 bytes)
    fn pairing_key_write(&self, session: &PyEncSession, slot: u8, pubkey_hex: &str) -> PyResult<()> {
        use tropic_rs::external::x25519_dalek::PublicKey;
        
        let mut tropic = self.tropic.lock().unwrap();
        let mut sess = session.session.lock().unwrap();
        
        let pairing_slot = PairingKeySlot::try_from(slot)
            .map_err(|e| PyException::new_err(format!("{:?}", e)))?;
        
        let pubkey_bytes = hex::decode(pubkey_hex)
            .map_err(|e| PyException::new_err(format!("Invalid pubkey hex: {}", e)))?;
        
        if pubkey_bytes.len() != 32 {
            return Err(PyException::new_err("pubkey must be 32 bytes"));
        }
        
        let pubkey = PublicKey::from(<[u8; 32]>::try_from(&pubkey_bytes[..]).unwrap());
        
        tropic.pairing_key_write(&mut *sess, pairing_slot, &pubkey).map_err(TropicError::from)?;
        Ok(())
    }
    
    /// Read reversible config
    /// 
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    /// 
    /// Returns:
    ///     str: Config as JSON string
    fn r_config_read(&self, session: &PyEncSession) -> PyResult<String> {
        let mut tropic = self.tropic.lock().unwrap();
        let mut sess = session.session.lock().unwrap();
        
        let config = tropic.r_config_read(&mut *sess).map_err(TropicError::from)?;
        let json = serde_json::to_string_pretty(&config).map_err(json_error_to_pyerr)?;
        Ok(json)
    }
    
    /// Write reversible config
    /// 
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    ///     config_json (str): Config as JSON string
    fn r_config_write(&self, session: &PyEncSession, config_json: &str) -> PyResult<()> {
        let mut tropic = self.tropic.lock().unwrap();
        let mut sess = session.session.lock().unwrap();
        
        let config: tropic_rs::common::config::Config = serde_json::from_str(config_json)
            .map_err(json_error_to_pyerr)?;
        
        tropic.r_config_write(&mut *sess, &config).map_err(TropicError::from)?;
        Ok(())
    }
}

/// Python wrapper for encrypted session
#[pyclass]
struct PyEncSession {
    session: Mutex<tropic_rs::l3::session::EncSession>,
}

#[pymethods]
impl PyEncSession {
    /// Create a new encrypted session
    /// 
    /// Args:
    ///     tropic (PyTropic01): The Tropic01 instance
    ///     pairing_key_slot (int): Pairing key slot (0-3)
    ///     sh_secret_hex (str): Static host secret as hex string
    ///     st_pubkey_hex (str): Static TROPIC01 public key as hex string
    /// 
    /// Returns:
    ///     PyEncSession: New encrypted session
    #[staticmethod]
    fn create(tropic: &PyTropic01, pairing_key_slot: u8, sh_secret_hex: &str, st_pubkey_hex: &str) -> PyResult<Self> {
        use tropic_rs::external::x25519_dalek::{StaticSecret, PublicKey};
        
        let slot = PairingKeySlot::try_from(pairing_key_slot)
            .map_err(|e| PyException::new_err(format!("{:?}", e)))?;
        
        // Decode hex strings
        let sh_secret_bytes = hex::decode(sh_secret_hex)
            .map_err(|e| PyException::new_err(format!("Invalid sh_secret hex: {}", e)))?;
        let st_pubkey_bytes = hex::decode(st_pubkey_hex)
            .map_err(|e| PyException::new_err(format!("Invalid st_pubkey hex: {}", e)))?;
        
        if sh_secret_bytes.len() != 32 {
            return Err(PyException::new_err("sh_secret must be 32 bytes"));
        }
        if st_pubkey_bytes.len() != 32 {
            return Err(PyException::new_err("st_pubkey must be 32 bytes"));
        }
        
        let sh_secret = StaticSecret::from(<[u8; 32]>::try_from(&sh_secret_bytes[..]).unwrap());
        let st_pubkey = PublicKey::from(<[u8; 32]>::try_from(&st_pubkey_bytes[..]).unwrap());
        
        let mut tropic_lock = tropic.tropic.lock().unwrap();
        let session = tropic_lock
            .create_session(rand::rng(), &sh_secret, slot, &st_pubkey)
            .map_err(TropicError::from)?;
        
        Ok(Self {
            session: Mutex::new(session),
        })
    }
    
    /// Serialize session to JSON
    fn to_json(&self) -> PyResult<String> {
        let session = self.session.lock().unwrap();
        let json = serde_json::to_string_pretty(&*session).map_err(json_error_to_pyerr)?;
        Ok(json)
    }
    
    /// Deserialize session from JSON
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        let session: tropic_rs::l3::session::EncSession = serde_json::from_str(json)
            .map_err(json_error_to_pyerr)?;
        Ok(Self {
            session: Mutex::new(session),
        })
    }
}

/// Python module for tropic-rs
#[pymodule]
fn _tropic_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyTropic01>()?;
    m.add_class::<PyEncSession>()?;
    Ok(())
}
