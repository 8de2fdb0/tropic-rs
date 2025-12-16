use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::sync::Mutex;

use tropic_cert_store::nom_decoder::NomDecoder;
use tropic_rs::{
    cert_store::CERT_BUFFER_LEN,
    common::{
        ecc::{EccCurve, EccKeySlot},
        MacAndDestroySlot, MCounterIndex, PairingKeySlot, UserDataSlot,
    },
    external::x25519_dalek::PublicKey,
    l2::{
        info::{BankId, FirmwareType},
        sleep::SleepKind,
        startup::RestartMode,
    },
    l3::CMD_SECRET_KEY_LEN,
    Tropic01,
};

mod transport;
use transport::UsbDongleTransport;

// Error wrapper for Python
#[derive(Debug)]
struct PyError(String);

impl From<tropic_rs::tropic::Error> for PyError {
    fn from(err: tropic_rs::tropic::Error) -> Self {
        PyError(format!("{:?}", err))
    }
}

impl From<PyError> for PyErr {
    fn from(err: PyError) -> PyErr {
        PyException::new_err(err.0)
    }
}

impl From<transport::Error> for PyErr {
    fn from(err: transport::Error) -> PyErr {
        PyException::new_err(format!("{:?}", err))
    }
}

impl From<serde_json::Error> for PyError {
    fn from(err: serde_json::Error) -> Self {
        PyError(format!("JSON error: {}", err))
    }
}

fn json_error_to_pyerr(err: serde_json::Error) -> PyErr {
    PyException::new_err(format!("JSON error: {}", err))
}

#[derive(serde::Serialize)]
struct PyHandshakeResp {
    et_pubkey: String,
    auth_tag: String,
    static_secret: String,
}

/// High-level Python interface to TROPIC01 secure element.
///
/// This class provides a Pythonic interface to all TROPIC01 functionality.   
///    
/// Example:
///     >>> tropic = Tropic01("/dev/ttyACM0")
///     >>> status = tropic.get_chip_status()
///     >>> print(status)
///     {'ready': True, 'alarm': False, 'chip_mode': 'Application'}
#[pyclass(name = "Tropic01")]
struct PyTropic01 {
    tropic: Option<Mutex<Tropic01<UsbDongleTransport, NomDecoder>>>,
    port: String,
    baud_rate: u32,
}

impl PyTropic01 {
    fn call_tropic<F, T>(&self, mut callback: F) -> PyResult<T>
    where
        F: FnMut(&mut Tropic01<UsbDongleTransport, NomDecoder>) -> Result<T, PyError>,
    {
        let mut tropic = self
            .tropic
            .as_ref()
            .ok_or(PyException::new_err("tropic not intialised"))?
            .lock()
            .unwrap();
        let result = callback(&mut tropic)?;
        Ok(result)
    }
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
            tropic: Some(Mutex::new(tropic)),
            port: port.to_string(),
            baud_rate,
        })
    }

    /// Context manager entry point. Returns self.
    fn __enter__(mut slf: PyRefMut<Self>) -> PyResult<PyRefMut<Self>> {
        let transport = UsbDongleTransport::new(&slf.port, slf.baud_rate)?;
        let tropic = Tropic01::<_, NomDecoder>::new(transport);
        slf.tropic = Some(Mutex::new(tropic));
        Ok(slf)
    }

    /// Context manager exit point. Automatically calls `close()` to release the serial port.
    fn __exit__(
        &mut self,
        _exc_type: Py<PyAny>,
        _exc_value: Py<PyAny>,
        _traceback: Py<PyAny>,
    ) -> PyResult<()> {
        self.tropic = None;
        Ok(())
    }

    /// Get the chip status
    ///
    /// Returns:
    ///     dict: Chip status with 'ready', 'alarm', and 'chip_mode' fields
    fn get_chip_status(&self) -> PyResult<Py<PyAny>> {
        let status = self.call_tropic(|tropic| {
            let status = tropic.get_chip_status().map_err(PyError::from)?;
            Ok(status)
        })?;

        Python::attach(|py| {
            let dict = PyDict::new(py);
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
        let json = self.call_tropic(|tropic| {
            let chip_id = tropic.get_chip_id().map_err(PyError::from)?;
            let json = serde_json::to_string_pretty(&chip_id)?;
            Ok(json)
        })?;

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
        let fw_type = match fw_type {
            "Riscv" | "RiscV" => FirmwareType::Riscv,
            "Spect" => FirmwareType::Spect,
            _ => return Err(PyException::new_err("Invalid firmware type")),
        };

        let version = self.call_tropic(|tropic| {
            let version = tropic
                .get_firmware_version(fw_type.clone())
                .map_err(PyError::from)?;
            Ok(version)
        })?;

        // Convert version data to hex string
        Ok(hex::encode(version.version))
    }

    /// Get firmware boot header for a specific bank
    ///
    /// Args:
    ///     bank_id (int): Bank ID (1, 2, 17, or 18)
    ///
    /// Returns:
    ///     str: JSON string with boot header information
    fn get_firmware_boot_header(&self, bank_id: u8) -> PyResult<String> {
        let json = self.call_tropic(|tropic| {
            let bank = match bank_id {
                1 => BankId::FwBankFw1,
                2 => BankId::FwBankFw2,
                17 => BankId::FwBankSpect1,
                18 => BankId::FwBankSpect2,
                _ => return Err(PyError("Invalid bank ID".to_string())),
            };

            let header = tropic
                .get_firmware_boot_header(bank)
                .map_err(PyError::from)?;

            let json = serde_json::to_string_pretty(&header)?;
            Ok(json)
        })?;

        Ok(json)
    }

    /// Get RISC-V firmware log
    ///
    /// Returns:
    ///     str: Firmware log as string
    fn get_riscv_firmware_log(&self) -> PyResult<String> {
        let log = self.call_tropic(|tropic| {
            let log = tropic.get_riscv_firmware_log().map_err(PyError::from)?;
            Ok(log)
        })?;

        Ok(format!("{}", log))
    }

    /// Get certificate store
    ///
    /// Returns:
    ///     str: JSON string with certificate store
    fn get_cert_store(&self) -> PyResult<String> {
        let json = self.call_tropic(|tropic| {
            let mut cert_buf = [0u8; CERT_BUFFER_LEN];
            let cert_store = tropic
                .get_cert_store(&mut cert_buf)
                .map_err(PyError::from)?;
            let json = serde_json::to_string_pretty(&cert_store)?;
            Ok(json)
        })?;

        Ok(json)
    }

    /// Put device to sleep
    ///
    /// Args:
    ///     kind (str): Sleep kind - "Regular" or "Deep"
    fn sleep(&self, kind: &str) -> PyResult<()> {
        self.call_tropic(|tropic| {
            let sleep_kind = match kind {
                "Regular" => SleepKind::Regular,
                "Deep" => SleepKind::Deep,
                _ => return Err(PyError("Invalid sleep kind".to_string())),
            };
            tropic.sleep(sleep_kind).map_err(PyError::from)?;
            Ok(())
        })?;
        Ok(())
    }

    /// Restart the device
    ///
    /// Args:
    ///     mode (str): Restart mode - "Reboot" or "Maintenance"
    fn restart(&self, mode: &str) -> PyResult<()> {
        self.call_tropic(|tropic| {
            let restart_mode = match mode {
                "Reboot" => RestartMode::Reboot,
                "Maintenance" | "Maintanance" => RestartMode::Maintanance,
                _ => return Err(PyError("Invalid restart mode".to_string())),
            };
            tropic.restart(restart_mode).map_err(PyError::from)?;
            Ok(())
        })?;

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
        let json = self.call_tropic(|tropic| {
            let slot = PairingKeySlot::try_from(pairing_key_slot)
                .map_err(|e| PyError(format!("{:?}", e)))?;

            let (handshake_resp, static_secret) = tropic
                .get_handshake(rand::rng(), slot)
                .map_err(PyError::from)?;

            let data = PyHandshakeResp {
                et_pubkey: hex::encode(handshake_resp.et_pubkey.as_bytes()),
                auth_tag: hex::encode(handshake_resp.auth_tag),
                static_secret: hex::encode(static_secret.to_bytes()),
            };

            let json = serde_json::to_string_pretty(&data)?;
            Ok(json)
        })?;
        Ok(json)
    }

    /// Abort the current session
    fn abort_session(&self) -> PyResult<()> {
        self.call_tropic(|tropic| {
            tropic.abort_session().map_err(PyError::from)?;
            Ok(())
        })?;
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
        let mut sess = session.session.lock().unwrap();

        let resp = self.call_tropic(|tropic| {
            let resp = tropic.ping(&mut sess, message).map_err(PyError::from)?;
            Ok(resp)
        })?;

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
        let mut sess = session.session.lock().unwrap();

        let pairing_key_hex = self.call_tropic(|tropic| {
            let pairing_slot =
                PairingKeySlot::try_from(slot).map_err(|e| PyError(format!("{:?}", e)))?;

            let resp = tropic
                .pairing_key_read(&mut sess, pairing_slot)
                .map_err(PyError::from)?;
            Ok(hex::encode(resp.s_hipub))
        })?;

        Ok(pairing_key_hex)
    }

    /// Write pairing key public key
    ///
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    ///     slot (int): Pairing key slot (0-3)
    ///     pubkey_hex (str): Public key as hex string (32 bytes)
    fn pairing_key_write(
        &self,
        session: &PyEncSession,
        slot: u8,
        pubkey_hex: &str,
    ) -> PyResult<()> {
        let mut sess = session.session.lock().unwrap();

        self.call_tropic(|tropic| {
            let pairing_slot =
                PairingKeySlot::try_from(slot).map_err(|e| PyError(format!("{:?}", e)))?;

            let pubkey_bytes = hex::decode(pubkey_hex).map_err(|e| {
                PyError(format!(
                    "Failed to decode byte array from pubkey hex: {}",
                    e
                ))
            })?;

            if pubkey_bytes.len() != 32 {
                return Err(PyError("pubkey must be 32 bytes".to_string()));
            }

            let pubkey = PublicKey::from(<[u8; 32]>::try_from(&pubkey_bytes[..]).unwrap());

            tropic
                .pairing_key_write(&mut sess, pairing_slot, &pubkey)
                .map_err(PyError::from)?;
            Ok(())
        })?;

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
        let mut sess = session.session.lock().unwrap();

        let json = self.call_tropic(|tropic| {
            let config = tropic.r_config_read(&mut sess).map_err(PyError::from)?;
            let json = serde_json::to_string_pretty(&config)?;
            Ok(json)
        })?;

        Ok(json)
    }

    /// Write reversible config
    ///
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    ///     config_json (str): Config as JSON string
    fn r_config_write(&self, session: &PyEncSession, config_json: &str) -> PyResult<()> {
        let mut sess = session.session.lock().unwrap();

        self.call_tropic(|tropic| {
            let config: tropic_rs::common::config::Config = serde_json::from_str(config_json)?;

            tropic
                .r_config_write(&mut sess, &config)
                .map_err(PyError::from)?;
            Ok(())
        })?;
        Ok(())
    }

    /// Invalidate pairing key
    ///
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    ///     slot (int): Pairing key slot (0-3)
    fn pairing_key_invalidate(&self, session: &PyEncSession, slot: u8) -> PyResult<()> {
        let mut sess = session.session.lock().unwrap();

        self.call_tropic(|tropic| {
            let pairing_slot =
                PairingKeySlot::try_from(slot).map_err(|e| PyError(format!("{:?}", e)))?;

            tropic
                .pairing_key_invalidate(&mut sess, pairing_slot)
                .map_err(PyError::from)?;
            Ok(())
        })?;

        Ok(())
    }

    /// Erase reversible config
    ///
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    fn r_config_erase(&self, session: &PyEncSession) -> PyResult<()> {
        let mut sess = session.session.lock().unwrap();

        self.call_tropic(|tropic| {
            tropic
                .r_config_erase(&mut sess)
                .map_err(PyError::from)?;
            Ok(())
        })?;

        Ok(())
    }

    /// Read irreversible config
    ///
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    ///
    /// Returns:
    ///     str: Config as JSON string
    fn i_config_read(&self, session: &PyEncSession) -> PyResult<String> {
        let mut sess = session.session.lock().unwrap();

        let json = self.call_tropic(|tropic| {
            let config = tropic.i_config_read(&mut sess).map_err(PyError::from)?;
            let json = serde_json::to_string_pretty(&config)?;
            Ok(json)
        })?;

        Ok(json)
    }

    /// Write irreversible config
    ///
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    ///     config_json (str): Config as JSON string
    fn i_config_write(&self, session: &PyEncSession, config_json: &str) -> PyResult<()> {
        let mut sess = session.session.lock().unwrap();

        self.call_tropic(|tropic| {
            let config: tropic_rs::common::config::Config = serde_json::from_str(config_json)?;

            tropic
                .i_config_write(&mut sess, &config)
                .map_err(PyError::from)?;
            Ok(())
        })?;

        Ok(())
    }

    /// Read user data from memory slot
    ///
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    ///     slot (int): User data slot (0-511)
    ///
    /// Returns:
    ///     bytes: User data
    fn r_mem_data_read(&self, session: &PyEncSession, slot: u16) -> PyResult<Vec<u8>> {
        let mut sess = session.session.lock().unwrap();

        let data = self.call_tropic(|tropic| {
            let user_slot =
                UserDataSlot::try_from(slot).map_err(|e| PyError(format!("{:?}", e)))?;

            let resp = tropic
                .r_mem_data_read(&mut sess, user_slot)
                .map_err(PyError::from)?;
            Ok(resp.user_data().to_vec())
        })?;

        Ok(data)
    }

    /// Write user data to memory slot
    ///
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    ///     slot (int): User data slot (0-511)
    ///     data (bytes): Data to write (max 32 bytes)
    fn r_mem_data_write(&self, session: &PyEncSession, slot: u16, data: &[u8]) -> PyResult<()> {
        let mut sess = session.session.lock().unwrap();

        self.call_tropic(|tropic| {
            let user_slot =
                UserDataSlot::try_from(slot).map_err(|e| PyError(format!("{:?}", e)))?;

            tropic
                .r_mem_data_write(&mut sess, user_slot, data)
                .map_err(PyError::from)?;
            Ok(())
        })?;

        Ok(())
    }

    /// Erase user data from memory slot
    ///
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    ///     slot (int): User data slot (0-511)
    fn r_mem_data_erase(&self, session: &PyEncSession, slot: u16) -> PyResult<()> {
        let mut sess = session.session.lock().unwrap();

        self.call_tropic(|tropic| {
            let user_slot =
                UserDataSlot::try_from(slot).map_err(|e| PyError(format!("{:?}", e)))?;

            tropic
                .r_mem_data_erase(&mut sess, user_slot)
                .map_err(PyError::from)?;
            Ok(())
        })?;

        Ok(())
    }

    /// Get random bytes
    ///
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    ///     n_bytes (int): Number of random bytes to get (max 32)
    ///
    /// Returns:
    ///     bytes: Random bytes
    fn random_value(&self, session: &PyEncSession, n_bytes: u8) -> PyResult<Vec<u8>> {
        let mut sess = session.session.lock().unwrap();

        let random_bytes = self.call_tropic(|tropic| {
            let resp = tropic
                .random_value(&mut sess, n_bytes)
                .map_err(PyError::from)?;
            Ok(resp.random_data().to_vec())
        })?;

        Ok(random_bytes)
    }

    /// Generate ECC key
    ///
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    ///     slot (int): ECC key slot (0-31)
    ///     curve (str): Curve type ("P256" or "Ed25519")
    fn ecc_key_generate(&self, session: &PyEncSession, slot: u16, curve: &str) -> PyResult<()> {
        let mut sess = session.session.lock().unwrap();

        self.call_tropic(|tropic| {
            let ecc_slot =
                EccKeySlot::try_from(slot).map_err(|e| PyError(format!("{:?}", e)))?;

            let ecc_curve = match curve {
                "P256" => EccCurve::P256,
                "Ed25519" => EccCurve::Ed25519,
                _ => return Err(PyError("Invalid curve type".to_string())),
            };

            tropic
                .ecc_key_generate(&mut sess, ecc_slot, ecc_curve)
                .map_err(PyError::from)?;
            Ok(())
        })?;

        Ok(())
    }

    /// Store ECC key
    ///
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    ///     slot (int): ECC key slot (0-31)
    ///     curve (str): Curve type ("P256" or "Ed25519")
    ///     secret_hex (str): Secret key as hex string (32 bytes)
    fn ecc_key_store(
        &self,
        session: &PyEncSession,
        slot: u16,
        curve: &str,
        secret_hex: &str,
    ) -> PyResult<()> {
        let mut sess = session.session.lock().unwrap();

        self.call_tropic(|tropic| {
            let ecc_slot =
                EccKeySlot::try_from(slot).map_err(|e| PyError(format!("{:?}", e)))?;

            let ecc_curve = match curve {
                "P256" => EccCurve::P256,
                "Ed25519" => EccCurve::Ed25519,
                _ => return Err(PyError("Invalid curve type".to_string())),
            };

            let secret_bytes = hex::decode(secret_hex).map_err(|e| {
                PyError(format!("Failed to decode byte array from secret hex: {}", e))
            })?;

            if secret_bytes.len() != CMD_SECRET_KEY_LEN {
                return Err(PyError(format!(
                    "Secret key must be {} bytes",
                    CMD_SECRET_KEY_LEN
                )));
            }

            let secret: [u8; CMD_SECRET_KEY_LEN] = secret_bytes.try_into().unwrap();

            tropic
                .ecc_key_store(&mut sess, ecc_slot, ecc_curve, &secret)
                .map_err(PyError::from)?;
            Ok(())
        })?;

        Ok(())
    }

    /// Read ECC public key
    ///
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    ///     slot (int): ECC key slot (0-31)
    ///
    /// Returns:
    ///     str: Public key as hex string
    fn ecc_key_read_pubkey(&self, session: &PyEncSession, slot: u16) -> PyResult<String> {
        let mut sess = session.session.lock().unwrap();

        let pubkey_hex = self.call_tropic(|tropic| {
            let ecc_slot =
                EccKeySlot::try_from(slot).map_err(|e| PyError(format!("{:?}", e)))?;

            let resp = tropic
                .ecc_key_read_pubkey(&mut sess, ecc_slot)
                .map_err(PyError::from)?;
            Ok(hex::encode(resp.pubkey))
        })?;

        Ok(pubkey_hex)
    }

    /// Erase ECC key
    ///
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    ///     slot (int): ECC key slot (0-31)
    fn ecc_key_erase(&self, session: &PyEncSession, slot: u16) -> PyResult<()> {
        let mut sess = session.session.lock().unwrap();

        self.call_tropic(|tropic| {
            let ecc_slot =
                EccKeySlot::try_from(slot).map_err(|e| PyError(format!("{:?}", e)))?;

            tropic
                .ecc_key_erase(&mut sess, ecc_slot)
                .map_err(PyError::from)?;
            Ok(())
        })?;

        Ok(())
    }

    /// ECDSA sign message
    ///
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    ///     slot (int): ECC key slot (0-31)
    ///     message (bytes): Message to sign
    ///
    /// Returns:
    ///     str: Signature as hex string
    fn ecc_ecdsa_sign(&self, session: &PyEncSession, slot: u16, message: &[u8]) -> PyResult<String> {
        let mut sess = session.session.lock().unwrap();

        let signature_hex = self.call_tropic(|tropic| {
            let ecc_slot =
                EccKeySlot::try_from(slot).map_err(|e| PyError(format!("{:?}", e)))?;

            let resp = tropic
                .ecc_ecdsa_sign(&mut sess, ecc_slot, message)
                .map_err(PyError::from)?;
            Ok(hex::encode(resp.signature()))
        })?;

        Ok(signature_hex)
    }

    /// EdDSA sign message
    ///
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    ///     slot (int): ECC key slot (0-31)
    ///     message (bytes): Message to sign
    ///
    /// Returns:
    ///     str: Signature as hex string
    fn ecc_eddsa_sign(&self, session: &PyEncSession, slot: u16, message: &[u8]) -> PyResult<String> {
        let mut sess = session.session.lock().unwrap();

        let signature_hex = self.call_tropic(|tropic| {
            let ecc_slot =
                EccKeySlot::try_from(slot).map_err(|e| PyError(format!("{:?}", e)))?;

            let resp = tropic
                .ecc_eddsa_sign(&mut sess, ecc_slot, message)
                .map_err(PyError::from)?;
            Ok(hex::encode(resp.signature()))
        })?;

        Ok(signature_hex)
    }

    /// Initialize monotonic counter
    ///
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    ///     index (int): Counter index (0-15)
    ///     value (int): Initial value
    fn mcounter_init(&self, session: &PyEncSession, index: u16, value: u32) -> PyResult<()> {
        let mut sess = session.session.lock().unwrap();

        self.call_tropic(|tropic| {
            let counter_index =
                MCounterIndex::try_from(index).map_err(|e| PyError(format!("{:?}", e)))?;

            tropic
                .mcounter_init(&mut sess, counter_index, value)
                .map_err(PyError::from)?;
            Ok(())
        })?;

        Ok(())
    }

    /// Update (increment) monotonic counter
    ///
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    ///     index (int): Counter index (0-15)
    fn mcounter_update(&self, session: &PyEncSession, index: u16) -> PyResult<()> {
        let mut sess = session.session.lock().unwrap();

        self.call_tropic(|tropic| {
            let counter_index =
                MCounterIndex::try_from(index).map_err(|e| PyError(format!("{:?}", e)))?;

            tropic
                .mcounter_update(&mut sess, counter_index)
                .map_err(PyError::from)?;
            Ok(())
        })?;

        Ok(())
    }

    /// Get monotonic counter value
    ///
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    ///     index (int): Counter index (0-15)
    ///
    /// Returns:
    ///     int: Counter value
    fn mcounter_get(&self, session: &PyEncSession, index: u16) -> PyResult<u32> {
        let mut sess = session.session.lock().unwrap();

        let value = self.call_tropic(|tropic| {
            let counter_index =
                MCounterIndex::try_from(index).map_err(|e| PyError(format!("{:?}", e)))?;

            let resp = tropic
                .mcounter_get(&mut sess, counter_index)
                .map_err(PyError::from)?;
            Ok(resp.mcounter)
        })?;

        Ok(value)
    }

    /// MAC and destroy operation
    ///
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    ///     slot (int): MAC and destroy slot (0-127)
    ///     data (bytes): Data to MAC (32 bytes)
    ///
    /// Returns:
    ///     bytes: Output data (32 bytes)
    fn mac_and_destroy(&self, session: &PyEncSession, slot: u16, data: &[u8]) -> PyResult<Vec<u8>> {
        let mut sess = session.session.lock().unwrap();

        let output_data = self.call_tropic(|tropic| {
            let mac_slot =
                MacAndDestroySlot::try_from(slot).map_err(|e| PyError(format!("{:?}", e)))?;

            if data.len() != 32 {
                return Err(PyError("Data must be 32 bytes".to_string()));
            }

            let data_array: [u8; 32] = data.try_into().unwrap();

            let resp = tropic
                .mac_and_destroy(&mut sess, &mac_slot, &data_array)
                .map_err(PyError::from)?;
            Ok(resp.data_out.to_vec())
        })?;

        Ok(output_data)
    }

    /// Get serial code
    ///
    /// Args:
    ///     session (PyEncSession): Active encrypted session
    ///
    /// Returns:
    ///     str: Serial code as hex string
    fn serial_code_get(&self, session: &PyEncSession) -> PyResult<String> {
        let mut sess = session.session.lock().unwrap();

        let serial_code_hex = self.call_tropic(|tropic| {
            let resp = tropic
                .serial_code_get(&mut sess)
                .map_err(PyError::from)?;
            Ok(hex::encode(resp.serial_code))
        })?;

        Ok(serial_code_hex)
    }
}

/// Encrypted session wrapper for TROPIC01.
///
/// This class provides a Pythonic interface to all TROPIC01 session functionality.   
///
///Example:
///    >>> /// Create session from handshake
///    >>> session = EncSession.create(tropic, 0, sh_secret_hex, st_pubkey_hex)
///    >>> /// Use session for operations
///    >>> response = tropic.ping(session, b"hello")
///    >>> /// Save session
///    >>> session_json = session.to_json()
///    >>> /// Restore session
///    >>> session = EncSession.from_json(session_json)
#[pyclass(name = "EncSession")]
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
    fn create(
        tropic: &PyTropic01,
        pairing_key_slot: u8,
        sh_secret_hex: &str,
        st_pubkey_hex: &str,
    ) -> PyResult<Self> {
        use tropic_rs::external::x25519_dalek::{PublicKey, StaticSecret};

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

        let mut tropic_lock = tropic
            .tropic
            .as_ref()
            .ok_or(PyException::new_err("tropic not intialised"))?
            .lock()
            .unwrap();
        let session = tropic_lock
            .create_session(rand::rng(), &sh_secret, slot, &st_pubkey)
            .map_err(PyError::from)?;

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
        let session: tropic_rs::l3::session::EncSession =
            serde_json::from_str(json).map_err(json_error_to_pyerr)?;
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
