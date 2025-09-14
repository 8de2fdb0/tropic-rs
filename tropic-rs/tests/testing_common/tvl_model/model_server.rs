use std::{
    io::Error,
    net::{Ipv4Addr, SocketAddr, TcpListener},
    process::{Child, Command},
    thread::sleep,
    time::Duration,
};

use derive_builder::Builder;
use log::{debug, error, info, warn};
use tempfile::NamedTempFile;
use wait_timeout::ChildExt;

use crate::testing_common::{LogLevel, LoggingCfg, ModelCfg, ModelCfgBuilder};

fn get_ephemeral_listener() -> Result<(TcpListener, u16), Error> {
    let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
    let listener = TcpListener::bind(addr)?;
    let port = listener.local_addr()?.port();
    Ok((listener, port))
}

struct ModelServerInner {
    port: u16,
    model_cfg_tmpfile: NamedTempFile,
    model_logging_cfg: LoggingCfg,
    model_logging_cfg_tmpfile: NamedTempFile,
    model_server_log: NamedTempFile,

    child: Child,
}

#[derive(Builder)]
pub struct ModelServer {
    #[builder(setter(into), default = LogLevel::Info)]
    log_level: LogLevel,
    #[builder(setter(into), default = ModelCfgBuilder::default().build().unwrap())]
    model_cfg: ModelCfg,
    #[builder(setter(into))]
    test_name: String,

    #[builder(setter(skip))]
    inner: Option<ModelServerInner>,
}

impl ModelServer {
    // A function to set up the server.
    pub fn start_tcp(&mut self) {
        // Get a free port in the Rust parent process and hold onto it.
        let (listener, port) = get_ephemeral_listener().expect("Failed to get free port");

        // We don't need the listener anymore since the Python process will re-bind.
        drop(listener);
        debug!("got ephemeral port {}", port);

        // Write model config to temp file.
        let model_cfg_tmpfile = self.model_cfg.write_to_tempfile();
        debug!("wrote model config to: {:?}", model_cfg_tmpfile.path());

        // Create model server logging config and write it to tempfile
        let (model_logging_cfg, mut model_server_log) =
            LoggingCfg::default().with_file_log(&self.test_name, self.log_level.clone());
        info!("model server log file path: {:?}", model_server_log.path());

        // Disable cleanup for the modle server log, will be cleaned on ModelServer::cleanup
        model_server_log.disable_cleanup(true);
        let model_logging_cfg_tmpfile = model_logging_cfg.write_to_tempfile();
        debug!(
            "wrote model logging config to: {:?}",
            model_logging_cfg_tmpfile.path()
        );

        info!("Starting TROPIC Verification Library server...");
        let child = Command::new("model_server") // Or "python" depending on your system
            .arg("tcp")
            .arg("-p")
            .arg(port.to_string())
            .arg("-l")
            .arg(model_logging_cfg_tmpfile.path())
            .arg("-c")
            .arg(model_cfg_tmpfile.path())
            .spawn()
            .expect("Failed to start TROPIC Verification Library server");

        // Give the server a moment to start up.
        // The duration will depend on how fast your server starts.
        sleep(Duration::from_secs(2));

        self.inner = Some(ModelServerInner {
            port,
            model_cfg_tmpfile,
            model_logging_cfg,
            model_logging_cfg_tmpfile,
            model_server_log,
            child,
        });
    }

    pub fn port(&self) -> Option<u16> {
        self.inner.as_ref().map(|inner| inner.port)
    }

    pub fn cleanup(&mut self) {
        if let Some(inner) = self.inner.as_mut() {
            inner.model_server_log.disable_cleanup(false)
        }
    }
}
impl Drop for ModelServer {
    fn drop(&mut self) {
        if let Some(inner) = &mut self.inner {
            #[cfg(unix)]
            {
                use libc::{SIGTERM, c_int};

                // This is a bit of a workaround since std::process::Child doesn't have `terminate()`.
                // We get the process ID and send the SIGTERM signal directly.
                let pid = inner.child.id() as c_int;
                unsafe {
                    if libc::kill(pid, SIGTERM) == -1 {
                        // Log or handle the error, but don't panic.

                        use log::error;
                        error!("Failed to send SIGTERM: {:?}", Error::last_os_error());
                    }
                }
            }

            // Wait for 2 seconds for the process to terminate gracefully.
            let wait_result = inner.child.wait_timeout(Duration::from_secs(2));

            match wait_result {
                Ok(Some(_status)) => {
                    debug!("TROPIC Verification Library server shut down gracefully.");
                }
                Ok(None) => {
                    // Timeout elapsed, the process is still running.
                    // Now, use the last resort: a forced kill.
                    warn!("Timeout exceeded, killing process forcefully...");
                    if let Err(e) = inner.child.kill() {
                        error!("Failed to kill child process: {}", e);
                    }
                    let _ = inner.child.wait(); // Wait for it to die to prevent a zombie process.
                }
                Err(e) => {
                    error!("Error while waiting for child process: {}", e);
                    // In case of error, still try to kill to be safe.
                    let _ = inner.child.kill();
                }
            }
        }
    }
}
