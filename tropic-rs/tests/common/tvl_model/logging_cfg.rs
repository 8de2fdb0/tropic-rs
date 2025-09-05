use std::{collections::HashMap, io::Write};

use serde::Serialize;
use tempfile::{Builder, NamedTempFile};

#[derive(Debug, Serialize)]
pub enum LoggerClass {
    #[serde(rename = "logging.StreamHandler")]
    StreamHandler,
    #[serde(rename = "logging.FileHandler")]
    FileHandler,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Critical,
}

#[derive(Debug, Serialize)]
pub struct Formatter {
    format: String,
}

#[derive(Debug, Serialize)]
pub struct Handler {
    class: LoggerClass,
    level: LogLevel,
    formatter: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Root {
    level: LogLevel,
    handlers: Vec<String>,
    disable_existing_loggers: bool,
}

#[derive(Debug, Serialize)]
pub struct LoggingCfg {
    version: u8,
    formatters: HashMap<String, Formatter>,
    handlers: HashMap<String, Handler>,
    root: Root,
}

impl LoggingCfg {
    pub fn with_file_log(mut self, test_name: &str, log_level: LogLevel) -> (Self, NamedTempFile) {
        let model_log_tmpfile = Builder::new()
            .prefix(&format!("test_model__{test_name}__"))
            .suffix(".log")
            .tempfile()
            .expect("failed to create tempfile");

        self.handlers.insert(
            "file".to_string(),
            Handler {
                class: LoggerClass::FileHandler,
                level: log_level,
                formatter: "simple".to_string(),
                encoding: Some("utf8".to_string()),
                mode: Some("w".to_string()),
                filename: Some(model_log_tmpfile.path().to_string_lossy().to_string()),
                stream: None,
            },
        );
        self.root.handlers.push("file".to_string());
        (self, model_log_tmpfile)
    }

    pub fn write_to_tempfile(&self) -> NamedTempFile {
        let yaml = serde_yaml::to_string(self).expect("failed to serialize logging config");

        let mut model_log_cfg_tmpfile = Builder::new()
            .prefix("test_model_logging_config_")
            .suffix(".yml")
            .tempfile()
            .expect("failed to create tempfile");

        write!(model_log_cfg_tmpfile, "{yaml}").expect("failed to write to tempfile");
        model_log_cfg_tmpfile
            .flush()
            .expect("failed to flush tempfile");
        model_log_cfg_tmpfile
    }
}

impl Default for LoggingCfg {
    fn default() -> Self {
        let mut formatters = HashMap::new();
        formatters.insert(
            "simple".to_string(),
            Formatter {
                format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s".to_string(),
            },
        );
        Self {
            version: 1,
            formatters,
            handlers: HashMap::new(),
            root: Root {
                level: LogLevel::Debug,
                handlers: Vec::new(),
                disable_existing_loggers: false,
            },
        }
    }
}

// version: 1
// formatters:
//   simple:
//     format: '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

// handlers:
//   console:
//     class : logging.StreamHandler
//     level: DEBUG
//     formatter: simple
//     stream: ext://sys.stdout
//   file:
//     class: logging.FileHandler
//     level: INFO
//     formatter: simple
//     encoding: utf8
//     mode: w
//     filename: ./test.log

// root:
//   level: DEBUG
//   handlers: [console, file]
// disable_existing_loggers: False
