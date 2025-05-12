use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, BufRead, BufReader, BufWriter, Write},
    os::unix::net::{UnixListener, UnixStream},
    process::exit,
};
use tokio::runtime::Runtime;

const SOCKET_PATH: &str = "/tmp/easy-proxy.sock";

#[derive(Debug, Serialize, Deserialize)]
pub struct Commands {
    pub message_type: String,
    pub message: String,
}

impl Commands {
    pub fn run() {
        // Remove existing socket file
        if let Err(e) = fs::remove_file(SOCKET_PATH) {
            if e.kind() != io::ErrorKind::NotFound {
                tracing::error!("Failed to remove {}: {:?}", SOCKET_PATH, e);
                exit(1);
            }
        }
        // Bind to the socket
        let listener = UnixListener::bind(SOCKET_PATH).unwrap_or_else(|e| {
            tracing::error!("Bind {} error: {:?}", SOCKET_PATH, e);
            exit(1);
        });
        tracing::info!("Listening on {}", SOCKET_PATH);
        // Reuse a single Tokio runtime
        let rt = Runtime::new().unwrap();
        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    if let Err(e) = handle_connection(s, &rt) {
                        tracing::error!("Connection error: {:?}", e);
                    }
                }
                Err(e) => tracing::error!("Accept error: {:?}", e),
            }
        }
    }

    pub fn send_command(command_str: &str) {
        // Connect and wrap in buffered I/O
        let mut stream = UnixStream::connect(SOCKET_PATH).unwrap_or_else(|e| {
            tracing::error!("Connect {} error: {:?}", SOCKET_PATH, e);
            exit(1);
        });
        let cmd = Commands {
            message_type: "command".into(),
            message: command_str.into(),
        };
        let mut writer = BufWriter::new(&stream);
        serde_json::to_writer(&mut writer, &cmd).unwrap();
        writer.write_all(b"\n").unwrap();
        writer.flush().unwrap();

        let mut reader = BufReader::new(&stream);
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            tracing::error!("Empty response");
            return;
        }
        match serde_json::from_str::<Commands>(line.trim()) {
            Ok(res) => match res.message_type.as_str() {
                "error" => {
                    tracing::error!("{}", res.message);
                    exit(1);
                }
                _ => tracing::info!("{}", res.message),
            },
            Err(e) => tracing::error!("Invalid response: {:?}", e),
        }
    }
}

fn handle_connection(stream: UnixStream, rt: &Runtime) -> io::Result<()> {
    let mut reader = BufReader::new(&stream);
    let mut writer = BufWriter::new(&stream);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(());
    }
    let cmd: Commands =
        serde_json::from_str(line.trim()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let mut res = Commands {
        message_type: "response".into(),
        message: String::new(),
    };
    if cmd.message_type == "command" {
        match cmd.message.as_str() {
            "reload" => rt.block_on(async {
                match crate::config::proxy::load().await {
                    Ok(_) => res.message = "Proxy configuration loaded successfully".into(),
                    Err(e) => {
                        tracing::error!("Error loading proxy config: {:?}", e);
                        res.message_type = "error".into();
                        res.message = format!("Error: {:?}", e);
                    }
                }
            }),
            "test" => rt.block_on(async {
                match crate::config::proxy::read().await {
                    Ok(c) => match crate::config::store::load(c).await {
                        Ok(_) => res.message = "Proxy configuration tested successfully".into(),
                        Err(e) => {
                            tracing::error!("Error loading proxy config: {:?}", e);
                            res.message_type = "error".into();
                            res.message = format!("Error loading proxy config: {:?}", e);
                        }
                    },
                    Err(e) => {
                        tracing::error!("Error reading proxy config: {:?}", e);
                        res.message_type = "error".into();
                        res.message = format!("Error reading proxy config: {:?}", e);
                    }
                }
            }),
            other => tracing::info!("Unknown command: {}", other),
        }
    }
    serde_json::to_writer(&mut writer, &res)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}
