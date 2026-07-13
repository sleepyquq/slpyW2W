//! 只读兼容性检查器。
//!
//! 只输出文件名、解析结果和字段数量；不会输出配置值。它不写入输入目录。

use std::{env, fs, path::Path};

use hk_proton_core::parse_wireguard;

fn main() {
    let mut failed = false;
    for argument in env::args_os().skip(1) {
        let path = Path::new(&argument);
        let label = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("<invalid-file-name>");

        let source = match fs::read_to_string(path) {
            Ok(source) => source,
            Err(_) => {
                eprintln!("FAIL {label}: 无法读取");
                failed = true;
                continue;
            }
        };

        match parse_wireguard(&source) {
            Ok(parsed) => println!(
                "OK {label}: address={} dns={} allowed_ips={} warnings={}",
                parsed.config.interface.addresses.len(),
                parsed.config.interface.dns_servers.len(),
                parsed.config.peer.allowed_ips.len(),
                parsed.warnings.len(),
            ),
            Err(error) => {
                // ConfigError 的设计保证错误文本不含任何输入值。
                eprintln!("FAIL {label}: {error}");
                failed = true;
            }
        }
    }

    if failed {
        std::process::exit(1);
    }
}
