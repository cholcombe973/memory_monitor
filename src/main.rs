#[macro_use]
extern crate clap;
extern crate humannum;
#[macro_use]
extern crate log;
extern crate procinfo;
extern crate simplelog;

use std::fs;
use std::io::Result as IOResult;
use std::io::{Error, ErrorKind};
use std::str::FromStr;

use clap::{Arg, App};
use humannum::parse_integer;
use procinfo::pid::{stat, Stat};
use simplelog::{Config, SimpleLogger};

fn find_all_pids(cmd_name: &str) -> IOResult<Vec<Stat>> {
    let mut info: Vec<Stat> = Vec::new();
    for entry in fs::read_dir("/proc/")? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let file_name = match path.file_name() {
                Some(f) => f,
                None => {
                    //Unable to determine file name
                    debug!("Unable to determine file name for {:?}. Skipping", path);
                    continue;
                }
            };
            let pid = i32::from_str(&file_name.to_string_lossy()).map_err(|e| {
                Error::new(ErrorKind::Other, format!("pid parsing failed: {}", e))
            })?;
            let s = stat(pid)?;
            if s.command == cmd_name {
                info.push(s);
            }
        } else {
            // Skip entries for anything not a process
            debug!("Skipping entry: {:?}.  Not a process", path);
            continue;
        }
    }
    Ok(info)
}

fn kill_and_restart(pid_info: Vec<Stat>, limit: u64) {
    for stat in pid_info {
        if stat.vsize > limit as usize {
            println!(
                "Killing {} process {} for memory at {} and restarting",
                stat.command,
                stat.pid,
                stat.vsize
            );
        }
    }
}

fn main() {
    let matches = App::new("Memory Monitor")
        .about("Kills a process that is using too much ram and restarts it")
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .arg(
            Arg::with_name("process_name")
                .help("The name of the process to monitor")
                .long("process_name")
                .short("p")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("limit")
                .help(
                    "The memory limit. Accepts things like :
                    25M, or 1G or 1048576
                    ki, Mi, Gi -- binary suffixes 8Ki → 8192
                    k, M, G -- decimal suffixes 25M → 25000000",
                )
                .long("limit")
                .required(true)
                .short("m")
                .takes_value(true),
        )
        .arg(Arg::with_name("v").short("v").multiple(true).help(
            "Sets the level of verbosity",
        ))
        .get_matches();

    let level = match matches.occurrences_of("v") {
        0 => log::LogLevelFilter::Info, //default
        1 => log::LogLevelFilter::Debug,
        _ => log::LogLevelFilter::Trace,
    };
    let _ = SimpleLogger::init(level, Config::default());

    let limit = matches.value_of("limit").unwrap();
    let proc_name = matches.value_of("process_name").unwrap();
    let memory_byte_limit: u64 = match parse_integer(limit) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Parsing of {} failed with error: {}.  Exiting", limit, e);
            return;
        }
    };
    println!("Searching for all processes with name: {}", proc_name);
    let pid_info = match find_all_pids(proc_name) {
        Ok(stat_info) => stat_info,
        Err(e) => {
            error!("Failed to gather proc info: {}.  Exiting", e);
            return;
        }
    };
    println!("Determining if any should be restarted");
    kill_and_restart(pid_info, memory_byte_limit);

}
