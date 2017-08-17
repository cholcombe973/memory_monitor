#[macro_use]
extern crate clap;
extern crate humannum;
#[macro_use]
extern crate log;
extern crate nix;
extern crate procinfo;
extern crate simplelog;

use std::fs;
use std::io::{Error, ErrorKind, Read};
use std::io::Result as IOResult;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use std::{thread, time};

use clap::{Arg, App};
use humannum::parse_integer;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
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
            debug!("Parsing pid: {:?}", file_name);
            let pid = match i32::from_str(&file_name.to_string_lossy()) {
                Ok(p) => p,
                Err(_) => {
                    trace!("Skipping entry: {:?}.  Not a process", file_name);
                    continue;
                }
            };
            let s = stat(pid)?;
            if s.command == cmd_name {
                info.push(s);
            }
        } else {
            // Skip entries for anything not a process
            trace!("Skipping entry: {:?}.  Not a process", path);
            continue;
        }
    }
    Ok(info)
}

fn get_cmdline(pid: i32) -> IOResult<Vec<String>> {
    let mut f = fs::File::open(format!("/proc/{}/cmdline", pid))?;
    let mut buff = String::new();
    f.read_to_string(&mut buff)?;
    let args: Vec<String> = buff.split("\0")
        .map(String::from)
        .filter(|arg| !arg.is_empty())
        .collect();
    for arg in &args {
        trace!("cmd arg: {:?}", arg.as_bytes());
    }
    Ok(args)
}

fn spinlock(pid: i32) {
    while Path::new(&format!("/proc/{}", pid)).exists() {
        trace!("Sleeping 10ms");
        //thread::sleep(time::Duration::from_millis(10));
    }
}

//TODO This function is too long
fn kill_and_restart(
    pid_info: Vec<Stat>,
    limit: u64,
    kill_parent: bool,
    simulate: bool,
) -> IOResult<()> {
    for stat_info in pid_info {
        if stat_info.vsize > limit as usize {
            let cmdline = if kill_parent {
                get_cmdline(stat_info.ppid)?
            } else {
                get_cmdline(stat_info.pid)?
            };
            debug!("cmdline: {:?}", cmdline);
            println!(
                "Killing {} process {} for memory at {} and restarting.  Cmdline: {}",
                cmdline[0],
                stat_info.pid,
                stat_info.vsize,
                cmdline.join(" ")
            );
            // If this isn't a simulation we're actually going to kill/restart things here
            if !simulate {
                // Safety first!
                if stat_info.pid == 1 {
                    warn!("Cannot kill pid 1.  Please verify what you're doing here");
                    continue;
                }
                kill(Pid::from_raw(stat_info.pid), Signal::SIGTERM)
                    .map_err(|e| Error::new(ErrorKind::Other, e))?;
                // Spinlock wait for the process to stop
                spinlock(stat_info.pid);
                if kill_parent {
                    if stat_info.ppid == 1 {
                        warn!("Cannot kill pid 1.  Please verify what you're doing here");
                        continue;
                    }
                    println!("Also killing parent process: {}", stat_info.ppid);
                    kill(Pid::from_raw(stat_info.ppid), Signal::SIGTERM)
                        .map_err(|e| Error::new(ErrorKind::Other, e))?;
                    // Spinlock wait for the process to stop
                    spinlock(stat_info.ppid);
                }
                println!("Starting {} up again", cmdline[0]);
                // Restart the process
                Command::new(&cmdline[0]).args(&cmdline[1..]).spawn()?;
                println!("Process successfully spawned");
            }
        }
    }
    Ok(())
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
                .short("l")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("parent")
                .help(
                    "For a child process set this to kill and respawn the parent",
                )
                .long("parent")
                .short("s"),
        )
        .arg(
            Arg::with_name("test")
                .help("Simulate but don't take any action")
                .long("test")
                .short("t"),
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
    debug!("Setting log level to: {}", level);
    let _ = SimpleLogger::init(level, Config::default());

    let limit = matches.value_of("limit").unwrap();
    debug!("Memory limit: {}", limit);
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
    kill_and_restart(
        pid_info,
        memory_byte_limit,
        matches.is_present("parent"),
        matches.is_present("test"),
    );
    println!("Finished");
}
