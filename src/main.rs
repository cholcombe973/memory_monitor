#[macro_use]
extern crate clap;
extern crate humannum;
#[macro_use]
extern crate log;
extern crate process_utils;
extern crate simplelog;

use clap::{Arg, App};
use humannum::parse_integer;
use process_utils::*;
use simplelog::{Config, SimpleLogger};

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
