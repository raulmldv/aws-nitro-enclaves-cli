// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

/// Simple proxy for translating vsock traffic to TCP traffic
/// Example of usage:
/// vsock-proxy 8000 127.0.0.1 9000
///
use clap::{App, AppSettings, Arg};
use env_logger::init;
use log::info;

use vsock_proxy::starter::{Proxy, ProxyArgs, ProxyType, VsockProxyResult};

fn main() -> VsockProxyResult<()> {
    init();

    let matches = App::new("Vsock-TCP proxy")
        .about("Vsock-TCP proxy")
        .setting(AppSettings::DisableVersion)
        .arg(
            Arg::with_name("ipv4")
                .short("4")
                .long("ipv4")
                .help("Force the proxy to use IPv4 addresses only.")
                .required(false),
        )
        .arg(
            Arg::with_name("ipv6")
                .short("6")
                .long("ipv6")
                .help("Force the proxy to use IPv6 addresses only.")
                .required(false)
                .conflicts_with("ipv4"),
        )
        .arg(
            Arg::with_name("workers")
                .short("w")
                .long("num_workers")
                .help("Set the maximum number of simultaneous\nconnections supported.")
                .required(false)
                .takes_value(true)
                .default_value("4"),
        )
        .arg(
            Arg::with_name("enclave_server")
                .long("enclave-server")
                .help("Changes proxy mode to listen on a TCP port and connect to a server over Vsock.")
                .required(false)
                .number_of_values(3),
        )
        .arg(
            Arg::with_name("local_port")
                .help("Local Vsock port to listen for incoming connections.")
                .required_unless("enclave_server"),
        )
        .arg(
            Arg::with_name("remote_addr")
                .help("Address of the server to be proxyed.")
                .required_unless("enclave_server"),
        )
        .arg(
            Arg::with_name("remote_port")
                .help("Remote TCP port of the server to be proxyed.")
                .required_unless("enclave_server"),
        )
        .arg(
            Arg::with_name("config_file")
                .long("config")
                .help("YAML file containing the services that\ncan be forwarded.\n")
                .required(false)
                .takes_value(true)
                .default_value("/etc/nitro_enclaves/vsock-proxy.yaml"),
        )
        .arg(
            Arg::with_name("exposed_port")
                .help("TCP port the proxy listens on.")
                .required(false),
        )
        .arg(
            Arg::with_name("remote_cid")
                .help("CID of the enclave containing the server app.")
                .required(false),
        )
        .arg(
            Arg::with_name("vsock_port")
                .help("Vsock port to connect to the server.")
                .required(false),
        )
        .get_matches();

    let proxy_type = if matches.is_present("enclave_server") {
        ProxyType::ServerOverVsock
    } else {
        ProxyType::ClientOverVsock
    };

    let only_4 = matches.is_present("ipv4");
    let only_6 = matches.is_present("ipv6");

    let num_workers = matches
        .value_of("workers")
        // This argument has a default value, so it is available
        .unwrap();
    let num_workers = num_workers
        .parse::<usize>()
        .map_err(|_| "Number of workers is not valid")?;

    let config_file = matches.value_of("config_file");

    match proxy_type {
        ProxyType::ClientOverVsock => {
            let local_port = matches
                .value_of("local_port")
                // This argument is required, so clap ensures it's available
                .unwrap();
            let local_port = local_port
                .parse::<u32>()
                .map_err(|_| "Local port is not valid")?;

            let remote_addr = matches
                .value_of("remote_addr")
                // This argument is required, so clap ensures it's available
                .unwrap();

            let remote_port = matches
                .value_of("remote_port")
                // This argument is required, so clap ensures it's available
                .unwrap();
            let remote_port = remote_port
                .parse::<u16>()
                .map_err(|_| "Remote port is not valid")?;

            let proxy = Proxy::new(
                proxy_type,
                ProxyArgs::new_client_over_vsock(local_port, remote_addr.to_string(), remote_port)
                    .map_err(|err| format!("Could not create proxy: {}", err))?,
                num_workers,
                config_file,
                only_4,
                only_6,
            )
            .map_err(|err| format!("Could not create proxy: {}", err))?;

            let listener = proxy
                .vsock_listen()
                .map_err(|err| format!("Could not listen for connections: {}", err))?;
            info!("Proxy is now in listening state");
            loop {
                proxy
                    .vsock_accept(&listener)
                    .map_err(|err| format!("Could not accept connection: {}", err))?;
            }
        }
        ProxyType::ServerOverVsock => {
            let args: Vec<_> = matches.values_of("enclave_server").unwrap().collect();

            let exposed_port = args.get(0).unwrap();
            let exposed_port = exposed_port
                .parse::<u16>()
                .map_err(|_| "Exposed port is not valid")?;

            let remote_cid = args.get(1).unwrap();
            let remote_cid = remote_cid.parse::<u32>().map_err(|_| "CID is not valid")?;

            let vsock_port = args.get(2).unwrap();
            let vsock_port = vsock_port
                .parse::<u32>()
                .map_err(|_| "Vsock port is not valid")?;

            let proxy = Proxy::new(
                proxy_type,
                ProxyArgs::new_server_over_vsock(exposed_port, remote_cid, vsock_port)
                    .map_err(|err| format!("Could not create proxy: {}", err))?,
                num_workers,
                config_file,
                only_4,
                only_6,
            )
            .map_err(|err| format!("Could not create proxy: {}", err))?;

            info!("Proxy created {:#?}", proxy.proxy_args.exposed_port);

            let listener = proxy
                .sock_listen()
                .map_err(|err| format!("Could not listen for connections: {}", err))?;
            info!("Proxy is now in listening state");
            loop {
                proxy
                    .sock_accept(&listener)
                    .map_err(|err| format!("Could not accept connection: {}", err))?;
            }
        }
    }
}
