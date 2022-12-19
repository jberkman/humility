// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! ## `humility debugmailbox`
//!
//! The LPC55 includes an extra access port referred to as the Debug Mailbox.
//! This allows for running a fixed set of commands to do useful things such
//! as forcing SWD enablement and putting the chip into ISP mode without
//! needing to touch an external pin
//!
//! ```console
//! $ humility debugmailbox debug
//! Looks like a plausible debug mailbox
//! Reset chip successfully!
//! entering debug
//!
//! $ humility debugmailbox isp
//! Looks like a plausible debug mailbox
//! Reset chip successfully!
//! entered ISP mode!
//! ```

use anyhow::{bail, Result};
use clap::Command as ClapCommand;
use clap::{CommandFactory, Parser};
use humility::cli::Subcommand;
use humility_cmd::{Archive, Command};
use packed_struct::prelude::*;
use probe_rs::{
    architecture::arm::{ApAddress, ArmProbeInterface, DpAddress},
    Probe,
};
use rsa::{pkcs1::FromRsaPrivateKey, PublicKeyParts};
use sha2::Digest;
use std::path::PathBuf;

// The debug mailbox registers
// See 51.5.5.1 of Rev 2.4 of the LPC55 manual
const CSW: u8 = 0x0;
const REQUEST: u8 = 0x4;
const RETURN: u8 = 0x8;
const IDR: u8 = 0xFC;

// See 51.5.5.1.4 of Rev 2.4 of the LPC55 manual
const DM_ID: u32 = 0x002a_0000;

// See 51.5.7.3 of Rev 2.4 of the LPC55 manual
const ACK_TOKEN: u32 = 0xa5a5;

// See 51.5.7.1.1 of Rev 2.4 of the LPC55 manual
#[repr(u8)]
pub enum DMCommand {
    //StartDM = 0x1,
    BulkErase = 0x3,
    ExitDM = 0x4,
    ISPMode = 0x5,
    //FAMode = 0x6,
    StartDebug = 0x7,
    DebugChallenge = 0x10,
    DebugResponse = 0x11,
}

#[derive(PackedStruct, Debug)]
#[packed_struct(size_bytes = "104", bit_numbering = "msb0", endian = "lsb")]
pub struct DebugAuthChallenge {
    version: u32,
    soc_class: u32,
    uuid: [u8; 16],
    revoke: u32,
    rot_id: [u8; 32],
    socu_pin: u32,
    socu_dflt: u32,
    vendor_usage: u32,
    cv: [u8; 32],
}

#[derive(PackedStruct, Debug)]
#[packed_struct(size_bytes = "940", bit_numbering = "msb0", endian = "lsb")]
pub struct DebugCred {
    version: u32,
    soc_class: u32,
    uuid: [u8; 16],
    rot_id: [u8; 128],
    dck_mod: [u8; 256],
    dck_exp: [u8; 4],
    cc_socu: u32,
    vendor: u32,
    beacon: u32,
    rotk_mod: [u8; 256],
    rotk_exp: [u8; 4],
    sig: [u8; 256],
}

impl DebugCred {
    fn new() -> Self {
        DebugCred {
            version: 0,
            soc_class: 0,
            uuid: [0; 16],
            rot_id: [0; 128],
            dck_mod: [0; 256],
            dck_exp: [0; 4],
            cc_socu: 0,
            vendor: 0,
            beacon: 0,
            rotk_mod: [0; 256],
            rotk_exp: [0; 4],
            sig: [0; 256],
        }
    }
}

#[derive(PackedStruct, Debug, Copy, Clone)]
#[packed_struct(size_bytes = "1200", bit_numbering = "msb0", endian = "lsb")]
pub struct DebugResponse {
    dc: [u8; 940],
    ab: [u8; 4],
    sig: [u8; 256],
}

#[derive(Parser, Debug)]
#[clap(name = "subcmd")]
enum DebugMailboxCmd {
    /// Force the device into a mode to attach SWD
    /// This will not work if you have secure boot enabled!
    Debug,
    /// Force the device into ISP mode
    Isp,
    /// Perform debug authentication
    DebugAuth { debugger_priv: PathBuf, rot_priv: PathBuf },
}

fn debug_challenge<'a>(
    probe: &mut Box<dyn ArmProbeInterface + 'a>,
    addr: &ApAddress,
) -> Result<DebugAuthChallenge> {
    // Start debug auth
    let result = write_req(probe, addr, DMCommand::DebugChallenge, &[])?;

    let transform = unsafe {
        core::slice::from_raw_parts::<u8>(
            result.as_ptr() as *const u8,
            result.len() * 4,
        )
    };

    let region = DebugAuthChallenge::unpack(&transform.try_into()?)?;

    println!("Hmmm {:x?}", region);
    Ok(region)
}

fn debug_response<'a>(
    probe: &mut Box<dyn ArmProbeInterface + 'a>,
    addr: &ApAddress,
    bytes: &[u8],
) -> Result<()> {
    let transform = unsafe {
        core::slice::from_raw_parts::<u32>(
            bytes.as_ptr() as *const u32,
            bytes.len() / 4,
        )
    };

    write_req(probe, addr, DMCommand::DebugResponse, &transform)?;

    Ok(())
}

fn exit_debug_mailbox<'a>(
    probe: &mut Box<dyn ArmProbeInterface + 'a>,
    addr: &ApAddress,
) -> Result<()> {
    let _ = write_req(probe, addr, DMCommand::ExitDM, &[])?;

    Ok(())
}

fn debug_auth<'a>(
    probe: &mut Box<dyn ArmProbeInterface + 'a>,
    dm_port: &ApAddress,
    debugger_priv: &PathBuf,
    rot_priv: &PathBuf,
) -> Result<()> {
    let challenge = debug_challenge(probe, dm_port)?;

    let debugger_priv_key =
        rsa::RsaPrivateKey::read_pkcs1_pem_file(debugger_priv)?;
    let rot_priv_key = rsa::RsaPrivateKey::read_pkcs1_pem_file(rot_priv)?;

    let mut cred = DebugCred::new();

    cred.version = challenge.version;
    cred.soc_class = challenge.soc_class;

    let mut key_hash = sha2::Sha256::new();

    // Same method used in generating hashes for images
    let n = rot_priv_key.n();
    let e = rot_priv_key.e();
    key_hash.update(&n.to_bytes_be());
    key_hash.update(&e.to_bytes_be());
    cred.rot_id[..32].clone_from_slice(&key_hash.finalize());

    cred.dck_mod.clone_from_slice(&debugger_priv_key.n().to_bytes_be());
    // This is weird because the exponent is only 3 bytes...
    for (i, c) in debugger_priv_key.e().to_bytes_be().iter().enumerate() {
        cred.dck_exp[3 - i] = *c;
    }
    cred.cc_socu = 0x3ff;

    cred.rotk_mod.clone_from_slice(&rot_priv_key.n().to_bytes_be());
    for (i, c) in rot_priv_key.e().to_bytes_be().iter().enumerate() {
        cred.rotk_exp[3 - i] = *c;
    }

    let cred_bytes = cred.pack()?;

    let mut hash = sha2::Sha256::new();

    hash.update(&cred_bytes[..0x2ac]);

    let sig = rot_priv_key.sign(
        rsa::padding::PaddingScheme::PKCS1v15Sign {
            hash: Some(rsa::hash::Hash::SHA2_256),
        },
        hash.finalize().as_slice(),
    )?;

    cred.sig.clone_from_slice(&sig[..]);

    let signed_bytes = cred.pack()?;

    let mut response =
        DebugResponse { dc: signed_bytes.clone(), ab: [0; 4], sig: [0; 256] };

    let mut response_hash = sha2::Sha256::new();

    response_hash.update(&response.dc);
    response_hash.update(&response.ab);
    response_hash.update(&challenge.cv);

    let saved_hash = response_hash.finalize();

    let response_sig = debugger_priv_key.sign(
        rsa::padding::PaddingScheme::PKCS1v15Sign {
            hash: Some(rsa::hash::Hash::SHA2_256),
        },
        saved_hash.clone().as_slice(),
    )?;

    response.sig.clone_from_slice(&response_sig);

    debug_response(probe, dm_port, &response.pack()?)?;

    exit_debug_mailbox(probe, dm_port)?;

    Ok(())
}

fn alive<'a>(
    probe: &mut Box<dyn ArmProbeInterface + 'a>,
    addr: &ApAddress,
) -> Result<()> {
    probe.write_raw_ap_register(*addr, CSW, 0x21)?;

    let mut timeout = 100;
    loop {
        std::thread::sleep(std::time::Duration::from_millis(10));
        if let Ok(val) = probe.read_raw_ap_register(*addr, CSW) {
            if val == 0 {
                break;
            }
        }

        if timeout == 0 {
            break;
        } else {
            timeout -= -1;
        }
    }

    if timeout == 0 {
        bail!("Timed out waiting for reset. Chip is unlikely to be alive!");
    } else {
        println!("Reset chip successfully!");
        Ok(())
    }
}

fn write_request_reg<'a>(
    probe: &mut Box<dyn ArmProbeInterface + 'a>,
    addr: &ApAddress,
    val: u32,
) -> Result<()> {
    probe.write_raw_ap_register(*addr, REQUEST, val)?;

    let mut timeout = 100;
    loop {
        std::thread::sleep(std::time::Duration::from_millis(10));
        if let Ok(val) = probe.read_raw_ap_register(*addr, CSW) {
            if val == 0 {
                break;
            } else if val & 0x4 == 0x4 {
                bail!("debug overrun");
            } else if val & 0x8 == 0x8 {
                bail!("AHB overrun!");
            }
        }

        if timeout == 0 {
            break;
        } else {
            timeout -= 1;
        }
    }

    if timeout == 0 {
        bail!("Timed out waiting for request, chip may not be alive!");
    }

    Ok(())
}

fn write_req<'a>(
    probe: &mut Box<dyn ArmProbeInterface + 'a>,
    addr: &ApAddress,
    command: DMCommand,
    args: &[u32],
) -> Result<Vec<u32>> {
    let val = (command as u32) | ((args.len() as u32) << 16);

    write_request_reg(probe, addr, val)?;

    for (i, c) in args.iter().enumerate() {
        let ret = read_return(probe, addr)?;

        if ret & 0xffff != ACK_TOKEN {
            bail!("Bad return {:x}", ret);
        }

        if ((ret >> 16) & 0xffff) != ((args.len() - i) as u32) {
            bail!("Parameter length mismatch!");
        }

        write_request_reg(probe, addr, *c)?;
    }

    let b = read_return(probe, addr)?;

    let mut response_len = (b >> 16) & 0x7fff;

    let ret_val = b & 0xffff;

    if ret_val != 0 {
        bail!("request fail {:x}", ret_val);
    }

    let mut response: Vec<u32> = Vec::new();

    if response_len == 0 {
        return Ok(response);
    }

    while response_len > 0 {
        write_request_reg(probe, addr, response_len << 16 | ACK_TOKEN)?;

        let b = read_return(probe, addr)?;

        response.push(b);

        response_len -= 1;
    }

    write_request_reg(probe, addr, ACK_TOKEN)?;

    Ok(response)
}

fn read_return<'a>(
    probe: &mut Box<dyn ArmProbeInterface + 'a>,
    addr: &ApAddress,
) -> Result<u32> {
    let mut timeout = 100;
    loop {
        std::thread::sleep(std::time::Duration::from_millis(10));
        if let Ok(val) = probe.read_raw_ap_register(*addr, RETURN) {
            return Ok(val);
        }

        if timeout == 0 {
            break;
        } else {
            timeout -= 1;
        }
    }

    bail!("Timed out reading return!");
}

fn debugmailboxcmd(context: &mut humility::ExecutionContext) -> Result<()> {
    let Subcommand::Other(subargs) = context.cli.cmd.as_ref().unwrap();
    let subargs = DebugMailboxArgs::try_parse_from(subargs)?;

    // Get a list of all available debug probes.
    let probes = Probe::list_all();

    if probes.is_empty() {
        bail!("No probes found!");
    }

    let num = subargs.probe_num.unwrap_or(0);

    if num > probes.len() {
        bail!("Invalid probe number {}", num);
    }

    // Use the specified probe or the first one found.
    let mut probe = probes[num].open()?;

    probe.attach_to_unspecified()?;
    let mut iface = probe
        .try_into_arm_interface()
        .unwrap()
        .initialize_unspecified()
        .unwrap();

    let dm_port = ApAddress { dp: DpAddress::Default, ap: 2 };

    // Check if this is a debug mailbox. This is based on the sequence from
    // the LPC55 Debug Mailbox user manual
    //
    // The manual presumes we have to bank select manually but probe-rs
    // handles this for us

    // Check the IDR
    let val = iface.read_raw_ap_register(dm_port, IDR)?;

    if val != DM_ID {
        bail!("IDR incorrect: {:x}", val);
    }
    {
        println!("Looks like a plausible debug mailbox");
    }

    alive(&mut iface, &dm_port)?;

    match subargs.cmd {
        DebugMailboxCmd::Debug => {
            let _ =
                write_req(&mut iface, &dm_port, DMCommand::StartDebug, &[])?;

            println!("entering debug");
        }
        DebugMailboxCmd::Isp => {
            // The argument here 0x1 = UART.
            let _ =
                write_req(&mut iface, &dm_port, DMCommand::ISPMode, &[0x1])?;

            println!("entered ISP mode!");
        }
        DebugMailboxCmd::DebugAuth { debugger_priv, rot_priv } => {
            debug_auth(&mut iface, &dm_port, &debugger_priv, &rot_priv)?;

            println!("Debug auth'd");
        }
    };

    Ok(())
}
#[derive(Parser, Debug)]
#[clap(name = "debugmailbox", about = env!("CARGO_PKG_DESCRIPTION"))]
struct DebugMailboxArgs {
    /// Which probe to connect
    probe_num: Option<usize>,

    #[clap(subcommand)]
    cmd: DebugMailboxCmd,
}

pub fn init() -> (Command, ClapCommand<'static>) {
    (
        Command::Unattached {
            name: "debugmailbox",
            archive: Archive::Ignored,
            run: debugmailboxcmd,
        },
        DebugMailboxArgs::command(),
    )
}
