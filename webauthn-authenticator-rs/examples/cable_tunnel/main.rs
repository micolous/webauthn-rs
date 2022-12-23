//! `cable_tunnel` shares a [Token] over a caBLE connection.
#[macro_use]
extern crate tracing;

use bluetooth_hci::{
    event::VendorEvent,
    host::{
        uart::Hci as UartHci, AdvertisingFilterPolicy, AdvertisingParameters, Channels, Hci,
        OwnAddressType,
    },
    types::{Advertisement, AdvertisingInterval, AdvertisingType},
    BdAddr, BdAddrType,
};
use clap::Parser;
use openssl::rand::rand_bytes;
use serialport::FlowControl;
use serialport_hci::{
    vendor::none::{Event, Vendor},
    SerialController,
};
use std::{
    fmt::Debug,
    time::Duration,
};

use webauthn_authenticator_rs::{
    cable::share_cable_authenticator,
    error::WebauthnCError,
    transport::{AnyTransport, Transport},
    ui::Cli,
};

#[derive(Debug, clap::Parser)]
#[clap(about = "caBLE tunneler tool")]
pub struct CliParser {
    /// Serial port where Bluetooth HCI controller is connected to.
    #[clap(short, long)]
    pub serial_port: String,

    /// Baud rate for communication with Bluetooth HCI controller.
    #[clap(short, long, default_value = "1000000")]
    pub baud_rate: u32,

    /// Tunnel server ID to use. 0 = Google.
    #[clap(short, long, default_value = "0")]
    pub tunnel_server_id: u16,

    /// `FIDO:/` URL from the initiator (QR code)
    #[clap(short, long)]
    pub cable_url: String,
}

fn start_advert<E, H, Vendor, VE, VS, Event>(
    hci: &mut H,
    advert: Option<Advertisement>,
) -> Result<(), WebauthnCError>
where
    E: Debug,
    H: UartHci<E, Event, VE> + Hci<E, VS = VS>,
    VE: Debug,
    VS: Debug,
    Event: VendorEvent<Error = VE, Status = VS> + Debug,
    Vendor: bluetooth_hci::Vendor<Event = Event> + Debug,
{
    trace!("sending reset...");
    hci.reset().unwrap();
    let mut r: bluetooth_hci::host::uart::Packet<_> = hci.read().unwrap();
    trace!(?r);

    if advert.is_none() {
        return Ok(());
    }
    let advert = advert.unwrap();

    hci.le_set_advertise_enable(false).unwrap();
    r = hci.read().unwrap();
    trace!(?r);

    let mut service_data = [0; 38];
    let len = advert.copy_into_slice(&mut service_data);

    let p = AdvertisingParameters {
        advertising_interval: AdvertisingInterval::for_type(
            AdvertisingType::NonConnectableUndirected,
        )
        .with_range(Duration::from_millis(100), Duration::from_millis(500))
        .unwrap(),
        own_address_type: OwnAddressType::Random,
        peer_address: BdAddrType::Random(bluetooth_hci::BdAddr([0xc0; 6])),
        advertising_channel_map: Channels::all(),
        advertising_filter_policy: AdvertisingFilterPolicy::WhiteListConnectionAllowScan,
    };
    let mut addr = [0u8; 6];
    addr[5] = 0xc0;
    rand_bytes(&mut addr[..5])?;

    hci.le_set_random_address(BdAddr(addr)).unwrap();
    r = hci.read().unwrap();
    trace!(?r);

    hci.le_set_advertising_parameters(&p).unwrap();
    r = hci.read().unwrap();
    trace!(?r);

    hci.le_set_advertising_data(&service_data[..len]).unwrap();
    r = hci.read().unwrap();
    trace!(?r);

    hci.le_set_advertise_enable(true).unwrap();
    r = hci.read().unwrap();
    trace!(?r);

    Ok(())
}

#[tokio::main]
async fn main() {
    let _ = tracing_subscriber::fmt::try_init();
    let opt = CliParser::parse();

    let port = serialport::new(opt.serial_port, opt.baud_rate)
        .timeout(Duration::from_secs(2))
        .flow_control(FlowControl::None)
        .open()
        .unwrap();
    let mut hci: SerialController<bluetooth_hci::host::uart::CommandHeader, Vendor> =
        SerialController::new(port);

    let mut transport = AnyTransport::new().unwrap();
    let mut token = transport.tokens().unwrap().pop().unwrap();
    let ui = Cli {};

    share_cable_authenticator(
        &mut token,
        opt.cable_url.trim(),
        opt.tunnel_server_id,
        |advert| start_advert::<_, _, Vendor, _, _, Event>(&mut hci, advert),
        &ui,
    )
    .await
    .unwrap();
}
