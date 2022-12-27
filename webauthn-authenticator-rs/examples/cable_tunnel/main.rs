//! `cable_tunnel` shares a [Token] over a caBLE connection.
#[macro_use]
extern crate tracing;

use bluetooth_hci::{
    host::{
        uart::{CommandHeader, Hci as UartHci, Packet},
        AdvertisingFilterPolicy, AdvertisingParameters, Channels, Hci, OwnAddressType,
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
use std::{fmt::Debug, time::Duration};

use webauthn_authenticator_rs::{
    cable::{share_cable_authenticator, Advertiser},
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

struct SerialHciAdvertiser {
    hci: SerialController<CommandHeader, Vendor>,
}

impl SerialHciAdvertiser {
    fn new(serial_port: &str, baud_rate: u32) -> Self {
        let port = serialport::new(serial_port, baud_rate)
            .timeout(Duration::from_secs(2))
            .flow_control(FlowControl::None)
            .open()
            .unwrap();
        Self {
            hci: SerialController::new(port),
        }
    }

    fn read(&mut self) -> Packet<Event> {
        let r = self.hci.read().unwrap();
        trace!("<<< {:?}", r);
        r
    }
}

impl Advertiser for SerialHciAdvertiser {
    fn stop_advertising(&mut self) -> Result<(), WebauthnCError> {
        trace!("sending reset...");
        self.hci.reset().unwrap();
        let _ = self.read();

        self.hci.le_set_advertise_enable(false).unwrap();
        let _ = self.read();
        Ok(())
    }

    fn start_advertising(
        &mut self,
        service_uuid: u16,
        payload: &[u8],
    ) -> Result<(), WebauthnCError> {
        self.stop_advertising()?;
        let advert = Advertisement::ServiceData16BitUuid(service_uuid, payload);
        let mut service_data = [0; 31];
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

        self.hci.le_set_random_address(BdAddr(addr)).unwrap();
        let _ = self.read();

        self.hci.le_set_advertising_parameters(&p).unwrap();
        let _ = self.read();

        self.hci
            .le_set_advertising_data(&service_data[..len])
            .unwrap();
        let _ = self.read();

        self.hci.le_set_advertise_enable(true).unwrap();
        let _ = self.read();
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    let _ = tracing_subscriber::fmt::try_init();
    let opt = CliParser::parse();
    let mut advertiser = SerialHciAdvertiser::new(&opt.serial_port, opt.baud_rate);

    let mut transport = AnyTransport::new().unwrap();
    let mut token = transport.tokens().unwrap().pop().unwrap();
    let ui = Cli {};

    share_cable_authenticator(
        &mut token,
        opt.cable_url.trim(),
        opt.tunnel_server_id,
        &mut advertiser,
        &ui,
    )
    .await
    .unwrap();
}
