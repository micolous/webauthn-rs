//! caBLE Bluetooth Low Energy scanner.
//!
//! An authenticator advertises its physical proximity to the platform and some
//! connection metadata by transmitting an encrypted service data payload.
//!
//! [Scanner] uses [btleplug] to watch for caBLE advertisements.
use btleplug::{
    api::{bleuuid::uuid_from_u16, Central, CentralEvent, Manager as _, ScanFilter},
    platform::Manager,
};
use futures::StreamExt;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::error::WebauthnCError;

/// Service Data UUID for caBLE assigned to Google (0xfde2).
///
/// This is transmitted by iOS 16 devices, and older versions of Chromium.
///
/// Prefer transmitting [FIDO_CABLE_SERVICE_U16].
///
/// Reference: [Bluetooth Assigned Numbers][], Section 3.11 (Member Services)
///
/// [Bluetooth Assigned Numbers]: https://www.bluetooth.com/specifications/assigned-numbers/
const GOOGLE_CABLE_SERVICE: Uuid = uuid_from_u16(0xfde2);

/// 16-bit Service Data UUID for caBLE assigned to FIDO2 (0xfff9).
///
/// This is used by newer versions of Chromium, and detectable by all (even
/// iOS 16).
///
/// Reference: [Bluetooth Assigned Numbers][], Section 3.10 (SDO Services)
///
/// [Bluetooth Assigned Numbers]: https://www.bluetooth.com/specifications/assigned-numbers/
pub(super) const FIDO_CABLE_SERVICE_U16: u16 = 0xfff9;

/// Service Data UUID for caBLE assigned to FIDO2 (0xfff9).
///
/// Reference: [Bluetooth Assigned Numbers][], Section 3.10 (SDO Services)
///
/// [Bluetooth Assigned Numbers]: https://www.bluetooth.com/specifications/assigned-numbers/
const FIDO_CABLE_SERVICE: Uuid = uuid_from_u16(FIDO_CABLE_SERVICE_U16);

fn get_scan_filter() -> ScanFilter {
    ScanFilter {
        services: vec![FIDO_CABLE_SERVICE, GOOGLE_CABLE_SERVICE],
    }
}

/// Bluetooth Low Energy advertising trait.
///
/// A caBLE authenticator needs to be able to send arbitrary service data
/// advertisements to be discoverable by the initiator (platform).
pub trait Advertiser {
    /// Start sending service data advertisements.
    ///
    /// Arguments:
    /// * `service_uuid`: a 16-bit service UUID to send advertising data for.
    /// * `payload`: the advertisement payload.
    ///
    /// Advertisements are of the type "Service Data - 16-bit UUID" (0x16).
    ///
    /// This should continue until [stop_advertising] is called.
    fn start_advertising(
        &mut self,
        service_uuid: u16,
        payload: &[u8],
    ) -> Result<(), WebauthnCError>;

    /// Stop sending service data advertisements.
    fn stop_advertising(&mut self) -> Result<(), WebauthnCError>;
}

/// caBLE Bluetooth Low Energy service data scanner.
pub struct Scanner {
    manager: Manager,
}

impl Scanner {
    /// Creates a new instance of the Bluetooth Low Energy scanner.
    pub async fn new() -> Result<Self, WebauthnCError> {
        Ok(Scanner {
            manager: Manager::new().await?,
        })
    }

    /// Starts scanning for caBLE BTLE advertisements in the background.
    ///
    /// Returned values are the advertisement payload.
    pub async fn scan(&self) -> Result<mpsc::Receiver<Vec<u8>>, WebauthnCError> {
        let (tx, rx) = mpsc::channel(100);

        // https://github.com/deviceplug/btleplug/blob/master/examples/event_driven_discovery.rs
        let adapters = self.manager.adapters().await?;
        let adapter = adapters
            .into_iter()
            .next()
            .ok_or(WebauthnCError::NoBluetoothAdapter)?;
        let mut events = adapter.events().await?;

        adapter.start_scan(get_scan_filter()).await?;

        tokio::spawn(async move {
            while let Some(event) = events.next().await {
                if let CentralEvent::ServiceDataAdvertisement {
                    id: _,
                    mut service_data,
                } = event
                {
                    // Service data advertisement events always use the 128-bit
                    // form, even though they're transmitted in 16-bit form.
                    if let Some(d) = service_data.remove(&FIDO_CABLE_SERVICE) {
                        if let Err(_) = tx.send(d).await {
                            return;
                        }
                    }

                    if let Some(d) = service_data.remove(&GOOGLE_CABLE_SERVICE) {
                        if let Err(_) = tx.send(d).await {
                            return;
                        }
                    }
                }
            }

            adapter.stop_scan().await.ok();
        });

        Ok(rx)
    }
}
