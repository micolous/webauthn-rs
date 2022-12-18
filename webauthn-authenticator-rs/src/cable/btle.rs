//! caBLE Bluetooth Low Energy scanner.
//! 
//! An authenticator advertises its physical proximity to the platform and some
//! connection metadata by transmitting an encrypted service data payload.
//! 
//! [Scanner] uses [btleplug] to watch for caBLE advertisements.
use btleplug::{api::{Central, CentralEvent, ScanFilter, Manager as _}, platform::Manager};
use futures::StreamExt;
use tokio::sync::mpsc;
use uuid::{uuid, Uuid};

use crate::error::WebauthnCError;

const GOOGLE_CABLE_SERVICE: Uuid = uuid!("0000fde2-0000-1000-8000-00805f9b34fb");
const FIDO_CABLE_SERVICE: Uuid = uuid!("0000fff9-0000-1000-8000-00805f9b34fb");

fn get_scan_filter() -> ScanFilter {
    ScanFilter {
        services: vec![
            FIDO_CABLE_SERVICE,
            GOOGLE_CABLE_SERVICE,
        ],
    }
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
        let adapter = adapters.into_iter().next().ok_or(WebauthnCError::NoBluetoothAdapter)?;
        let mut events = adapter.events().await?;
        
        adapter.start_scan(get_scan_filter()).await?;

        tokio::spawn(async move {
            while let Some(event) = events.next().await {
                if let CentralEvent::ServiceDataAdvertisement { id: _, mut service_data } = event {
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
