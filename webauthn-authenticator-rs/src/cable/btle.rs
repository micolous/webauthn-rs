use std::pin::Pin;

use btleplug::{api::{Central, CentralEvent, ScanFilter, Manager as _}, platform::Manager, Error};
use futures::StreamExt;
use tokio::sync::mpsc;
use uuid::{uuid, Uuid};

use crate::error::WebauthnCError;

const FIDO_CABLE_SERVICE: Uuid = uuid!("0000fff9-0000-1000-8000-00805f9b34fb");

fn get_scan_filter() -> ScanFilter {
    ScanFilter {
        services: vec![FIDO_CABLE_SERVICE],
    }
}

pub struct Scanner {
    manager: Manager,
}

impl Scanner {
    pub async fn new() -> Result<Self, WebauthnCError> {
        Ok(Scanner {
            manager: Manager::new().await?,
        })
    }
    pub async fn scan(&self) -> Result<mpsc::Receiver<Vec<u8>>, WebauthnCError> {
        let (tx, rx) = mpsc::channel(100);

        // https://github.com/deviceplug/btleplug/blob/master/examples/event_driven_discovery.rs
        let adapters = self.manager.adapters().await?;
        // TODO: handle error
        let adapter = adapters.into_iter().next().unwrap();
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
                }
            }

        });

        Ok(rx)
    }
}
