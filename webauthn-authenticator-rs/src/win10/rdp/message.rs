use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use uuid::Uuid;
use webauthn_rs_proto::AuthenticatorTransport;

/// <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpewa/3012640f-f57a-45a4-aa87-e2afbad42a68>
#[derive(Default, Deserialize, Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChannelRequest {
    pub command: u8,
    pub flags: u32,
    #[serde(rename = "timeout")]
    pub timeout_ms: u32,
    // #[serde(with = "UuidDef")]
    pub transaction_id: Uuid,
    #[serde(rename = "webAuthNPara", skip_serializing_if = "Option::is_none")]
    pub webauthn_para: Option<WebauthnPara>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<ByteBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Only supported on Windows 11 23H2
    pub filter_hybrid_transport: Option<bool>,
}

/// <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpewa/508c6afe-166c-4b4b-8a1f-8604d0d95c10>
#[derive(Default, Deserialize, Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WebauthnPara {
    pub wnd: isize,
    pub attachment: u32,
    pub require_resident: bool,
    pub prefer_resident: bool,
    pub user_verification: u32,
    pub attestation_preference: u32,
    pub enterprise_attestation: u32,
    // #[serde(with = "UuidDef")]
    pub cancellation_id: Uuid,
}

/// <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpewa/ef4bafb6-0801-4c17-9238-99e3efdc0798>
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ChannelResponse {
    pub device_info: Option<DeviceInfo>,
    pub status: u8,
    pub response: Option<ByteBuf>,
    pub device_info_list: Option<Vec<DeviceInfo>>,
}

/// <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpewa/ef4bafb6-0801-4c17-9238-99e3efdc0798>
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    max_msg_size: Option<u32>,
    max_serialized_large_blob_array: Option<u32>,
    provider_type: String,
    provider_name: String,
    device_path: Option<String>,
    manufacturer: Option<String>,
    product: Option<String>,
    #[serde(rename = "aaGuid")]
    aaguid: Option<Uuid>,
    resident_key: Option<bool>,
    uv_status: Option<u8>,
    uv_retries: Option<u8>,
    u2f_protocol: Option<bool>,
}

impl DeviceInfo {
    pub fn get_transport(&self) -> Option<AuthenticatorTransport> {
        let provider = self.provider_type.to_ascii_lowercase();
        match provider.as_str() {
            "hid" => Some(AuthenticatorTransport::Usb),
            "nfc" => Some(AuthenticatorTransport::Nfc),
            "ble" => Some(AuthenticatorTransport::Ble),
            "platform" => Some(AuthenticatorTransport::Internal),
            "test" => Some(AuthenticatorTransport::Test),
            _ => None,
        }
    }
}

pub const CMD_API_VERSION: ChannelRequest = ChannelRequest {
    command: 8,
    request: None,
    flags: 0,
    timeout_ms: 0,
    transaction_id: Uuid::nil(),
    webauthn_para: None,
    filter_hybrid_transport: None,
};

pub const CMD_IUVPA: ChannelRequest = ChannelRequest {
    command: 6,
    request: None,
    flags: 0,
    timeout_ms: 0,
    transaction_id: Uuid::nil(),
    webauthn_para: None,
    filter_hybrid_transport: None,
};

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn get_version() {
        // The canonical example had the wrong command code. It lists 5, it's actually 8.
        let version_command_bytes: [u8; 57] = [
            0xa4, 0x67, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, /* 0x5 */ 0x8, 0x65, 0x66,
            0x6c, 0x61, 0x67, 0x73, 0x0, 0x67, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x0, 0x6d,
            0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x50,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ];

        let s = serde_cbor_2::to_vec(&CMD_API_VERSION).unwrap();
        assert_eq!(&version_command_bytes, s.as_slice());

        let o: ChannelRequest = serde_cbor_2::from_slice(&version_command_bytes).unwrap();
        assert_eq!(o, CMD_API_VERSION);
    }
}
