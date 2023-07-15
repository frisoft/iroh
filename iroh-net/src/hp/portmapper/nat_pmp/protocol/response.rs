use std::net::Ipv4Addr;

use super::{MapProtocol, Opcode, Version};

#[derive(Debug)]
pub enum Response {
    PublicAddress {
        epoch_time: u32,
        public_ip: Ipv4Addr,
    },
    PortMap {
        proto: MapProtocol,
        epoch_time: u32,
        private_port: u16,
        external_port: u16,
        lifetime_seconds: u32,
    },
}

// 3.5.  Result Codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ResultCode {
    Success = 0,
    // TODO(@divma): responses having this error have a different packet format. annoying
    UnsupportedVersion = 1,
    /// Functionality is suported but not allowerd: e.g. box supports mapping, but user has turned
    /// feature off.
    NotAuthorizedOrRefused = 2,
    /// Netfork failures, e.g. NAT box itself has not obtained a DHCP lease.
    NetworkFailure = 3,
    /// NAT box cannot create any more mappings at this time.
    OutOfResources = 4,
    UnsupportedOpcode = 5,
}

/// Errors that can occur when decoding a [`Response`] from a server.
// TODO(@divma): copy docs instead of refer?
#[derive(Debug, derive_more::Display, thiserror::Error)]
pub enum Error {
    /// Request is too short or is otherwise malformed.
    #[display("Response is malformed")]
    Malformed,
    /// The [`RESPONSE_INDICATOR`] is not present.
    #[display("Packet does not appear to be a response")]
    NotAResponse,
    /// See [`InvalidOpcode`].
    #[display("Invalid Opcode received")]
    InvalidOpcode,
    /// See [`InvalidVersion`].
    #[display("Invalid version received")]
    InvalidVersion,
    /// See [`InvalidResultCode`].
    #[display("Invalid result code received")]
    InvalidResultCode,
    UnsupportedVersion,
    NotAuthorizedOrRefused,
    NetworkFailure,
    OutOfResources,
    UnsupportedOpcode,
}

/// Minimum size of an encoded [`Response`] sent by a server to this client.
// NOTE: 1byte for the version +
//       1byte for the opcode +
//       2byte for the result code +
//       4bytes for the epoch time +
//       4bytes for the ip addr = response size for a public ip request
pub const MIN_RESP_SIZE: usize = 1 + 1 + 2 + 4 + 4;
/// Minimum size of an encoded [`Response`] sent by a server to this client.
// NOTE: 1byte for the version +
//       1byte for the opcode +
//       2byte for the result code +
//       4bytes for the epoch time +
//       2bytes for the private port +
//       2bytes for the public port +
//       4bytes for the lifetime = response size for a mapping request
pub const MAX_RESP_SIZE: usize = 1 + 1 + 2 + 4 + 2 + 2 + 4;

/// Indicator ORd into the [`Opcode`] to indicate a response packet.
pub const RESPONSE_INDICATOR: u8 = 1u8 << 7;

/// Error ocurring when attempting to identity the [`Opcode`] in a server response.
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidOpcode;

impl TryFrom<u8> for Opcode {
    type Error = InvalidOpcode;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Opcode::DetermineExternalAddress),
            1 => Ok(Opcode::MapUdp),
            2 => Ok(Opcode::MapTcp),
            _ => Err(InvalidOpcode),
        }
    }
}

/// Error ocurring when attempting to identify the [`Version`] in a server response.
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidVersion;

impl TryFrom<u8> for Version {
    type Error = InvalidVersion;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Version::NatPmp),
            _ => Err(InvalidVersion),
        }
    }
}

/// Error ocurring when attempting to decode the [`ResultCode`] in a server response.
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidResultCode;

impl TryFrom<u16> for ResultCode {
    type Error = InvalidResultCode;

    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(ResultCode::Success),
            1 => Ok(ResultCode::UnsupportedVersion),
            2 => Ok(ResultCode::NotAuthorizedOrRefused),
            3 => Ok(ResultCode::NetworkFailure),
            4 => Ok(ResultCode::OutOfResources),
            5 => Ok(ResultCode::UnsupportedOpcode),
            _ => Err(InvalidResultCode),
        }
    }
}

impl From<InvalidOpcode> for Error {
    fn from(_: InvalidOpcode) -> Self {
        Error::InvalidOpcode
    }
}

impl From<InvalidVersion> for Error {
    fn from(_: InvalidVersion) -> Self {
        Error::InvalidVersion
    }
}

impl From<InvalidResultCode> for Error {
    fn from(_: InvalidResultCode) -> Self {
        Error::InvalidResultCode
    }
}

impl Response {
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < MIN_RESP_SIZE || buf.len() > MAX_RESP_SIZE {
            return Err(Error::Malformed);
        }
        let _: Version = buf[0].try_into()?;
        let opcode = buf[1];
        if !(opcode & RESPONSE_INDICATOR == RESPONSE_INDICATOR) {
            return Err(Error::NotAResponse);
        }
        let opcode: Opcode = (opcode & !RESPONSE_INDICATOR).try_into()?;

        let result_bytes =
            u16::from_be_bytes(buf[2..4].try_into().expect("slice has the right len"));
        let result_code = result_bytes.try_into()?;

        match result_code {
            ResultCode::Success => Ok(()),
            ResultCode::UnsupportedVersion => Err(Error::UnsupportedVersion),
            ResultCode::NotAuthorizedOrRefused => Err(Error::NotAuthorizedOrRefused),
            ResultCode::NetworkFailure => Err(Error::NetworkFailure),
            ResultCode::OutOfResources => Err(Error::OutOfResources),
            ResultCode::UnsupportedOpcode => Err(Error::UnsupportedOpcode),
        }?;

        let response = match opcode {
            Opcode::DetermineExternalAddress => {
                let epoch_bytes = buf[4..8].try_into().expect("slice has the right len");
                let epoch_time = u32::from_be_bytes(epoch_bytes);
                let ip_bytes: [u8; 4] = buf[8..12].try_into().expect("slice has the right len");
                Response::PublicAddress {
                    epoch_time,
                    public_ip: ip_bytes.into(),
                }
            }
            other @ (Opcode::MapUdp | Opcode::MapTcp) => {
                let proto = if other == Opcode::MapUdp {
                    MapProtocol::UDP
                } else {
                    MapProtocol::TCP
                };

                let epoch_bytes = buf[4..8].try_into().expect("slice has the right len");
                let epoch_time = u32::from_be_bytes(epoch_bytes);

                let private_port_bytes = buf[8..10].try_into().expect("slice has the right len");
                let private_port = u16::from_be_bytes(private_port_bytes);

                let external_port_bytes = buf[10..12].try_into().expect("slice has the right len");
                let external_port = u16::from_be_bytes(external_port_bytes);

                let lifetime_bytes = buf[12..16].try_into().expect("slice has the right len");
                let lifetime_seconds = u32::from_be_bytes(lifetime_bytes);
                Response::PortMap {
                    proto,
                    epoch_time,
                    private_port,
                    external_port,
                    lifetime_seconds,
                }
            }
        };

        Ok(response)
    }
}
