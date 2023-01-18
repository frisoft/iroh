use anyhow::{bail, ensure, Result};
use bytes::BytesMut;
use postcard::experimental::max_size::MaxSize;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

/// Maximum message size is limited to 100MiB for now.
const MAX_MESSAGE_SIZE: usize = 1024 * 1024 * 100;

pub const VERSION: u64 = 1;

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone, MaxSize)]
pub struct Handshake {
    pub version: u64,
}

impl Default for Handshake {
    fn default() -> Self {
        Handshake { version: VERSION }
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone, MaxSize)]
pub struct Request {
    pub id: u64,
    /// blake3 hash
    pub name: [u8; 32],
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct Response<'a> {
    pub id: u64,
    #[serde(borrow)]
    pub data: Res<'a>,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub enum Res<'a> {
    NotFound,
    // If found, a stream of bao data is sent as next message.
    Found {
        /// The size of the coming data in bytes, raw content size.
        size: usize,
        outboard: &'a [u8],
    },
}

impl Res<'_> {
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        match self {
            Self::Found { outboard, .. } => outboard.len(),
            _ => 0,
        }
    }
}

/// Write the given data to the provider sink, with a unsigned varint length prefix.
pub async fn write_lp<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    ensure!(
        data.len() < MAX_MESSAGE_SIZE,
        "sending message is too large"
    );

    // send length prefix
    let mut buffer = [0u8; 10];
    let lp = unsigned_varint::encode::u64(data.len() as u64, &mut buffer);
    writer.write_all(lp).await?;

    // write message
    writer.write_all(data).await?;
    Ok(())
}

/// Read and deserialize into the given type from the provided source, based on the length prefix.
pub async fn read_lp<'a, R: AsyncRead + futures::io::AsyncRead + Unpin, T: Deserialize<'a>>(
    mut reader: R,
    buffer: &'a mut BytesMut,
) -> Result<Option<(T, usize)>> {
    // read length prefix
    let size = read_prefix(&mut reader, buffer).await?;

    while buffer.len() < size {
        debug!("reading message {} {}", buffer.len(), size);
        reader.read_buf(buffer).await?;
    }

    let response: T = postcard::from_bytes(&buffer[..size])?;
    debug!("read message of size {}", size);

    Ok(Some((response, size)))
}

/// Read and deserialize into the given type from the provided source, based on the length prefix.
pub async fn read_lp_data<R: AsyncRead + futures::io::AsyncRead + Unpin>(
    mut reader: R,
    buffer: &mut BytesMut,
) -> Result<Option<BytesMut>> {
    // read length prefix
    let size = read_prefix(&mut reader, buffer).await?;

    while buffer.len() < size {
        reader.read_buf(buffer).await?;
    }
    let response = buffer.split_to(size);
    Ok(Some(response))
}

async fn read_prefix<R: AsyncRead + futures::io::AsyncRead + Unpin>(
    mut reader: R,
    buffer: &mut BytesMut,
) -> Result<usize> {
    // read length prefix
    let size = loop {
        if let Ok((size, rest)) = unsigned_varint::decode::u64(&buffer[..]) {
            let size = usize::try_from(size)?;
            ensure!(size < MAX_MESSAGE_SIZE, "received message is too large");

            let _ = buffer.split_to(buffer.len() - rest.len());
            break size;
        }

        if reader.read_buf(buffer).await? == 0 {
            bail!("no more data available");
        }
    };

    Ok(size)
}