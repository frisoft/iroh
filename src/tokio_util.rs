//! Utilities for working with tokio io
use std::{
    io::{self},
    pin::Pin,
    task::Poll,
};

use bao_tree::io::fsm::{
    AsyncSliceReaderFsm, AsyncSliceWriter, AsyncSliceWriterFsm, Either, FileAdapterFsm,
};
use bytes::Bytes;
use futures::{future::LocalBoxFuture, Future, FutureExt};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};

/// A reader that tracks the number of bytes read
#[derive(Debug)]
pub(crate) struct TrackingReader<R> {
    inner: R,
    read: u64,
}

impl<R> TrackingReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner, read: 0 }
    }

    #[allow(dead_code)]
    pub fn bytes_read(&self) -> u64 {
        self.read
    }

    pub fn into_parts(self) -> (R, u64) {
        (self.inner, self.read)
    }
}

impl<R> AsyncRead for TrackingReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let filled0 = buf.filled().len();
        let res = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = res {
            let size = buf.filled().len().saturating_sub(filled0);
            this.read = this.read.saturating_add(size as u64);
        }
        res
    }
}

/// Converts an AsyncWrite into an AsyncSliceWriter by just ignoring the offsets
#[derive(Debug)]
pub struct ConcatenateSliceWriter<W>(W);

impl<W> ConcatenateSliceWriter<W> {
    /// Create a new `ConcatenateSliceWriter` from an inner writer
    pub fn new(inner: W) -> Self {
        Self(inner)
    }

    /// Return the inner writer
    pub fn into_inner(self) -> W {
        self.0
    }
}

impl<W: AsyncWrite + Unpin + 'static> AsyncSliceWriter for ConcatenateSliceWriter<W> {
    type WriteAtFuture<'a> = LocalBoxFuture<'a, io::Result<()>>;
    fn write_at(&mut self, _offset: u64, data: Bytes) -> Self::WriteAtFuture<'_> {
        async move { self.0.write_all(&data).await }.boxed_local()
    }

    type WriteArrayAtFuture<'a> = LocalBoxFuture<'a, io::Result<()>>;
    fn write_array_at<const N: usize>(
        &mut self,
        _offset: u64,
        bytes: [u8; N],
    ) -> Self::WriteArrayAtFuture<'_> {
        async move { self.0.write_all(&bytes).await }.boxed_local()
    }

    type SyncFuture<'a> = LocalBoxFuture<'a, io::Result<()>>;
    fn sync(&mut self) -> Self::SyncFuture<'_> {
        self.0.flush().boxed_local()
    }

    type SetLenFuture<'a> = futures::future::Ready<io::Result<()>>;

    fn set_len(&mut self, _len: u64) -> Self::SetLenFuture<'_> {
        futures::future::ready(io::Result::Ok(()))
    }
}

impl<W: AsyncWrite + Unpin + 'static> AsyncSliceWriterFsm for ConcatenateSliceWriter<W> {
    type WriteAtFuture = LocalBoxFuture<'static, (Self, io::Result<()>)>;
    fn write_at(mut self, _offset: u64, data: Bytes) -> Self::WriteAtFuture {
        async move {
            let res = self.0.write_all(&data).await;
            (self, res)
        }
        .boxed_local()
    }

    type WriteArrayAtFuture = LocalBoxFuture<'static, (Self, io::Result<()>)>;
    fn write_array_at<const N: usize>(
        mut self,
        _offset: u64,
        bytes: [u8; N],
    ) -> Self::WriteArrayAtFuture {
        async move {
            let res = self.0.write_all(&bytes).await;
            (self, res)
        }
        .boxed_local()
    }

    type SyncFuture = LocalBoxFuture<'static, (Self, io::Result<()>)>;
    fn sync(mut self) -> Self::SyncFuture {
        async move {
            let res = self.0.flush().await;
            (self, res)
        }
        .boxed_local()
    }

    type SetLenFuture = futures::future::Ready<(Self, io::Result<()>)>;
    fn set_len(self, _len: u64) -> Self::SetLenFuture {
        // set_len is a noop
        futures::future::ready((self, io::Result::Ok(())))
    }
}

/// A slice writer that adds a synchronous progress callback
#[derive(Debug)]
pub struct ProgressSliceWriter<W>(W, mpsc::Sender<(u64, usize)>);

impl<W> ProgressSliceWriter<W> {
    /// Create a new `ProgressSliceWriter` from an inner writer and a progress callback
    pub fn new(inner: W, on_write: mpsc::Sender<(u64, usize)>) -> Self {
        Self(inner, on_write)
    }

    /// Return the inner writer
    pub fn into_inner(self) -> W {
        self.0
    }
}

impl<W: AsyncSliceWriterFsm + 'static> AsyncSliceWriterFsm for ProgressSliceWriter<W> {
    type WriteAtFuture = LocalBoxFuture<'static, (Self, io::Result<()>)>;
    fn write_at(self, offset: u64, data: Bytes) -> Self::WriteAtFuture {
        // use try_send so we don't block if updating the progress bar is slow
        self.1.try_send((offset, Bytes::len(&data))).ok();
        async move {
            let (this, res) = self.0.write_at(offset, data).await;
            (Self(this, self.1), res)
        }
        .boxed_local()
    }

    type WriteArrayAtFuture = LocalBoxFuture<'static, (Self, io::Result<()>)>;
    fn write_array_at<const N: usize>(
        self,
        offset: u64,
        bytes: [u8; N],
    ) -> Self::WriteArrayAtFuture {
        // use try_send so we don't block if updating the progress bar is slow
        self.1.try_send((offset, bytes.len())).ok();
        async move {
            let (this, res) = self.0.write_array_at(offset, bytes).await;
            (Self(this, self.1), res)
        }
        .boxed_local()
    }

    type SyncFuture = LocalBoxFuture<'static, (Self, io::Result<()>)>;
    fn sync(self) -> Self::SyncFuture {
        async move {
            let (this, res) = self.0.sync().await;
            (Self(this, self.1), res)
        }
        .boxed_local()
    }

    type SetLenFuture = LocalBoxFuture<'static, (Self, io::Result<()>)>;
    fn set_len(self, len: u64) -> Self::SyncFuture {
        async move {
            let (this, res) = self.0.set_len(len).await;
            (Self(this, self.1), res)
        }
        .boxed_local()
    }
}

impl<W: AsyncSliceWriter + 'static> AsyncSliceWriter for ProgressSliceWriter<W> {
    type WriteAtFuture<'a> = W::WriteAtFuture<'a>;
    fn write_at(&mut self, offset: u64, data: Bytes) -> Self::WriteAtFuture<'_> {
        // use try_send so we don't block if updating the progress bar is slow
        self.1.try_send((offset, Bytes::len(&data))).ok();
        self.0.write_at(offset, data)
    }

    type WriteArrayAtFuture<'a> = W::WriteArrayAtFuture<'a>;
    fn write_array_at<const N: usize>(
        &mut self,
        offset: u64,
        bytes: [u8; N],
    ) -> Self::WriteArrayAtFuture<'_> {
        // use try_send so we don't block if updating the progress bar is slow
        self.1.try_send((offset, bytes.len())).ok();
        self.0.write_array_at(offset, bytes)
    }

    type SyncFuture<'a> = W::SyncFuture<'a>;
    fn sync(&mut self) -> Self::SyncFuture<'_> {
        self.0.sync()
    }

    type SetLenFuture<'a> = W::SetLenFuture<'a>;
    fn set_len(&mut self, size: u64) -> Self::SetLenFuture<'_> {
        self.0.set_len(size)
    }
}

/// A writer that tracks the number of bytes written
#[derive(Debug)]
pub(crate) struct TrackingWriter<W> {
    inner: W,
    written: u64,
}

impl<W> TrackingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner, written: 0 }
    }

    #[allow(dead_code)]
    pub fn bytes_written(&self) -> u64 {
        self.written
    }

    pub fn into_parts(self) -> (W, u64) {
        (self.inner, self.written)
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for TrackingWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let res = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(size)) = res {
            this.written = this.written.saturating_add(size as u64);
        }
        res
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A writer that tries to send the total number of bytes written after each write
///
/// It sends the total number instead of just an increment so the update is self-contained
#[derive(Debug)]
pub struct ProgressWriter<W> {
    inner: TrackingWriter<W>,
    sender: mpsc::Sender<u64>,
}

impl<W> ProgressWriter<W> {
    /// Create a new `ProgressWriter` from an inner writer
    pub fn new(inner: W) -> (Self, mpsc::Receiver<u64>) {
        let (sender, receiver) = mpsc::channel(1);
        (
            Self {
                inner: TrackingWriter::new(inner),
                sender,
            },
            receiver,
        )
    }

    /// Return the inner writer
    pub fn into_inner(self) -> W {
        self.inner.into_parts().0
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for ProgressWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let res = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(_)) = res {
            this.sender.try_send(this.inner.bytes_written()).ok();
        }
        res
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub(crate) async fn read_as_bytes(reader: &mut Either<Bytes, FileAdapterFsm>) -> io::Result<Bytes> {
    match reader {
        Either::Left(bytes) => Ok(bytes.clone()),
        Either::Right(file) => {
            let t: FileAdapterFsm = file.clone();
            let (t, len) = t.len().await;
            let len = len?;
            let (_t, res) = t.read_at(0, len as usize).await;
            res
        }
    }
}

/// A join handle that owns the task it is running, and aborts it when dropped.
#[derive(Debug)]
pub(crate) struct AbortingJoinHandle<T>(tokio::task::JoinHandle<T>);

impl<T> From<tokio::task::JoinHandle<T>> for AbortingJoinHandle<T> {
    fn from(handle: tokio::task::JoinHandle<T>) -> Self {
        Self(handle)
    }
}

impl<T> Future for AbortingJoinHandle<T> {
    type Output = std::result::Result<T, tokio::task::JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        self.0.poll_unpin(cx)
    }
}

impl<T> Drop for AbortingJoinHandle<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
