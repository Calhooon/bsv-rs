//! The `storage` module's doors (`send_rule`'s header has the rule).

use super::{send, Values};
use crate::storage::{StorageDownloader, StorageUploader};

// src/storage/downloader.rs
fn downloader<V: Values>(v: &V) {
    let downloader = v.any::<&StorageDownloader>();
    send(downloader.resolve(v.any()));
    send(downloader.download(v.any()));
}

// src/storage/uploader.rs
fn uploader<V: Values>(v: &V) {
    let uploader = v.any::<&StorageUploader>();
    send(uploader.publish_file(v.any(), v.any()));
    send(uploader.find_file(v.any()));
    send(uploader.list_uploads());
    send(uploader.renew_file(v.any(), v.any()));
}
