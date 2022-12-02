// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// S&PDX-License-Identifier: Apache-2.0
#![allow(dead_code)]
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{EnclaveBuildError, Result};

/// Root folder for the cache.
pub const CACHE_ROOT_FOLDER: &str = "XDG_DATA_HOME";
/// Path to the blobs folder
pub const CACHE_BLOBS_FOLDER: &str = "blobs/sha256/";
/// Name of the cache index file which stores the (image URI <-> image hash) mappings.
pub const CACHE_INDEX_FILE_NAME: &str = "index.json";
/// The name of the OCI layout file from the cache.
pub const CACHE_OCI_LAYOUT_FILE: &str = "oci-layout";

/// Constants used for complying with the OCI cache structure
pub const DEFAULT_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
pub const REF_ANNOTATION: &str = "org.opencontainers.image.ref.name";
pub const OCI_LAYOUT: (&str, &str) = ("imageLayoutVersion", "1.0.0");

/// Manifest entry in index file
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestEntry {
    #[serde(rename = "mediaType")]
    media_type: String,
    #[serde(rename = "size")]
    size: usize,
    #[serde(rename = "digest")]
    digest: String,
    #[serde(rename = "annotations")]
    annotations: HashMap<String, String>,
}

/// Cache index file structure
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheIndex {
    #[serde(rename = "schemaVersion", default = "schema_default")]
    schema_version: u32,
    #[serde(rename = "manifests", default = "Vec::new")]
    manifests: Vec<ManifestEntry>,
}

impl Default for CacheIndex {
    fn default() -> Self {
        CacheIndex {
            schema_version: 2,
            manifests: Vec::new(),
        }
    }
}

fn schema_default() -> u32 {
    2
}

/// Struct which provides operations with the local cache.
///
/// The index file is located in the cache root folder and keeps track of images stored in cache.
///
/// The cache structure is:
///
/// {CACHE_ROOT_PATH}/index.json\
/// {CACHE_ROOT_PATH}/blobs/sha256\
/// {CACHE_ROOT_PATH}/blobs/sha256/hash_of_blob_1\
/// {CACHE_ROOT_PATH}/blobs/sha256/hash_of_blob_2\
/// etc.
///
/// A blob can be:
///
/// {IMAGE_FOLDER_PATH}/blobs/sha256/manifest_hash - the image manifest, stored as a JSON String.\
/// {IMAGE_FOLDER_PATH}/blobs/sha256/config_hash - the image configuration, stored as a JSON String.\
/// {IMAGE_FOLDER_PATH}/blobs/sha256/layer_hash - one of the image layers, each in a separate gzip compressed tar file.
#[derive(Clone)]
pub struct CacheManager {
    /// The root folder of the cache
    root_path: PathBuf,

    /// A map storing the cached images, with the map entry format being (image_reference, image_hash)
    cached_images: HashMap<String, String>,
}

impl CacheManager {
    /// Creates a new CacheManager instance and returns it. As argument, a path to the root folder
    /// of the cache should be provided.
    ///
    /// Apart from that, the function also creates (if not already created) all folders from the path
    /// specified as argument.
    ///
    /// If an index file exists at the path, it loads the file's contents into the 'cached_images'
    /// field. If not, a new empty index file is created at that path.
    pub fn new(root_path: &Path) -> Result<Self> {
        // Create all missing folders, if not already created
        fs::create_dir_all(&root_path).map_err(EnclaveBuildError::CacheInitError)?;

        // Try to open the index file and read the contents.
        // If the file is missing, create it.
        OpenOptions::new()
            .write(true)
            .read(true)
            .create(true)
            .open(root_path.to_path_buf().join(CACHE_INDEX_FILE_NAME))
            .map_err(EnclaveBuildError::CacheInitError)?;

        // Load the index content and match image names to config hashes.
        // If the index file is empty, return an empty hashmap.
        let cached_images = match Self::fetch_index(&root_path) {
            Ok(index) => index
                .manifests
                .iter()
                // Extract <image_name, manifest_digest> from index
                .filter_map(|entry| {
                    entry
                        .annotations
                        .get(REF_ANNOTATION)
                        .map(|img_ref| (img_ref.to_string(), entry.digest.to_string()))
                })
                // Read manifest files and map digest to JSON content
                .filter_map(|(img_ref, manifest_hash)| {
                    Self::fetch_manifest(&root_path, &manifest_hash)
                        .ok()
                        .map(|manifest| (img_ref, manifest))
                })
                // Extract config digests from manifests resulting in a <image_name, config_digest> map
                .filter_map(|(img_ref, manifest)| {
                    Self::fetch_config_digest(manifest)
                        .ok()
                        .map(|config_digest| (img_ref, config_digest))
                })
                .collect::<HashMap<String, String>>(),
            Err(_) => HashMap::new(),
        };

        Ok(Self {
            root_path: root_path.to_path_buf(),
            cached_images,
        })
    }

    fn fetch_index(root_path: &Path) -> Result<CacheIndex> {
        Ok(match File::options()
            .read(true)
            .open(root_path.join(CACHE_INDEX_FILE_NAME))
        {
            Ok(file) => serde_json::from_reader(file).map_err(EnclaveBuildError::SerdeError),
            Err(err) => Err(EnclaveBuildError::CacheMissError(format!(
                "Cache index file missing: {:?}",
                err
            ))),
        }?)
    }

    /// Returns manifest from blob, given the digest
    fn fetch_manifest(root_path: &Path, manifest_hash: &str) -> Result<Value> {
        let digest = manifest_hash
            .strip_prefix("sha256:")
            .ok_or(EnclaveBuildError::ManifestError)?;
        let target_path = root_path.join(CACHE_BLOBS_FOLDER);

        // Read the JSON string from the cached manifest file
        let manifest_path = target_path.join(digest);
        let file = File::open(&manifest_path).map_err(|_| EnclaveBuildError::ManifestError)?;
        let manifest_json: Value =
            serde_json::from_reader(file).map_err(EnclaveBuildError::SerdeError)?;

        Ok(manifest_json)
    }

    /// Extract config digest from manifest
    fn fetch_config_digest(manifest_json: Value) -> Result<String> {
        Ok(manifest_json
            .get("config")
            .ok_or_else(|| {
                EnclaveBuildError::CacheMissError(
                    "'config' field missing from image manifest.".to_string(),
                )
            })?
            .get("digest")
            .ok_or_else(|| {
                EnclaveBuildError::CacheMissError(
                    "'digest' field missing from image manifest.".to_string(),
                )
            })?
            .as_str()
            .ok_or_else(|| {
                EnclaveBuildError::CacheMissError(
                    "Failed to get config digest from image manifest.".to_string(),
                )
            })?
            .strip_prefix("sha256:")
            .ok_or_else(|| {
                EnclaveBuildError::CacheMissError(
                    "Failed to get config digest from image manifest.".to_string(),
                )
            })?
            .to_string())
    }
}

#[cfg(test)]
pub mod tests {
    use serde_json::Value;

    use crate::{cache::CacheManager, image};

    #[test]
    fn test_fetch_config_digest() {
        let manifest: Value = serde_json::from_str(image::tests::TEST_MANIFEST).unwrap();
        let config_digest = CacheManager::fetch_config_digest(manifest).unwrap();

        assert_eq!(image::tests::TEST_IMAGE_HASH.to_string(), config_digest);
    }
}
