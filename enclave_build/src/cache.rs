// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// S&PDX-License-Identifier: Apache-2.0
#![allow(dead_code)]
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{Error, ErrorKind, Read, Write},
    path::{Path, PathBuf},
};

use oci_distribution::client::ImageData;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest;

use crate::{
    image::{self, ImageDetails},
    EnclaveBuildError, Result,
};

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

    /// Stores the image data provided as argument in the cache at the folder pointed
    /// by the 'root_path' field.
    pub fn store_image_data(&mut self, image_name: &str, image_data: &ImageData) -> Result<()> {
        // Create the folder where the image data will be stored. Each image blob will be stored in
        // a file named by the SHA256 digest of the content.
        let blobs_path = self.root_path.join(CACHE_BLOBS_FOLDER);
        fs::create_dir_all(&blobs_path).map_err(EnclaveBuildError::CacheStoreError)?;

        for layer in &image_data.layers {
            // Each layer file will be named after the layer's digest hash
            let layer_file_path =
                blobs_path.join(format!("{:x}", sha2::Sha256::digest(&layer.data)));
            File::create(&layer_file_path)
                .map_err(EnclaveBuildError::CacheStoreError)?
                .write_all(&layer.data)
                .map_err(EnclaveBuildError::CacheStoreError)?;
        }

        // Store the manifest
        let manifest = image_data
            .manifest
            .as_ref()
            .ok_or_else(|| EnclaveBuildError::ManifestError)?;
        let manifest_bytes = serde_json::to_vec(manifest).map_err(EnclaveBuildError::SerdeError)?;

        File::create(&blobs_path.join(format!("{:x}", sha2::Sha256::digest(&manifest_bytes))))
            .map_err(EnclaveBuildError::CacheStoreError)?
            .write_all(&manifest_bytes)
            .map_err(EnclaveBuildError::CacheStoreError)?;

        // Store the config and validate UTF8 bytes
        let config_json = String::from_utf8(image_data.config.data.clone()).map_err(|_| {
            EnclaveBuildError::CacheStoreError(Error::new(
                ErrorKind::InvalidData,
                "Config data invalid",
            ))
        })?;
        let config_digest = format!("{:x}", sha2::Sha256::digest(&config_json.as_bytes()));

        File::create(&blobs_path.join(&config_digest))
            .map_err(EnclaveBuildError::CacheStoreError)?
            .write_all(config_json.as_bytes())
            .map_err(EnclaveBuildError::CacheStoreError)?;

        // If index file present, read and append new image entry
        let index_json: CacheIndex = match File::options().read(true).open(CACHE_INDEX_FILE_NAME) {
            Ok(file) => serde_json::from_reader(file).map_err(EnclaveBuildError::SerdeError)?,
            Err(_) => CacheIndex::default(),
        };
        let mut index_content = index_json;
        let image_ref =
            Self::normalize_reference(&image::build_image_reference(&image_name)?.whole());

        // Create manifest entry in the index file
        let new_manifest = ManifestEntry {
            media_type: manifest
                .media_type
                .as_ref()
                .unwrap_or(&DEFAULT_MEDIA_TYPE.to_string())
                .to_string(),
            size: manifest_bytes.len(),
            digest: format!("sha256:{:x}", sha2::Sha256::digest(&manifest_bytes)),
            annotations: HashMap::from([(REF_ANNOTATION.to_string(), image_ref.clone())]),
        };

        // If all image data was successfully stored, add the image to the index file
        index_content.manifests.push(new_manifest);
        let index_file = File::options()
            .create(true)
            .write(true)
            .truncate(true)
            .open(self.root_path.join(CACHE_INDEX_FILE_NAME))
            .map_err(EnclaveBuildError::CacheStoreError)?;

        // Write index file content
        serde_json::to_writer(index_file, &index_content).map_err(EnclaveBuildError::SerdeError)?;

        // Write oci_layout file from template constant
        let layout_content = json!(HashMap::from([OCI_LAYOUT]));

        let layout_file = File::options()
            .create(true)
            .write(true)
            .open(self.root_path.join(CACHE_OCI_LAYOUT_FILE))
            .map_err(EnclaveBuildError::CacheStoreError)?;

        serde_json::to_writer(layout_file, &layout_content)
            .map_err(EnclaveBuildError::SerdeError)?;

        // Save image entry in the `CacheManager` map
        self.cached_images.insert(image_ref, config_digest);

        Ok(())
    }

    /// Determines if an image is stored correctly in the cache represented by the current CacheManager object.
    pub fn check_cached_image(&self, image_name: &str) -> Result<()> {
        // Check that the index.json file exists
        let index: CacheIndex = Self::fetch_index(&self.root_path)?;

        // The image is theoretically cached, but check the manifest, config and layers to validate
        // that the image data is stored correctly

        // First validate the manifest
        // Since the struct pulled by the oci_distribution API does not contain the manifest digest,
        // and another HTTP request should be made to get the digest, just check that the manifest file
        // exists and has the right structure for the next validations
        let manifest_json = self
            .fetch_manifest_from_index(&image_name, index)
            .map_err(|_| EnclaveBuildError::ManifestError)?;

        // The manifest is checked, so now validate the layers from the manifest
        self.validate_layers(&manifest_json)?;

        // Extract the config digest from the manifest
        let config_digest = Self::fetch_config_digest(manifest_json)?;

        // Finally, check that the config is correctly cached
        // This is done by applying a hash function on the config file contents and comparing the
        // result with the config digest from the manifest
        let config_str = self.fetch_config(&config_digest)?;

        // Compare the two digests
        if config_digest != format!("{:x}", sha2::Sha256::digest(config_str.as_bytes())) {
            return Err(EnclaveBuildError::CacheMissError(
                "Config content digest and manifest digest do not match".to_string(),
            ));
        }

        Ok(())
    }

    /// Validates that the image layers are cached correctly by checking them with the layer descriptors
    /// from the image manifest.
    fn validate_layers(&self, manifest_obj: &Value) -> Result<()> {
        let layers_path = self.root_path.join(CACHE_BLOBS_FOLDER);

        // Try to get the layer list from the manifest JSON
        let layers_vec = manifest_obj
            .get("layers")
            .ok_or_else(|| {
                EnclaveBuildError::CacheMissError(
                    "'layers' field missing from manifest JSON.".to_string(),
                )
            })?
            .as_array()
            .ok_or_else(|| {
                EnclaveBuildError::CacheMissError("Manifest deserialize error.".to_string())
            })?
            .to_vec();

        // Get the cached blobs as a HashMap mapping a layer digest to the corresponding layer file
        let mut cached_blobs = HashMap::new();

        fs::read_dir(layers_path)
            .map_err(|err| {
                EnclaveBuildError::CacheMissError(format!("Failed to get image layers: {:?}", err))
            })?
            .into_iter()
            // Get only the valid directory entries that are valid files and return (name, file) pair
            .filter_map(|entry| match entry {
                Ok(dir_entry) => match File::open(dir_entry.path()) {
                    Ok(file) => Some((dir_entry.file_name(), file)),
                    Err(_) => None,
                },
                Err(_) => None,
            })
            // Map a layer digest to the layer file
            // The 'cached_layers' hashmap will contain all layer files found in the cache for the current image
            .for_each(|(name, file)| {
                if let Ok(file_name) = name.into_string() {
                    cached_blobs.insert(file_name, file);
                }
            });

        // Iterate through each layer found in the image manifest and validate that it is stored in
        // the cache by checking the digest
        for layer_obj in layers_vec {
            // Read the layer digest from the manifest
            let layer_digest: String = layer_obj
                .get("digest")
                .ok_or_else(|| {
                    EnclaveBuildError::CacheMissError(
                        "Image layer digest not found in manifest".to_string(),
                    )
                })?
                .as_str()
                .ok_or_else(|| {
                    EnclaveBuildError::CacheMissError("Layer info extract error".to_string())
                })?
                .strip_prefix("sha256:")
                .ok_or_else(|| {
                    EnclaveBuildError::CacheMissError("Layer info extract error".to_string())
                })?
                .to_string();

            // Get the cached layer file matching the digest
            // If not present, then a layer file is missing, so return Error
            let mut layer_file = cached_blobs.get(&layer_digest).ok_or_else(|| {
                EnclaveBuildError::CacheMissError("Layer missing from cache.".to_string())
            })?;
            let mut layer_bytes = Vec::new();
            layer_file.read_to_end(&mut layer_bytes).map_err(|_| {
                EnclaveBuildError::CacheMissError("Failed to read layer".to_string())
            })?;

            let calc_digest = format!("{:x}", sha2::Sha256::digest(layer_bytes.as_slice()));

            // Check that the digests match
            if calc_digest != layer_digest {
                return Err(EnclaveBuildError::CacheMissError(
                    "Layer not valid".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Returns the manifest JSON string from the cache.
    fn fetch_manifest_from_index(&self, image_name: &str, index: CacheIndex) -> Result<Value> {
        let img_ref =
            Self::normalize_reference(&image::build_image_reference(&image_name)?.whole());
        let manifest_entry = index
            .manifests
            .iter()
            .filter(|entry| match entry.annotations.get(REF_ANNOTATION) {
                Some(value) => img_ref == value.to_string(),
                None => false,
            })
            .next()
            .ok_or(EnclaveBuildError::ManifestError)?;

        Self::fetch_manifest(&self.root_path, &manifest_entry.digest)
    }

    /// Fetch index file from the cache root path
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

    /// Returns the config JSON string from the cache.
    fn fetch_config(&self, config_digest: &str) -> Result<String> {
        let target_path = self.root_path.join(CACHE_BLOBS_FOLDER);

        let mut config_json = String::new();
        File::open(target_path.join(config_digest))
            .map_err(|_| EnclaveBuildError::ConfigError)?
            .read_to_string(&mut config_json)
            .map_err(|_| EnclaveBuildError::ConfigError)?;

        if config_json.is_empty() {
            return Err(EnclaveBuildError::ConfigError);
        }

        Ok(config_json)
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

    /// Add `docker.io` to references that are missing this registry so `linuxkit` can validate cache presence
    fn normalize_reference(reference: &str) -> String {
        let docker_prefix = "docker.io/";
        if reference.starts_with(docker_prefix) {
            return reference.to_string();
        }

        docker_prefix.to_owned() + reference
    }

    /// Fetches the image metadata from cache as an ImageDetails struct.
    ///
    /// If the data is not correctly cached or a file is missing, it returns an error.
    ///
    /// If the image is not cached, it does not attempt to pull the image from remote.
    pub fn fetch_image_details(&self, image_name: &str) -> Result<ImageDetails> {
        let config_hash = self
            .get_image_hash_from_name(&Self::normalize_reference(&image_name))
            .ok_or_else(|| EnclaveBuildError::CacheMissError("Image hash missing".to_string()))?;

        // // Add algorithm prefix to the hash
        let image_hash = format!("sha256:{}", config_hash);
        let config_json = self.fetch_config(&config_hash)?;

        Ok(ImageDetails::new(
            image::build_image_reference(&image_name)?.whole(),
            image_hash,
            image::deserialize_from_reader(config_json.as_bytes())?,
        ))
    }

    /// Returns the image hash (if available in the CacheManager's hashmap) taking the image
    /// name as parameter.
    fn get_image_hash_from_name(&self, name: &str) -> Option<String> {
        match image::build_image_reference(&name) {
            Ok(image_ref) => self
                .cached_images
                .get(&image_ref.whole())
                .map(|val| val.to_string()),
            Err(_) => None,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::collections::HashMap;

    use oci_distribution::manifest::OciImageManifest;
    use serde_json::Value;
    use sha2::Digest;
    use std::env::temp_dir;

    /// This function caches the test image in a temporary directory and returns that directory and
    /// the cache manager initalized with it as root path.
    fn setup_temp_cache() -> (PathBuf, CacheManager) {
        // Use a temporary dir as the cache root path.
        let root_dir = temp_dir();

        // Use a mock ImageData struct
        let image_data = image::tests::build_image_data();

        // Initialize the cache manager
        let mut cache_manager =
            CacheManager::new(&root_dir).expect("failed to create the  CacheManager");

        // Store the mock image data in the temp cache
        cache_manager
            .store_image_data(image::tests::TEST_IMAGE_NAME, &image_data)
            .expect("failed to store test image to cache");

        (root_dir, cache_manager)
    }

    #[test]
    fn test_image_is_cached() {
        let (_cache_root_path, cache_manager) = setup_temp_cache();

        let res = cache_manager.check_cached_image(image::tests::TEST_IMAGE_NAME);

        assert!(res.is_ok());
    }

    #[test]
    fn test_image_is_not_cached() {
        let (cache_root_path, cache_manager) = setup_temp_cache();

        // Delete the index file so that check_cached_image() returns error
        let index_file_path = cache_root_path.join(CACHE_INDEX_FILE_NAME);
        fs::remove_file(&index_file_path).expect("could not remove the cache index file");

        let res = cache_manager.check_cached_image(image::tests::TEST_IMAGE_NAME);

        assert!(res.is_err());
    }

    #[test]
    fn test_validate_layers() {
        let (cache_root_path, cache_manager) = setup_temp_cache();

        // Digest of the layer to be deleted
        let delete_layer_digest =
            "1aed4d8555515c961bffea900d5e7f1c1e4abf0f6da250d8bf15843106e0533b";

        let layer_path = cache_root_path
            .join(CACHE_BLOBS_FOLDER)
            .join(delete_layer_digest);
        fs::remove_file(&layer_path).expect("could not remove the layer file");

        let res = cache_manager.check_cached_image(image::tests::TEST_IMAGE_NAME);

        assert!(res.is_err());
    }

    #[test]
    fn test_fetch_manifest_from_index() {
        let (_cache_root_path, cache_manager) = setup_temp_cache();

        let index: CacheIndex = CacheManager::fetch_index(&cache_manager.root_path).unwrap();
        let manifest = cache_manager
            .fetch_manifest_from_index(image::tests::TEST_IMAGE_NAME, index)
            .unwrap();

        let expected_manifest: serde_json::Value =
            serde_json::from_str(image::tests::TEST_MANIFEST).unwrap();

        assert_eq!(manifest, expected_manifest);
    }

    #[test]
    fn test_fetch_index() {
        let (cache_root_path, _cache_manager) = setup_temp_cache();

        let cache_index =
            CacheManager::fetch_index(&cache_root_path).expect("Failed to fetch index.json");

        let manifest: OciImageManifest = serde_json::from_str(image::tests::TEST_MANIFEST).unwrap();
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let manifest_entry = ManifestEntry {
            media_type: manifest
                .media_type
                .as_ref()
                .unwrap_or(&DEFAULT_MEDIA_TYPE.to_string())
                .to_string(),
            size: manifest_bytes.len(),
            digest: format!("sha256:{:x}", sha2::Sha256::digest(&manifest_bytes)),
            annotations: HashMap::from([(
                REF_ANNOTATION.to_string(),
                CacheManager::normalize_reference(
                    &image::build_image_reference(image::tests::TEST_IMAGE_NAME)
                        .unwrap()
                        .whole(),
                ),
            )]),
        };

        let expected_index = CacheIndex {
            schema_version: 2,
            manifests: vec![manifest_entry],
        };

        assert_eq!(cache_index, expected_index);
    }

    #[test]
    fn test_fetch_manifest() {
        let (cache_root_path, _cache_manager) = setup_temp_cache();

        let manifest_digest = format!(
            "sha256:{:x}",
            sha2::Sha256::digest(
                &image::tests::TEST_MANIFEST
                    .to_string()
                    .replace("\n", "")
                    .replace(" ", "")
                    .as_bytes()
            )
        );

        let cached_manifest = CacheManager::fetch_manifest(&cache_root_path, &manifest_digest)
            .expect("failed to fetch image manifest from cache");

        let val: serde_json::Value = serde_json::from_str(image::tests::TEST_MANIFEST).unwrap();

        assert_eq!(cached_manifest, val);
    }

    #[test]
    fn test_fetch_config() {
        let (_cache_root_path, cache_manager) = setup_temp_cache();

        let cached_config = cache_manager
            .fetch_config(image::tests::TEST_IMAGE_HASH)
            .expect("failed to fetch image config from cache");

        let val1: serde_json::Value = serde_json::from_str(cached_config.as_str()).unwrap();
        let val2: serde_json::Value = serde_json::from_str(image::tests::TEST_CONFIG).unwrap();

        assert_eq!(val1, val2);
    }

    #[test]
    fn test_fetch_config_digest() {
        let manifest: Value = serde_json::from_str(image::tests::TEST_MANIFEST).unwrap();
        let config_digest = CacheManager::fetch_config_digest(manifest).unwrap();

        assert_eq!(image::tests::TEST_IMAGE_HASH.to_string(), config_digest);
    }

    #[test]
    fn test_get_image_hash_from_name() {
        let (_cache_root_path, cache_manager) = setup_temp_cache();

        let image_hash = cache_manager
            .get_image_hash_from_name(&CacheManager::normalize_reference(
                image::tests::TEST_IMAGE_NAME,
            ))
            .ok_or("")
            .expect("failed to get image hash from cache");

        assert_eq!(image_hash, image::tests::TEST_IMAGE_HASH.to_string());
    }
}
