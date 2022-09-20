// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{EnclaveBuildError, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io::Read;

use sha2::Digest;

use oci_distribution::{client::ImageData, Reference};
use oci_spec::image::ImageConfiguration;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
/// Struct representing the image metadata, like the image ID (hash) and config.
pub struct ImageDetails {
    /// The reference of an image, e.g. "docker.io/library/hello-world:latest".
    // Use a String, since the oci_distribution::Reference struct does not implement
    // Serialize/Deserialize
    uri: String,
    /// The image ID, calculated as the SHA256 digest hash of the image config.
    #[serde(rename = "Id")]
    hash: String,
    /// The image config.
    config: ImageConfiguration,
}

impl ImageDetails {
    pub fn new(image_uri: String, image_hash: String, config: ImageConfiguration) -> Self {
        Self {
            uri: image_uri,
            hash: image_hash,
            config,
        }
    }

    /// Try to build an ImageDetails struct from an oci_distribution ImageData struct.
    //
    // The oci_distribution ImageData struct does not contain the image name or reference, so this
    // must be additionally passed to the function as well.
    pub fn build_details(image_name: &str, image_data: &ImageData) -> Result<Self> {
        // Calculate the image hash as the digest of the image config, as specified in the OCI image spec
        // https://github.com/opencontainers/image-spec/blob/main/config.md
        let image_hash = format!("sha256:{:x}", sha2::Sha256::digest(&image_data.config.data));

        let image_ref = build_image_reference(&image_name)?;

        Ok(Self {
            uri: image_ref.whole(),
            hash: image_hash,
            config: deserialize_from_reader(image_data.config.data.as_slice())?,
        })
    }
}

/// For example, "hello-world" image has reference "docker.io/library/hello-world:latest".
///
/// This function uses the implementation from oci_distribution.
pub fn build_image_reference(image_name: &str) -> Result<Reference> {
    let image_ref = image_name.parse().map_err(|err| {
        EnclaveBuildError::ImageDetailError(format!("Failed to find image reference: {:?}", err))
    })?;

    Ok(image_ref)
}

pub fn deserialize_from_reader<R: Read, T: DeserializeOwned>(reader: R) -> Result<T> {
    let deserialized_obj =
        serde_json::from_reader(reader).map_err(EnclaveBuildError::SerdeError)?;

    Ok(deserialized_obj)
}
