// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]

use crate::image::ImageDetails;
use crate::storage::OciStorage;
use crate::{EnclaveBuildError, Result};

use tokio::runtime::Runtime;

pub struct OciImageManager {
    /// Name of the container image.
    image_name: String,
    /// Have the storage as an option for the CLI to continue running if there is a storage creation
    /// error (the image will simply be pulled in this case, instead of being fetched from storage)
    storage: Option<OciStorage>,
}

impl OciImageManager {
    /// When calling this constructor, it also tries to initialize the storage at the default path.
    /// If this fails, the ImageManager is still created, but the 'storage' field is set to 'None'.
    pub fn new(image_name: &str) -> Self {
        // Add the default ":latest" tag if the image tag is missing
        let image_name = check_tag(image_name);

        // The docker daemon is not used, so a local storage needs to be created
        // Get the default storage root path
        let root_path = match OciStorage::get_default_root_path() {
            Ok(path) => path,
            Err(_) => {
                // If the storage root path could not be determined, then the storage can not be initialized
                return Self {
                    image_name,
                    storage: None,
                };
            }
        };

        // Try to create/read the storage
        let storage = match OciStorage::new(&root_path) {
            Ok(manager) => Some(manager),
            Err(err) => {
                // If the storage could not be created, log the error
                eprintln!("{:?}", err);
                None
            }
        };

        Self {
            image_name,
            storage,
        }
    }

    /// Returns a struct containing image metadata.
    ///
    /// If the image is stored correctly, the function tries to fetch the image from the storage.
    ///
    /// If the image is not stored or a storage was not created (the 'storage' field is None),
    /// it pulls the image, stores it (if the 'storage' field is not None) and returns its metadata.
    ///
    /// If the pull succeeded but the store operation failed, it returns the pulled image metadata.
    async fn get_image_details(&mut self, image_name: &str) -> Result<ImageDetails> {
        let image_name = check_tag(image_name);

        let local_storage = (self.storage).as_mut();

        if let Some(storage) = local_storage {
            // Try to fetch the image from the storage
            let image_details = storage.fetch_image_details(&image_name).map_err(|err| {
                // Log the fetching error
                eprintln!("{:?}", err);
                err
            });

            // If the fetching failed, pull it from remote and store it
            return image_details.or(self.fetch_and_try_store_image(&image_name).await);
        }

        self.fetch_and_try_store_image(&image_name).await
    }

    /// Pulls image from remote registry and stores it if possible
    async fn fetch_and_try_store_image(&mut self, image_name: &str) -> Result<ImageDetails> {
        // The image is not stored, so try to pull and then store it
        let image_data = crate::pull::pull_image_data(image_name).await?;

        // If the store operation failed, still return the image details
        if let Some(local_storage) = self.storage.as_mut() {
            local_storage
                .store_image_data(image_name, &image_data)
                .map_err(|err| eprintln!("Failed to store image: {:?}", err))
                .ok();
        }

        // Get the image metadata from the pulled struct
        let image_details = ImageDetails::build_details(image_name, &image_data)?;

        Ok(image_details)
    }

    /// Extracts from the image and returns the CMD and ENV expressions (in this order).
    ///
    /// If there are no CMD expressions found, it tries to locate the ENTRYPOINT command.
    fn extract_image(&mut self) -> Result<(Vec<String>, Vec<String>)> {
        let image_name = self.image_name.clone();
        // Try to get the image details
        let act_get_image = async { self.get_image_details(&image_name).await };
        let image = Runtime::new()
            .map_err(|_| EnclaveBuildError::RuntimeError)?
            .block_on(act_get_image)
            .map_err(|err| EnclaveBuildError::ExtractError(format!("{:?}", err)))?;

        // Get the expressions from the image
        let config_section = image
            .config()
            .config()
            .as_ref()
            .ok_or(EnclaveBuildError::ConfigError)?;

        let cmd = config_section.cmd();
        let env = config_section.env();
        let entrypoint = config_section.entrypoint();

        // If no CMD instructions are found, try to locate an ENTRYPOINT command
        match (cmd, env, entrypoint) {
            (Some(cmd), Some(env), _) => Ok((cmd.to_vec(), env.to_vec())),
            (_, Some(env), Some(entrypoint)) => Ok((entrypoint.to_vec(), env.to_vec())),
            (_, _, Some(entrypoint)) => Ok((entrypoint.to_vec(), Vec::<String>::new())),
            (_, _, _) => Err(EnclaveBuildError::ExtractError(
                "Failed to locate ENTRYPOINT".to_string(),
            )),
        }
    }
}

/// Adds the default ":latest" tag to an image if it is untagged
fn check_tag(image_name: &str) -> String {
    let name = image_name.to_string();
    match name.contains(':') {
        true => name,
        false => format!("{}:latest", name),
    }
}
