// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]

use crate::image::ImageDetails;
use crate::storage::OciStorage;
use crate::{EnclaveBuildError, Result};

use tempfile::NamedTempFile;
use tokio::runtime::Runtime;

/// Trait which provides an interface for handling images.
pub trait ImageManager {
    fn image_name(&self) -> &String;
    /// Pulls the image from remote and stores it in the local storage.
    fn pull_image(&mut self) -> Result<()>;
    /// Builds an image locally (from a Dockerfile in case of Docker).
    fn build_image(&self, dockerfile_dir: String) -> Result<()>;
    /// Inspects the image and returns its metadata in the form of a JSON Value.
    fn inspect_image(&mut self) -> Result<serde_json::Value>;
    /// Returns the architecture of the image.
    fn architecture(&mut self) -> Result<String>;
    /// Returns two temp files containing the CMD and ENV expressions extracted from the image,
    /// in this order.
    fn load(&mut self) -> Result<(NamedTempFile, NamedTempFile)>;
}

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

impl ImageManager for OciImageManager {
    fn image_name(&self) -> &String {
        &self.image_name
    }

    /// Pulls the image from remote and attempts to store it locally.
    fn pull_image(&mut self) -> Result<()> {
        let image_name = self.image_name.clone();
        let act = async {
            // Attempt to pull and store the image
            self.get_image_details(&image_name).await?;

            Ok(())
        };

        let runtime = Runtime::new().map_err(|_| EnclaveBuildError::RuntimeError)?;
        runtime.block_on(act)
    }

    fn build_image(&self, _: String) -> Result<()> {
        todo!();
    }

    /// Inspect the image and return its description as a JSON String.
    fn inspect_image(&mut self) -> Result<serde_json::Value> {
        let image_name = self.image_name.clone();
        let act = async {
            let image_details = self.get_image_details(&image_name).await?;

            // Serialize to a serde_json::Value
            serde_json::to_value(&image_details).map_err(EnclaveBuildError::SerdeError)
        };

        let runtime = Runtime::new().map_err(|_| EnclaveBuildError::RuntimeError)?;
        runtime.block_on(act)
    }

    /// Extracts the CMD and ENV expressions from the image and returns them each in a
    /// temporary file
    fn load(&mut self) -> Result<(NamedTempFile, NamedTempFile)> {
        let (cmd, env) = self.extract_image()?;

        let cmd_file = crate::docker::write_config(cmd)
            .map_err(|err| EnclaveBuildError::ExtractError(format!("{:?}", err)))?;
        let env_file = crate::docker::write_config(env)
            .map_err(|err| EnclaveBuildError::ExtractError(format!("{:?}", err)))?;

        Ok((cmd_file, env_file))
    }

    /// Returns architecture information of the image.
    fn architecture(&mut self) -> Result<String> {
        let image_name = self.image_name.clone();
        let act_get_image = async {
            let image = self.get_image_details(&image_name).await?;

            Ok(format!("{}", image.config().architecture()))
        };

        let runtime = Runtime::new().map_err(|_| EnclaveBuildError::RuntimeError)?;
        runtime.block_on(act_get_image)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;

    /// Test extracted configuration is as expected
    #[test]
    fn test_config() {
        #[cfg(target_arch = "x86_64")]
        let mut image_manager = OciImageManager::new(
            "667861386598.dkr.ecr.us-east-1.amazonaws.com/enclaves-samples:vsock-sample-server-x86_64",
        );
        #[cfg(target_arch = "aarch64")]
        let mut image_manager = OciImageManager::new(
            "667861386598.dkr.ecr.us-east-1.amazonaws.com/enclaves-samples:vsock-sample-server-aarch64",
        );

        let (cmd_file, env_file) = image_manager.load().unwrap();
        let mut cmd_file = File::open(cmd_file.path()).unwrap();
        let mut env_file = File::open(env_file.path()).unwrap();

        let mut cmd = String::new();
        cmd_file.read_to_string(&mut cmd).unwrap();
        assert_eq!(
            cmd,
            "/bin/sh\n\
             -c\n\
             ./vsock-sample server --port 5005\n"
        );

        let mut env = String::new();
        env_file.read_to_string(&mut env).unwrap();
        assert_eq!(
            env,
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        );
    }
}
