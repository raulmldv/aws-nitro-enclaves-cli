// Copyright 2019-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::path::Path;
use std::process::Command;

mod docker;
mod yaml_generator;

use docker::DockerUtil;
use eif_defs::EIF_HDR_ARCH_ARM64;
use eif_utils::{EifBuilder, SignEnclaveInfo, EifIdentityInfo};
use sha2::Digest;
use std::collections::BTreeMap;
use yaml_generator::YamlGenerator;
use tokio::runtime::Runtime;
use serde_json::json;

pub const DEFAULT_TAG: &str = "1.0";

pub struct Docker2Eif<'a> {
    docker_image: String,
    docker: DockerUtil,
    init_path: String,
    nsm_path: String,
    kernel_img_path: String,
    cmdline: String,
    linuxkit_path: String,
    artifacts_prefix: String,
    output: &'a mut File,
    sign_info: Option<SignEnclaveInfo>,
    eif_data: EifIdentityInfo,
}

#[derive(Debug, PartialEq)]
pub enum Docker2EifError {
    DockerError,
    DockerfilePathError,
    ImagePullError,
    InitPathError,
    NsmPathError,
    KernelPathError,
    LinuxkitExecError,
    LinuxkitPathError,
    MetadataPathError,
    MetadataFileError,
    ArtifactsPrefixError,
    RamfsError,
    RemoveFileError,
    SignImageError(String),
    SignArgsError,
    UnsupportedArchError,
}

impl<'a> Docker2Eif<'a> {
    pub fn new(
        docker_image: String,
        init_path: String,
        nsm_path: String,
        kernel_img_path: String,
        cmdline: String,
        linuxkit_path: String,
        output: &'a mut File,
        artifacts_prefix: String,
        certificate_path: &Option<String>,
        key_path: &Option<String>,
        img_name: &Option<String>,
        img_version: &Option<String>,
        meta_file_path: &Option<String>,
    ) -> Result<Self, Docker2EifError> {
        let docker = DockerUtil::new(docker_image.clone());

        if !Path::new(&init_path).is_file() {
            return Err(Docker2EifError::InitPathError);
        } else if !Path::new(&nsm_path).is_file() {
            return Err(Docker2EifError::NsmPathError);
        } else if !Path::new(&kernel_img_path).is_file() {
            return Err(Docker2EifError::KernelPathError);
        } else if !Path::new(&linuxkit_path).is_file() {
            return Err(Docker2EifError::LinuxkitPathError);
        } else if !Path::new(&artifacts_prefix).is_dir() {
            return Err(Docker2EifError::ArtifactsPrefixError);
        }

        let meta_file = match meta_file_path {
            Some(meta) => {
                if !Path::new(&meta).is_file() {
                    return Err(Docker2EifError::MetadataPathError);
                } else {
                    Some(meta.clone())
                }
            },
            None => None,
        };

        let uri_split: Vec<&str> = docker_image.split(':').collect();
        let repo = uri_split[0].to_string();
        let mut tag = DEFAULT_TAG.to_string();
        if uri_split.len() > 1 {
            tag = uri_split[1].to_string();
        }

        let img_name = match img_name {
            Some(name) => name,
            None => &repo,
        };
        let img_version = match img_version {
            Some(version) => version,
            None => &tag,
        };


        let sign_info = match (certificate_path, key_path) {
            (None, None) => None,
            (Some(cert_path), Some(key_path)) => Some(
                SignEnclaveInfo::new(&cert_path, &key_path)
                    .map_err(|err| Docker2EifError::SignImageError(format!("{:?}", err)))?,
            ),
            _ => return Err(Docker2EifError::SignArgsError),
        };

        let docker_info = json!({});

        Ok(Docker2Eif {
            docker_image,
            docker,
            init_path,
            nsm_path,
            kernel_img_path,
            cmdline,
            linuxkit_path,
            output,
            artifacts_prefix,
            sign_info,
            eif_data: EifIdentityInfo::new(
                img_name.clone(),
                img_version.clone(),
                meta_file,
                docker_info,
            )
        })
    }

    pub fn pull_docker_image(&self) -> Result<(), Docker2EifError> {
        self.docker.pull_image().map_err(|e| {
            eprintln!("Docker error: {:?}", e);
            Docker2EifError::DockerError
        })?;

        Ok(())
    }

    pub fn build_docker_image(&self, dockerfile_dir: String) -> Result<(), Docker2EifError> {
        if !Path::new(&dockerfile_dir).is_dir() {
            return Err(Docker2EifError::DockerfilePathError);
        }
        self.docker.build_image(dockerfile_dir).map_err(|e| {
            eprintln!("Docker error: {:?}", e);
            Docker2EifError::DockerError
        })?;

        Ok(())
    }

    pub fn create(&mut self) -> Result<BTreeMap<String, String>, Docker2EifError> {
        let info = async {
            self.docker.docker.images().get(&self.docker_image).inspect().await
        };
        let runtime = Runtime::new().map_err(|_| Docker2EifError::DockerError)?;
        let docker_info = runtime.block_on(info).unwrap();
        
        let (cmd_file, env_file) = self.docker.load().map_err(|e| {
            eprintln!("Docker error: {:?}", e);
            Docker2EifError::DockerError
        })?;

        let yaml_generator = YamlGenerator::new(
            self.docker_image.clone(),
            self.init_path.clone(),
            self.nsm_path.clone(),
            cmd_file.path().to_str().unwrap().to_string(),
            env_file.path().to_str().unwrap().to_string(),
        );

        let ramfs_config_file = yaml_generator.get_bootstrap_ramfs().map_err(|e| {
            eprintln!("Ramfs error: {:?}", e);
            Docker2EifError::RamfsError
        })?;
        let ramfs_with_rootfs_config_file = yaml_generator.get_customer_ramfs().map_err(|e| {
            eprintln!("Ramfs error: {:?}", e);
            Docker2EifError::RamfsError
        })?;

        let bootstrap_ramfs = format!("{}/bootstrap-initrd.img", self.artifacts_prefix);
        let customer_ramfs = format!("{}/customer-initrd.img", self.artifacts_prefix);

        let output = Command::new(&self.linuxkit_path)
            .args(&[
                "build",
                "-name",
                &bootstrap_ramfs,
                "-format",
                "kernel+initrd",
                ramfs_config_file.path().to_str().unwrap(),
            ])
            .output()
            .map_err(|_| Docker2EifError::LinuxkitExecError)?;
        if !output.status.success() {
            eprintln!(
                "Linuxkit reported an error while creating the bootstrap ramfs: {:?}",
                String::from_utf8_lossy(&output.stderr)
            );
            return Err(Docker2EifError::LinuxkitExecError);
        }

        // Prefix the docker image filesystem, as expected by init
        let output = Command::new(&self.linuxkit_path)
            .args(&[
                "build",
                "-name",
                &customer_ramfs,
                "-format",
                "kernel+initrd",
                "-prefix",
                "rootfs/",
                ramfs_with_rootfs_config_file.path().to_str().unwrap(),
            ])
            .output()
            .map_err(|_| Docker2EifError::LinuxkitExecError)?;
        if !output.status.success() {
            eprintln!(
                "Linuxkit reported an error while creating the customer ramfs: {:?}",
                String::from_utf8_lossy(&output.stderr)
            );
            return Err(Docker2EifError::LinuxkitExecError);
        }

        let arch = self.docker.architecture().map_err(|e| {
            eprintln!("Docker error: {:?}", e);
            Docker2EifError::DockerError
        })?;

        let flags = match arch.as_str() {
            docker::DOCKER_ARCH_ARM64 => EIF_HDR_ARCH_ARM64,
            docker::DOCKER_ARCH_AMD64 => 0,
            _ => return Err(Docker2EifError::UnsupportedArchError),
        };

        let arg_data = EifIdentityInfo {
            img_name: self.eif_data.img_name.clone(),
            img_version: self.eif_data.img_version.clone(),
            metadata_path: match &self.eif_data.metadata_path {
                Some(meta) => Some(meta.clone()),
                None => None
            },
            docker_info: json!(docker_info),
        };

        let mut build = EifBuilder::new(
            &Path::new(&self.kernel_img_path),
            self.cmdline.clone(),
            self.sign_info.clone(),
            sha2::Sha384::new(),
            flags,
            arg_data,
        );

        // Linuxkit adds -initrd.img sufix to the file names.
        let bootstrap_ramfs = format!("{}-initrd.img", bootstrap_ramfs);
        let customer_ramfs = format!("{}-initrd.img", customer_ramfs);

        build.add_ramdisk(Path::new(&bootstrap_ramfs));
        build.add_ramdisk(Path::new(&customer_ramfs));

        Ok(build.write_to(self.output))
    }
}
