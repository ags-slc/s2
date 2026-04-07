use secrecy::SecretString;

use crate::config::ProviderConfig;
use crate::error::S2Error;
use crate::provider::{SecretProvider, SecretUri};

/// Provider for AWS Systems Manager Parameter Store.
/// URI format: ssm:///parameter/path
pub struct SsmProvider {
    region: Option<String>,
    profile: Option<String>,
    rt: tokio::runtime::Runtime,
}

impl SsmProvider {
    pub fn new(config: Option<&ProviderConfig>) -> Result<Self, S2Error> {
        let region = config
            .and_then(|c| c.settings.get("region"))
            .and_then(|v| v.as_str())
            .map(String::from);
        let profile = config
            .and_then(|c| c.settings.get("profile"))
            .and_then(|v| v.as_str())
            .map(String::from);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| S2Error::Provider(format!("tokio runtime: {e}")))?;
        Ok(Self {
            region,
            profile,
            rt,
        })
    }

    async fn build_client(&self) -> aws_sdk_ssm::Client {
        let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(ref profile) = self.profile {
            config_loader = config_loader.profile_name(profile);
        }
        if let Some(ref region) = self.region {
            config_loader = config_loader.region(aws_config::Region::new(region.clone()));
        }
        let aws_config = config_loader.load().await;
        aws_sdk_ssm::Client::new(&aws_config)
    }
}

impl SecretProvider for SsmProvider {
    fn scheme(&self) -> &str {
        "ssm"
    }

    fn display_name(&self) -> &str {
        "AWS SSM Parameter Store"
    }

    fn resolve(&self, uri: &SecretUri) -> Result<SecretString, S2Error> {
        self.rt.block_on(async {
            let client = self.build_client().await;

            let result = client
                .get_parameter()
                .name(&uri.path)
                .with_decryption(true)
                .send()
                .await
                .map_err(|e| S2Error::Provider(format!("SSM GetParameter: {e}")))?;

            let value = result
                .parameter()
                .and_then(|p| p.value())
                .ok_or_else(|| S2Error::Provider(format!("SSM: no value for {}", uri.path)))?;

            Ok(SecretString::from(value.to_string()))
        })
    }

    fn resolve_prefix(
        &self,
        uri: &SecretUri,
        recursive: bool,
    ) -> Result<Vec<(String, SecretString)>, S2Error> {
        self.rt.block_on(async {
            let client = self.build_client().await;

            let mut results = Vec::new();
            let mut next_token: Option<String> = None;

            loop {
                let mut req = client
                    .get_parameters_by_path()
                    .path(&uri.path)
                    .with_decryption(true)
                    .recursive(recursive);

                if let Some(token) = next_token.take() {
                    req = req.next_token(token);
                }

                let response = req
                    .send()
                    .await
                    .map_err(|e| S2Error::Provider(format!("SSM GetParametersByPath: {e}")))?;

                for param in response.parameters() {
                    if let (Some(name), Some(value)) = (param.name(), param.value()) {
                        results.push((name.to_string(), SecretString::from(value.to_string())));
                    }
                }

                match response.next_token() {
                    Some(token) => next_token = Some(token.to_string()),
                    None => break,
                }
            }

            Ok(results)
        })
    }
}
