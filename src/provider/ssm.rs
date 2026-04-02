use secrecy::SecretString;

use crate::config::ProviderConfig;
use crate::error::S2Error;
use crate::provider::{SecretProvider, SecretUri};

/// Provider for AWS Systems Manager Parameter Store.
/// URI format: ssm:///parameter/path
pub struct SsmProvider {
    region: Option<String>,
}

impl SsmProvider {
    pub fn new(config: Option<&ProviderConfig>) -> Result<Self, S2Error> {
        let region = config
            .and_then(|c| c.settings.get("region"))
            .and_then(|v| v.as_str())
            .map(String::from);
        Ok(Self { region })
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
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| S2Error::Provider(format!("tokio runtime: {}", e)))?;

        rt.block_on(async {
            let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
            if let Some(ref region) = self.region {
                config_loader =
                    config_loader.region(aws_config::Region::new(region.clone()));
            }
            let aws_config = config_loader.load().await;
            let client = aws_sdk_ssm::Client::new(&aws_config);

            let result = client
                .get_parameter()
                .name(&uri.path)
                .with_decryption(true)
                .send()
                .await
                .map_err(|e| S2Error::Provider(format!("SSM GetParameter: {}", e)))?;

            let value = result
                .parameter()
                .and_then(|p| p.value())
                .ok_or_else(|| {
                    S2Error::Provider(format!("SSM: no value for {}", uri.path))
                })?;

            Ok(SecretString::from(value.to_string()))
        })
    }
}
