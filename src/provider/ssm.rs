use aws_sdk_ssm::error::{DisplayErrorContext, ProvideErrorMetadata, SdkError};
use secrecy::SecretString;

use crate::config::ProviderConfig;
use crate::error::S2Error;
use crate::provider::{SecretProvider, SecretUri};

/// Map an SSM probe failure to a semantic `S2Error`, distinguishing a genuine IAM
/// authorization denial from any other failure (missing credentials, region/DNS,
/// throttling, service outage).
///
/// Classification reads the wire error code from metadata, never the `Display` string:
/// `GetParametersByPath` does not model `AccessDenied` as a typed variant, and
/// `SdkError`'s `Display` collapses every service error to the literal `"service error"`
/// (aws-smithy-runtime-api 1.11.6, `client/result.rs:494`), so a substring match on the
/// message can never see `"AccessDeniedException"`. `ProvideErrorMetadata::code()` returns
/// the wire code (`"AccessDeniedException"` for an IAM denial). `detail` is rendered with
/// `DisplayErrorContext` so it carries the full cause chain instead of `"service error"`.
fn classify_probe_error<E, R>(prefix: &str, err: &SdkError<E, R>) -> S2Error
where
    E: ProvideErrorMetadata + std::error::Error + 'static,
    R: std::fmt::Debug,
{
    let detail = format!(
        "SSM health probe on '{prefix}': {}",
        DisplayErrorContext(err)
    );
    if err.code() == Some("AccessDeniedException") {
        S2Error::ProviderAccessDenied(detail)
    } else {
        S2Error::Provider(detail)
    }
}

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

    fn health_check(&self, hints: &[SecretUri]) -> Result<(), S2Error> {
        // Distinct prefixes to probe. Each referenced URI path is normalized to the
        // hierarchy prefix that `GetParametersByPath` (and the `*`-import path) uses,
        // matching how scoped IAM policies (`.../secrets/*`) authorize listing. If no
        // ssm:/// URIs were referenced, probe root as a best-effort reachability check.
        let mut prefixes = super::distinct_prefixes(hints);
        if prefixes.is_empty() {
            prefixes.push("/".to_string());
        }

        self.rt.block_on(async {
            let client = self.build_client().await;
            for prefix in &prefixes {
                // max_results(1) + with_decryption(false): no KMS decrypt, no plaintext
                // secret in memory. A successful call (even with zero rows) proves
                // reachability, credential/region/profile resolution, and the
                // ssm:GetParametersByPath grant on this prefix.
                client
                    .get_parameters_by_path()
                    .path(prefix)
                    .with_decryption(false)
                    .max_results(1)
                    .send()
                    .await
                    .map_err(|e| classify_probe_error(prefix, &e))?;
            }
            Ok(())
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

            let path = super::normalize_path_prefix(&uri.path);

            loop {
                let mut req = client
                    .get_parameters_by_path()
                    .path(&path)
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

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_ssm::config::{BehaviorVersion, Credentials, Region};
    use aws_smithy_http_client::test_util::{ReplayEvent, StaticReplayClient};
    use aws_smithy_types::body::SdkBody;

    /// Build an SSM client whose HTTP layer replays a canned AWS error response, so the
    /// SDK's real error deserializer runs and populates the wire error code — no network,
    /// no credentials resolution.
    fn client_replaying(status: u16, error_type: &str) -> aws_sdk_ssm::Client {
        let response = http::Response::builder()
            .status(status)
            .header("x-amzn-errortype", error_type)
            .body(SdkBody::from(format!(
                r#"{{"__type":"{error_type}","message":"stubbed"}}"#
            )))
            .unwrap();
        let http_client = StaticReplayClient::new(vec![ReplayEvent::new(
            http::Request::builder()
                .uri("https://ssm.us-east-1.amazonaws.com/")
                .body(SdkBody::empty())
                .unwrap(),
            response,
        )]);
        let conf = aws_sdk_ssm::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(Credentials::new("akid", "secret", None, None, "static"))
            .http_client(http_client)
            .build();
        aws_sdk_ssm::Client::from_conf(conf)
    }

    fn probe(client: &aws_sdk_ssm::Client) -> S2Error {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt.block_on(async {
            client
                .get_parameters_by_path()
                .path("/prod/apps/service-a/secrets/")
                .with_decryption(false)
                .max_results(1)
                .send()
                .await
                .expect_err("stubbed response is an error")
        });
        classify_probe_error("/prod/apps/service-a/secrets/", &err)
    }

    // Proof of life for the classifier: a genuine IAM 400 AccessDeniedException, deserialized
    // by the real SDK, must classify as `ProviderAccessDenied` (the "grant the policy" lane) —
    // NOT `Provider`/unreachable ("transient, do not re-key"). Driving the actual send path is
    // what proves `ProvideErrorMetadata::code()` yields "AccessDeniedException"; asserting the
    // classifier against a hand-built string would restate the bug this fix removes.
    #[test]
    fn access_denied_response_classifies_as_provider_access_denied() {
        assert!(matches!(
            probe(&client_replaying(400, "AccessDeniedException")),
            S2Error::ProviderAccessDenied(_)
        ));
    }

    // Any other service failure must NOT be mistaken for an authz denial.
    #[test]
    fn other_service_error_classifies_as_provider_unreachable() {
        assert!(matches!(
            probe(&client_replaying(500, "InternalServerError")),
            S2Error::Provider(_)
        ));
    }
}
