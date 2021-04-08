//! Basic implementation of Kubernetes Admission API
use crate::Operator;
use anyhow::{bail, ensure, Context};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Status;
use k8s_openapi::{
    api::{
        admissionregistration::v1::MutatingWebhookConfiguration,
        core::v1::{Secret, Service},
    },
    apimachinery::pkg::apis::meta::v1::OwnerReference,
    Metadata, Resource,
};
use kube::{api::ObjectMeta, Client};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::sync::Arc;

/// WebhookResources encapsulates Kubernetes resources necessary to register the admission webhook.
/// # Examples
///
/// ```
/// #[derive(
///   AdmissionWebhook,
///   CustomResource,
///   Serialize,
///   Deserialize,
///   PartialEq,
///   Default,
///   Debug,
///   Clone,
///   JsonSchema,
/// )]
/// #[kube(
/// group = "example.com",
/// version = "v1",
/// kind = "MyCr",
/// )]
/// pub struct MyCrSpec {
///     pub owner: String,
/// }
///
/// let namespace = "default";
/// let (service, secret, config) = MyCr::::admission_webhook_resources(namespace);
/// let webhook_resources = WebhookResources(service, secret, config);
/// println!("{}", webhook_resources);
/// ```
pub struct WebhookResources(
    pub k8s_openapi::api::core::v1::Service,
    pub k8s_openapi::api::core::v1::Secret,
    pub k8s_openapi::api::admissionregistration::v1::MutatingWebhookConfiguration,
);

impl WebhookResources {
    /// returns the service
    pub fn service(&self) -> &Service {
        &self.0
    }

    /// returns the secret
    pub fn secret(&self) -> &Secret {
        &self.1
    }

    /// returns the webhook_config
    pub fn webhook_config(&self) -> &MutatingWebhookConfiguration {
        &self.2
    }

    /// applies the webhook resources and makes them owned by the object
    /// that the `owner` resource belongs to -- this way the resource will get deleted
    /// automatically, when the owner gets deleted
    pub async fn apply_owned<T>(&self, client: Client, owner: &T) -> anyhow::Result<()>
    where
        T: Resource + Metadata<Ty = ObjectMeta>,
    {
        let api_version = k8s_openapi::api_version(owner);
        let kind = k8s_openapi::kind(owner);
        let metadata = owner.metadata();

        let owner_references = Some(vec![OwnerReference {
            api_version: api_version.to_string(),
            controller: Some(true),
            kind: kind.to_string(),
            name: metadata.name.as_ref().unwrap().to_string(),
            uid: metadata.uid.as_ref().unwrap().to_string(),
            ..Default::default()
        }]);

        let mut secret = self.secret().to_owned();
        secret.metadata.owner_references = owner_references.clone();

        let mut service = self.service().to_owned();
        service.metadata.owner_references = owner_references.clone();

        let mut webhook_config = self.webhook_config().to_owned();
        webhook_config.metadata.owner_references = owner_references;

        WebhookResources(service, secret, webhook_config)
            .apply(client)
            .await
    }

    /// applies the webhook resources
    pub async fn apply(&self, client: Client) -> anyhow::Result<()> {
        let secret_namespace = self.secret().metadata.namespace.as_ref().with_context(|| {
            format!(
                "secret {} does not have namespace set",
                self.secret()
                    .metadata
                    .name
                    .as_ref()
                    .unwrap_or(&"".to_string())
            )
        })?;
        let service_namespace = self
            .service()
            .metadata
            .namespace
            .as_ref()
            .with_context(|| {
                format!(
                    "service {} does not have namespace set",
                    self.service()
                        .metadata
                        .name
                        .as_ref()
                        .unwrap_or(&"".to_string())
                )
            })?;

        let secret_api: kube::Api<Secret> = kube::Api::namespaced(client.clone(), secret_namespace);
        secret_api
            .create(&Default::default(), self.secret())
            .await?;

        let service_api = kube::Api::namespaced(client.clone(), service_namespace);
        service_api
            .create(&Default::default(), self.service())
            .await?;

        let wh_config_api = kube::Api::all(client.clone());
        wh_config_api
            .create(&Default::default(), self.webhook_config())
            .await?;

        Ok(())
    }
}

impl Display for WebhookResources {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let service = self.service();
        write!(
            f,
            r#"
# resources necessary to expose the operator's webhook
# the service expects a pod with the labels
#
#    {:?}
#
# in namespace {}
#
# the service for the webhook
{}

# the secret containing the certificate and the private key the
# webhook service uses for secure communication
{}

# the webhook configuration
{}
"#,
            service.spec.clone().unwrap().selector.unwrap(),
            service.metadata.namespace.as_ref().unwrap(),
            serde_yaml::to_string(self.service()).unwrap(),
            serde_yaml::to_string(self.secret()).unwrap(),
            serde_yaml::to_string(self.webhook_config()).unwrap()
        )
    }
}

/// Result of admission hook.
#[allow(clippy::large_enum_variant)]
pub enum AdmissionResult<T> {
    /// Permit the request. Pass the object (with possible mutations) back.
    /// JSON Patch of any changes will automatically be created.
    Allow(T),
    /// Deny the request. Pass a Status object to provide information about the error.
    Deny(Status),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
/// AdmissionRequest describes the admission.Attributes for the admission request.
struct AdmissionRequest<T> {
    /// UID is an identifier for the individual request/response. It allows us to distinguish instances of requests which are
    /// otherwise identical (parallel requests, requests when earlier requests did not modify etc)
    /// The UID is meant to track the round trip (request/response) between the KAS and the WebHook, not the user request.
    /// It is suitable for correlating log entries between the webhook and apiserver, for either auditing or debugging.
    uid: Option<String>,
    /// Object is the object from the incoming request.
    object: T,
}

/// AdmissionResponse describes an admission response.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdmissionResponse {
    /// UID is an identifier for the individual request/response.
    /// This must be copied over from the corresponding AdmissionRequest.
    uid: Option<String>,
    /// Allowed indicates whether or not the admission request was permitted.
    allowed: bool,
    /// Result contains extra details into why an admission request was denied.
    /// This field IS NOT consulted in any way if "Allowed" is "true".
    status: Option<Status>,
    /// The patch body. Currently we only support "JSONPatch" which implements RFC 6902.
    patch: Option<json_patch::Patch>,
    /// The type of Patch. Currently we only allow "JSONPatch".
    patch_type: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdmissionReviewRequest<T> {
    api_version: String,
    kind: String,
    request: AdmissionRequest<T>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdmissionReviewResponse {
    api_version: String,
    kind: String,
    response: AdmissionResponse,
}

/// AdmissionTLS wraps certificate and private key for the admission webhook server. If you read
/// the secret from a Kubernets secret, use the convenience function [AdmissionTLS::from()]
pub struct AdmissionTLS {
    /// tls certificate
    pub cert: String,
    /// tls private key
    pub private_key: String,
}

impl AdmissionTLS {
    /// Convenience function to extract secret data from a Kubernetes secret of type `tls`. It supports
    /// Secrets that have secrets set via `data` or `string_data`
    pub fn from(s: &Secret) -> anyhow::Result<Self> {
        ensure!(
            s.type_.as_ref().unwrap() == "tls",
            "only tls secrets can be converted to AdmisstionTLS struct"
        );

        let metadata = &s.metadata;
        let error_msg = |key: &str| {
            format!(
                "secret data {}/{} does not contain key {}",
                metadata.name.as_ref().unwrap_or(&"".to_string()),
                metadata.namespace.as_ref().unwrap_or(&"".to_string()),
                key
            )
        };

        const TLS_CRT: &'static str = "tls.crt";
        const TLS_KEY: &'static str = "tls.key";

        if let Some(data) = &s.data {
            let cert_byte_string = data.get(TLS_CRT).context(error_msg(TLS_CRT))?;
            let key_byte_string = data.get(TLS_KEY).context(error_msg(TLS_KEY))?;

            return Ok(AdmissionTLS {
                cert: std::str::from_utf8(&cert_byte_string.0)?.to_string(),
                private_key: std::str::from_utf8(&key_byte_string.0)?.to_string(),
            });
        }

        if let Some(string_data) = &s.string_data {
            let cert = string_data.get(TLS_CRT).context(error_msg(TLS_CRT))?;
            let key = string_data.get(TLS_KEY).context(error_msg(TLS_KEY))?;

            return Ok(AdmissionTLS {
                cert: cert.to_string(),
                private_key: key.to_string(),
            });
        }

        bail!(
            "secret {}/{} does not contain any data",
            metadata.name.as_ref().unwrap_or(&"".to_string()),
            metadata.namespace.as_ref().unwrap_or(&"".to_string())
        )
    }
}

pub(crate) async fn endpoint<O: Operator>(operator: Arc<O>) {
    let operator = Arc::clone(&operator);
    let tls = operator.admission_hook_tls().await;
    if let Err(e) = tls {
        panic!("error getting tls secret for admission webhook: {}", e);
    }

    let tls = tls.unwrap();

    use warp::Filter;
    let routes = warp::any()
        .and(warp::post())
        .and(warp::body::json())
        .and_then(move |request: AdmissionReviewRequest<O::Manifest>| {
            let operator = Arc::clone(&operator);
            async move {
                let original = serde_json::to_value(&request.request.object).unwrap();
                let response = match operator.admission_hook(request.request.object).await {
                    AdmissionResult::Allow(manifest) => {
                        let value = serde_json::to_value(&manifest).unwrap();
                        let patch = json_patch::diff(&original, &value);
                        let (patch, patch_type) = if !patch.0.is_empty() {
                            (Some(patch), Some("JSONPatch".to_string()))
                        } else {
                            (None, None)
                        };
                        AdmissionResponse {
                            uid: request.request.uid,
                            allowed: true,
                            status: None,
                            patch,
                            patch_type,
                        }
                    }
                    AdmissionResult::Deny(status) => AdmissionResponse {
                        uid: request.request.uid,
                        allowed: false,
                        status: Some(status),
                        patch: None,
                        patch_type: None,
                    },
                };
                Ok::<_, std::convert::Infallible>(warp::reply::json(&AdmissionReviewResponse {
                    api_version: request.api_version,
                    kind: request.kind,
                    response,
                }))
            }
        });
    warp::serve(routes)
        .tls()
        .cert(tls.cert)
        .key(tls.private_key)
        .run(([0, 0, 0, 0], 8443))
        .await;
}
