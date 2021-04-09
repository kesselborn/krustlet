//! Basic implementation of Kubernetes Admission API
use crate::Operator;
use anyhow::{bail, ensure, Context};
use k8s_openapi::{api::authentication::v1::UserInfo, apimachinery::pkg::apis::meta::v1::Status};
use k8s_openapi::{
    api::{
        admissionregistration::v1::MutatingWebhookConfiguration,
        core::v1::{Secret, Service},
    },
    apimachinery::pkg::apis::meta::v1::OwnerReference,
    Metadata, Resource,
};
use kube::{
    api::{Meta, ObjectMeta, PostParams},
    Client,
};
use serde::{Deserialize, Serialize, Serializer};
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use warp::Filter;

/// WebhookResources encapsulates Kubernetes resources necessary to register the admission webhook.
/// and provides some convenience functions
///
/// # Examples
///
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
/// let webhook_resources =
///     admission::WebhookResources::from(MyCr::admission_webhook_resources(namespace));
/// println!("{}", webhook_resources); // print resources as yaml
///
/// // get the installed crd resource
/// let my_crd = Api::<CustomResourceDefinition>::all(client.clone())
///     .get(&MyCr::crd().metadata.name.unwrap())
///     .await?;
///
/// // install the necessary resources for serving a admission controller (service, secret, mutatingwebhookconfig)
/// // and make them owned by the crd ... this way, they will all be deleted once the crd gets deleted
/// webhook_resources
///     .apply_owned(client.clone(), &my_crd)
///     .await?;
///
pub struct WebhookResources(pub Service, pub Secret, pub MutatingWebhookConfiguration);

impl From<(Service, Secret, MutatingWebhookConfiguration)> for WebhookResources {
    fn from(tuple: (Service, Secret, MutatingWebhookConfiguration)) -> Self {
        WebhookResources(tuple.0, tuple.1, tuple.2)
    }
}

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
    /// automatically, when the owner gets deleted.
    ///
    /// it will create the resources if they
    /// are not present yet or replace them if they already exist
    pub async fn apply_owned<T>(&self, client: &Client, owner: &T) -> anyhow::Result<()>
    where
        T: Resource + Metadata<Ty = ObjectMeta>,
    {
        let metadata = owner.metadata();

        let owner_references = Some(vec![OwnerReference {
            api_version: k8s_openapi::api_version(owner).to_string(),
            controller: Some(true),
            kind: k8s_openapi::kind(owner).to_string(),
            name: metadata.name.clone().unwrap(),
            uid: metadata.uid.clone().unwrap(),
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

    /// applies the webhook resources to the cluster, i.e. it will create the resources if they
    /// are not present yet or replace them if they already exist
    pub async fn apply(&self, client: &Client) -> anyhow::Result<()> {
        let secret_namespace = self.secret().metadata.namespace.as_ref().with_context(|| {
            format!(
                "secret {} does not have namespace set",
                self.secret()
                    .metadata
                    .name
                    .clone()
                    .unwrap_or("".to_string())
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

        {
            let api: kube::Api<Secret> = kube::Api::namespaced(client.to_owned(), secret_namespace);
            let name = self.secret().metadata.name.as_ref().unwrap();
            if let Ok(existing_secret) = api.get(name).await {
                let mut secret = self.secret().to_owned();
                secret.metadata.resource_version = Some(existing_secret.resource_ver().unwrap());
                api.replace(name, &PostParams::default(), &secret).await?;
            } else {
                api.create(&Default::default(), self.secret()).await?;
            }
        }

        {
            let api: kube::Api<Service> =
                kube::Api::namespaced(client.to_owned(), service_namespace);
            let name = self.service().metadata.name.as_ref().unwrap();
            if let Ok(existing_service) = api.get(name).await {
                let mut service = self.service().to_owned();

                // keep the cluster-ip -- this must not be changed on update
                let mut service_spec = service.spec.unwrap();
                service_spec.cluster_ip = existing_service.spec.clone().unwrap().cluster_ip;
                service.spec = Some(service_spec);

                service.metadata.resource_version = Some(existing_service.resource_ver().unwrap());
                api.replace(name, &PostParams::default(), &service).await?;
            } else {
                api.create(&Default::default(), self.service()).await?;
            }
        }

        {
            let api: kube::Api<MutatingWebhookConfiguration> = kube::Api::all(client.to_owned());
            let name = self.webhook_config().metadata.name.as_ref().unwrap();
            if let Ok(existing_webhook_config) = api.get(name).await {
                let mut webhook_config = self.webhook_config().to_owned();
                webhook_config.metadata.resource_version =
                    Some(existing_webhook_config.resource_ver().unwrap());
                api.replace(name, &PostParams::default(), &webhook_config)
                    .await?;
            } else {
                api.create(&Default::default(), self.webhook_config())
                    .await?;
            }
        }

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
    Allow(Option<T>),
    /// Deny the request. Pass a Status object to provide information about the error.
    Deny(Status),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
/// Kind is the fully-qualified type of object being submitted (for example, v1.Pod or autoscaling.v1.Scale)
pub struct AdmissionRequestKind {
    /// resource's group
    pub group: String,
    /// resource's version
    pub version: String,
    /// resource's kind
    pub kind: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
/// Resource is the fully-qualified resource being requested (for example, v1.pods)
pub struct AdmissionRequestResource {
    /// resource's group
    pub group: String,
    /// resource's version
    pub version: String,
    /// resource's kind
    pub resource: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
/// AdmissionRequest describes the admission.Attributes for the admission request.
pub struct AdmissionRequest<T> {
    /// `uid` is an identifier for the individual request/response. It allows us to distinguish instances of requests which are
    /// otherwise identical (parallel requests, requests when earlier requests did not modify etc)
    /// The UID is meant to track the round trip (request/response) between the KAS and the WebHook, not the user request.
    /// It is suitable for correlating log entries between the webhook and apiserver, for either auditing or debugging.
    pub uid: String,

    /// `kind` is the fully-qualified type of object being submitted (for example, v1.Pod or autoscaling.v1.Scale)
    pub kind: AdmissionRequestKind,

    /// `resource` is the fully-qualified resource being requested (for example, v1.pods)
    pub resource: AdmissionRequestResource,

    /// `sub_resource` is the subresource being requested, if any (for example, "status" or "scale")
    pub sub_resource: Option<String>,

    /// `request_kind` is the fully-qualified type of the original API request (for example, v1.Pod or autoscaling.v1.Scale).
    /// If this is specified and differs from the value in "kind", an equivalent match and conversion was performed.
    ///
    /// For example, if deployments can be modified via apps/v1 and apps/v1beta1, and a webhook registered a rule of
    /// `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]` and `matchPolicy: Equivalent`,
    /// an API request to apps/v1beta1 deployments would be converted and sent to the webhook
    /// with `kind: {group:"apps", version:"v1", kind:"Deployment"}` (matching the rule the webhook registered for),
    /// and `requestKind: {group:"apps", version:"v1beta1", kind:"Deployment"}` (indicating the kind of the original API request).
    pub request_kind: Option<AdmissionRequestKind>,

    /// `request_resource` is the fully-qualified resource of the original API request (for example, v1.pods).
    /// If this is specified and differs from the value in "resource", an equivalent match and conversion was performed.
    ///
    /// For example, if deployments can be modified via apps/v1 and apps/v1beta1, and a webhook registered a rule of
    /// `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]` and `matchPolicy: Equivalent`,
    /// an API request to apps/v1beta1 deployments would be converted and sent to the webhook
    /// with `resource: {group:"apps", version:"v1", resource:"deployments"}` (matching the resource the webhook registered for),
    /// and `requestResource: {group:"apps", version:"v1beta1", resource:"deployments"}` (indicating the resource of the original API request).
    pub request_resource: Option<AdmissionRequestResource>,

    /// `request_sub_resource` is the name of the subresource of the original API request, if any (for example, "status" or "scale")
    /// If this is specified and differs from the value in "subResource", an equivalent match and conversion was performed.
    /// See documentation for the "matchPolicy" field in the webhook configuration type.
    /// +optional
    pub request_sub_resource: Option<String>,

    /// `name` is the name of the object as presented in the request.  On a CREATE operation, the client may omit name and
    /// rely on the server to generate the name.  If that is the case, this field will contain an empty string.
    pub name: Option<String>,

    /// `namespace` is the namespace associated with the request (if any).
    pub namespace: Option<String>,

    /// the operation of the admission request: one of CREATE, UPDATE, DELETE, CONNECT
    pub operation: String,

    /// `user_info` is information about the requesting user
    pub user_info: UserInfo,

    /// `object` is the object from the incoming request -- empty on DELETE
    pub object: Option<T>,

    /// `old_object` is the existing object. Only populated for DELETE and UPDATE requests.
    pub old_object: Option<T>,

    /// whether this is a dry run or not
    pub dry_run: Option<bool>,
}

struct JsonPatch(json_patch::Patch);

impl Serialize for JsonPatch {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let base64_encoded_string = base64::encode(serde_json::to_string(&self.0).unwrap());
        serializer.serialize_str(&base64_encoded_string)
    }
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
    /// This needs to be a base64 encoded string
    patch: Option<JsonPatch>,
    /// The type of Patch. Currently we only allow "JSONPatch".
    patch_type: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
/// AdmissionReviewRequest is the request that the webhook receives from Kubernetes
struct AdmissionReviewRequest<T> {
    /// api_version of the admission request
    api_version: String,

    /// should be AdmissionReview
    kind: String,

    /// the admission request
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

    let routes = warp::any()
        .and(warp::post())
        .and(warp::body::json())
        .and_then(move |request: AdmissionReviewRequest<O::Manifest>| {
            let operator = Arc::clone(&operator);
            async move {
                let original = serde_json::to_value(&request.request.object).unwrap();
                let response = match operator.admission_hook(&request.request).await {
                    AdmissionResult::Allow(manifest) => {
                        let (patch, patch_type) = if let Some(manifest) = manifest {
                            let value = serde_json::to_value(&manifest).unwrap();
                            let patch = json_patch::diff(&original, &value);

                            if !patch.0.is_empty() {
                                (Some(JsonPatch(patch)), Some("JSONPatch".to_string()))
                            } else {
                                (None, None)
                            }
                        } else {
                            (None, None)
                        };

                        AdmissionResponse {
                            uid: Some(request.request.uid),
                            allowed: true,
                            status: None,
                            patch,
                            patch_type,
                        }
                    }
                    AdmissionResult::Deny(status) => AdmissionResponse {
                        uid: Some(request.request.uid),
                        allowed: false,
                        status: Some(status),
                        patch: None,
                        patch_type: None,
                    },
                };

                let xxx = &AdmissionReviewResponse {
                    api_version: request.api_version,
                    kind: request.kind,
                    response,
                };

                // let yyy = String::from_utf8(serde_json::to_vec(xxx).unwrap()).unwrap();
                let yyy = serde_json::to_value(xxx).unwrap();

                tracing::info!("returning: {:?}", &yyy);
                Ok::<_, std::convert::Infallible>(warp::reply::json(&yyy))
            }
        })
        .with(warp::trace::request());

    warp::serve(routes)
        .tls()
        .cert(tls.cert)
        .key(tls.private_key)
        .run(([0, 0, 0, 0], 8443))
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::admissionregistration::v1::MutatingWebhookConfiguration;
    use k8s_openapi::api::core::v1::Secret;
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use kube::CustomResource;
    pub use schemars::JsonSchema;
    use serde::{Deserialize, Serialize};
    use std::cmp::PartialEq;

    #[derive(CustomResource, Debug, Serialize, Deserialize, Clone, Default, JsonSchema)]
    #[kube(
        group = "animals.com",
        version = "v1",
        kind = "Moose",
        derive = "Default",
        status = "MooseStatus",
        namespaced
    )]
    struct MooseSpec {
        height: f64,
        weight: f64,
        antlers: bool,
    }
    #[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
    enum MoosePhase {
        Asleep,
        Hungry,
        Roaming,
    }
    #[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
    struct MooseStatus {
        phase: Option<MoosePhase>,
        message: Option<String>,
    }

    #[test]
    fn it_can_deserialize_create_admission_request() -> anyhow::Result<()> {
        let admission_request_json = include_str!("../tests/create.json");

        let admission_request: super::AdmissionReviewRequest<Moose> =
            serde_json::from_str(admission_request_json)?;

        Ok(())
    }

    #[test]
    fn it_can_deserialize_update_admission_request() -> anyhow::Result<()> {
        let admission_request_json = include_str!("../tests/update.json");

        let admission_request: super::AdmissionReviewRequest<Moose> =
            serde_json::from_str(admission_request_json)?;

        Ok(())
    }

    #[test]
    fn it_can_deserialize_delete_admission_request() -> anyhow::Result<()> {
        let admission_request_json = include_str!("../tests/delete.json");

        let admission_request: super::AdmissionReviewRequest<Moose> =
            serde_json::from_str(admission_request_json)?;

        Ok(())
    }
}
