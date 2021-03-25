use crate::proc_macro::TokenStream;
use quote::{quote, format_ident};
use syn::{
    Data, DeriveInput, Result,
};

pub trait CustomDerive: Sized {
    fn parse(input: syn::DeriveInput) -> Result<Self>;
    fn emit(self) -> Result<proc_macro2::TokenStream>;
}

#[derive(Debug)]
pub struct CustomResourceInfos {
    pub name: String,
}

pub(crate) fn run_custom_derive<T>(input: TokenStream) -> TokenStream
    where
        T: CustomDerive,
{
    let input: proc_macro2::TokenStream = input.into();
    let token_stream = match syn::parse2(input)
        .and_then(|input| <T as CustomDerive>::parse(input))
        .and_then(<T as CustomDerive>::emit)
    {
        Ok(token_stream) => token_stream,
        Err(err) => err.to_compile_error(),
    };

    token_stream.into()
}

trait ResultExt<T> {
    fn spanning(self, spanned: impl quote::ToTokens) -> Result<T>;
}

impl<T, E> ResultExt<T> for std::result::Result<T, E>
    where
        E: std::fmt::Display,
{
    fn spanning(self, spanned: impl quote::ToTokens) -> Result<T> {
        self.map_err(|err| syn::Error::new_spanned(spanned, err))
    }
}

impl CustomDerive for CustomResourceInfos {
    fn parse(input: DeriveInput) -> Result<Self> {
        let ident = input.ident;

        // Limit derive to structs
        let _s = match input.data {
            Data::Struct(ref s) => s,
            _ => {
                return Err(r#"Enums or Unions can not #[derive(AdmisstionWebhook)"#)
                    .spanning(ident)
            }
        };

        // Outputs
        let mut cri = CustomResourceInfos {
            name: "".to_string(),
        };

        let mut name: Option<String> = None;

        // Arg parsing
        for attr in &input.attrs {
            if let syn::AttrStyle::Outer = attr.style {} else {
                continue;
            }
            if !attr.path.is_ident("kube") {
                continue;
            }
            let metas = match attr.parse_meta()? {
                syn::Meta::List(meta) => meta.nested,
                meta => {
                    return Err(r#"#[kube] expects a list of metas, like `#[kube(...)]`"#)
                        .spanning(meta)
                }
            };

            for meta in metas {
                match &meta {
                    // key-value arguments
                    syn::NestedMeta::Meta(syn::Meta::NameValue(meta)) => {
                        if meta.path.is_ident("kind") {
                            if let syn::Lit::Str(lit) = &meta.lit {
                                name = Some(lit.value());
                                break;
                            } else {
                                return Err(
                                    r#"#[kube(kind = "...")] expects a string literal value"#,
                                )
                                    .spanning(meta);
                            }
                        }
                    } // unknown arg
                    _ => (),
                };
            }
        }
        cri.name = name.expect("kube macro must have property name set");

        Ok(cri)
    }

    fn emit(self) -> Result<proc_macro2::TokenStream> {
        let name = self.name;
        let name_identifier = format_ident!("{}", name);
        let gen = quote! {
            impl #name_identifier {
                fn admission_webhook_secret(namespace: &str) -> k8s_openapi::api::core::v1::Secret {
                    let crd = #name_identifier::crd();

                    let service_name = format!("{}-{}-admission-webhook", crd.spec.names.plural, crd.spec.group).to_string().replace(".", "-");

                    let subject_alt_names = vec![
                        service_name.clone(),
                        format!("{}.{}", &service_name, namespace).to_string(),
                    ];
                    let cert = rcgen::generate_simple_self_signed(subject_alt_names).unwrap();

                    let mut data = std::collections::BTreeMap::new();
                    data.insert("tls.crt".into(), cert.serialize_pem().unwrap());
                    data.insert("tls.key".into(), cert.serialize_private_key_pem());

                    k8s_openapi::api::core::v1::Secret {
                        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                            name: Some(format!("{}-tls", service_name)),
                            namespace: Some(namespace.to_string()),
                            ..Default::default()
                        },
                        string_data: Some(data),
                        type_: Some("tls".to_string()),
                        ..Default::default()
                    }
                }

                fn admission_webhook_service(namespace: &str) -> k8s_openapi::api::core::v1::Service {
                    let crd = #name_identifier::crd();

                    let service_name = format!("{}-{}-admission-webhook", crd.spec.names.plural, crd.spec.group).to_string().replace(".", "-");
                    let selector_value = format!("{}-{}-operator", crd.spec.names.plural, crd.spec.group).to_string().replace(".", "-");

                    let mut selector = std::collections::BTreeMap::new();
                    selector.insert("app".into(), selector_value);

                    k8s_openapi::api::core::v1::Service {
                        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                            name: Some(service_name),
                            namespace: Some(namespace.to_string()),
                            ..Default::default()
                        },
                        spec: Some(k8s_openapi::api::core::v1::ServiceSpec {
                            selector: Some(selector),
                            ports: Some(vec![k8s_openapi::api::core::v1::ServicePort{
                                protocol: Some("TCP".to_string()),
                                name: Some("https".to_string()),
                                port: 443,
                                target_port: Some(k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(8443)),
                                ..Default::default()
                            }]),
                            type_: Some("ClusterIP".to_string()),
                            ..Default::default()
                        }),
                        status: None
                   }
                }

                fn admission_webhook_configuration(service: k8s_openapi::api::core::v1::Service, secret: k8s_openapi::api::core::v1::Secret) -> anyhow::Result<k8s_openapi::api::admissionregistration::v1::MutatingWebhookConfiguration> {
                   let crd = #name_identifier::crd();

                   let webhook_name = format!("{}.{}", crd.spec.names.plural, crd.spec.group).to_string();
                   let versions: Vec<String> = crd.spec.versions.into_iter().map(|v| v.name).collect();

                   anyhow::ensure!(secret.type_ == Some("tls".to_string()), format!("secret with name {} is not a tls secret", secret.metadata.name.unwrap()));

                   // there must be a more elegant way to do this ... I gave up though
                   let mut ca_bundle = None;
                   if let Some(data) = secret.string_data {
                       if let Some(value) = data.get("tls.crt") {
                           ca_bundle = Some(k8s_openapi::ByteString(value.as_bytes().into()));
                       }
                   } else if let Some(data) = secret.data {
                      if let Some(value) = data.get("tls.crt") {
                          ca_bundle = Some(value.to_owned());
                      }
                   }

                   anyhow::ensure!(ca_bundle.is_some(), format!("secret with name {} is does not container data 'tls.crt'", secret.metadata.name.unwrap()));

                   Ok(k8s_openapi::api::admissionregistration::v1::MutatingWebhookConfiguration{
                       metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                           name: Some(webhook_name.clone()),
                           ..Default::default()
                       },
                       webhooks: Some(vec![k8s_openapi::api::admissionregistration::v1::MutatingWebhook{
                           admission_review_versions: versions.clone(),
                           name: webhook_name.clone(),
                           rules: Some(vec![k8s_openapi::api::admissionregistration::v1::RuleWithOperations{
                               api_groups: Some(vec![crd.spec.group]),
                               api_versions: Some(versions),
                               operations: Some(vec!["*".to_string()]),
                               resources: Some(vec![crd.spec.names.plural]),
                               scope: Some(crd.spec.scope)
                           }]),
                           client_config: k8s_openapi::api::admissionregistration::v1::WebhookClientConfig{
                               ca_bundle: ca_bundle,
                               service: Some(k8s_openapi::api::admissionregistration::v1::ServiceReference{
                                   name: service.metadata.name.unwrap(),
                                   namespace: service.metadata.namespace.unwrap(),
                                   ..Default::default()
                               }),
                               url: None
                           },
                           ..Default::default()
                       }])
                   })
                }
            }
        };

       Ok(gen.into())
    }
}


