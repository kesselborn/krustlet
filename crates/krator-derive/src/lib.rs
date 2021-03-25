//! A crate for deriving state machine traits in Kubelet. Right now this crate only consists of a
//! derive macro for the `TransitionTo` trait. In addition to the `derive` attribute, this macro
//! also requires the use of a custom attribute called `transition_to` that specifies the types that
//! can be transitioned to. Not specifying this attribute will result in a compile time error.
extern crate proc_macro;
use crate::proc_macro::TokenStream;
mod transitions;

#[proc_macro_derive(TransitionTo, attributes(transition_to))]
pub fn derive_transition_to(input: TokenStream) -> TokenStream {
    transitions::run_custom_derive(input)
}

#[cfg(feature = "admission-webhook")]
mod admission;

#[cfg(feature = "admission-webhook")]
#[proc_macro_derive(AdmissionWebhook)]
pub fn derive_admission_webhook(input: TokenStream) -> TokenStream {
    admission::run_custom_derive::<admission::CustomResourceInfos>(input)
}

