//! Exposes an API for creating state-machine-based Kubernetes Operators.
//!
//! See [krator_derive::AdmissionWebhook] for some useful macros when planning to provide an admission webhook

#![deny(missing_docs)]

mod manifest;
mod object;
mod operator;
mod runtime;

#[cfg(feature = "admission-webhook")]
pub mod admission;

pub mod state;

pub use manifest::Manifest;
pub use object::{ObjectState, ObjectStatus};
pub use operator::Operator;
pub use runtime::OperatorRuntime;
pub use state::{SharedState, State, Transition, TransitionTo};

#[cfg(feature = "derive")]
#[allow(unused_imports)]
#[macro_use]
extern crate krator_derive;

#[cfg(feature = "derive")]
#[doc(hidden)]
pub use krator_derive::*;
