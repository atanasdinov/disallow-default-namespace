extern crate kubewarden_policy_sdk as kubewarden;

use guest::prelude::*;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, StatefulSet};
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::Pod;
use kubewarden::{logging, protocol_version_guest, request::ValidationRequest, validate_settings};
use kubewarden_policy_sdk::wapc_guest as guest;
use lazy_static::lazy_static;
use serde::de::DeserializeOwned;
use serde_json::Value;
use slog::{info, o, warn, Logger};

use settings::Settings;

mod settings;

lazy_static! {
    static ref LOG_DRAIN: Logger = Logger::root(
        logging::KubewardenDrain::new(),
        o!("policy" => "disallow-default-namespace")
    );
}

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<Settings>);
    register_function("protocol_version", protocol_version_guest);
}

const DEFAULT_NAMESPACE: &str = "default";

trait Resource {
    fn namespace(&self) -> String;
}

impl Resource for Pod {
    fn namespace(&self) -> String {
        self.metadata.namespace.clone().unwrap_or_default()
    }
}

impl Resource for Job {
    fn namespace(&self) -> String {
        self.metadata.namespace.clone().unwrap_or_default()
    }
}

impl Resource for Deployment {
    fn namespace(&self) -> String {
        self.metadata.namespace.clone().unwrap_or_default()
    }
}

impl Resource for DaemonSet {
    fn namespace(&self) -> String {
        self.metadata.namespace.clone().unwrap_or_default()
    }
}

impl Resource for StatefulSet {
    fn namespace(&self) -> String {
        self.metadata.namespace.clone().unwrap_or_default()
    }
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<Settings> = ValidationRequest::new(payload)?;
    let kind: String = validation_request.request.kind.kind;
    let object: Value = validation_request.request.object;

    return match kind.as_ref() {
        "Pod" => validate_resource::<Pod>(kind, object),
        "Job" => validate_resource::<Job>(kind, object),
        "Deployment" => validate_resource::<Deployment>(kind, object),
        "DaemonSet" => validate_resource::<DaemonSet>(kind, object),
        "StatefulSet" => validate_resource::<StatefulSet>(kind, object),
        _ => kubewarden::accept_request(), // non-workload resource
    };
}

fn validate_resource<T: Resource + DeserializeOwned>(kind: String, object: Value) -> CallResult {
    match serde_json::from_value::<T>(object) {
        Ok(resource) => {
            let namespace: String = resource.namespace();

            if namespace.is_empty() || namespace == DEFAULT_NAMESPACE {
                info!(LOG_DRAIN, "rejecting {} from 'default' namespace", kind);
                let message = format!(
                    "Kind {:?} can not be deployed to the 'default' namespace",
                    kind
                );
                return kubewarden::reject_request(Some(message), None, None, None);
            }

            kubewarden::accept_request()
        }
        Err(err) => {
            warn!(LOG_DRAIN, "rejecting invalid {} request: {}", kind, err);
            let message = Some(format!("Invalid {} request", kind));
            kubewarden::reject_request(message, Some(400), None, None)
        }
    }
}

#[cfg(test)]
mod tests {
    use kubewarden_policy_sdk::test::Testcase;

    use super::*;

    #[test]
    fn accept_pod_with_custom_namespace() {
        let request_file = "test_data/pod_creation_custom_namespace.json";
        let tc = Testcase {
            name: String::from("Pod creation with valid namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name
        );
    }

    #[test]
    fn reject_pod_with_invalid_namespace() {
        let request_file = "test_data/pod_creation_default_namespace.json";
        let tc = Testcase {
            name: String::from("Pod creation with default namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name
        );
    }

    #[test]
    fn reject_pod_with_empty_namespace() {
        let request_file = "test_data/pod_creation_empty_namespace.json";
        let tc = Testcase {
            name: String::from("Pod creation with empty namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name
        );
    }

    #[test]
    fn accept_job_with_custom_namespace() {
        let request_file = "test_data/job_creation_custom_namespace.json";
        let tc = Testcase {
            name: String::from("Job creation with valid namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name
        );
    }

    #[test]
    fn reject_job_with_invalid_namespace() {
        let request_file = "test_data/job_creation_default_namespace.json";
        let tc = Testcase {
            name: String::from("Job creation with default namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name
        );
    }

    #[test]
    fn reject_job_with_empty_namespace() {
        let request_file = "test_data/job_creation_empty_namespace.json";
        let tc = Testcase {
            name: String::from("Job creation with empty namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name
        );
    }

    #[test]
    fn accept_daemon_set_with_custom_namespace() {
        let request_file = "test_data/daemon_set_creation_custom_namespace.json";
        let tc = Testcase {
            name: String::from("Daemon set creation with valid namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name
        );
    }

    #[test]
    fn reject_daemon_set_with_invalid_namespace() {
        let request_file = "test_data/daemon_set_creation_default_namespace.json";
        let tc = Testcase {
            name: String::from("Daemon set creation with default namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name
        );
    }

    #[test]
    fn reject_daemon_set_with_empty_namespace() {
        let request_file = "test_data/daemon_set_creation_empty_namespace.json";
        let tc = Testcase {
            name: String::from("Daemon set creation with empty namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name
        );
    }

    #[test]
    fn accept_stateful_set_with_custom_namespace() {
        let request_file = "test_data/stateful_set_creation_custom_namespace.json";
        let tc = Testcase {
            name: String::from("Stateful set creation with valid namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name
        );
    }

    #[test]
    fn reject_stateful_set_with_invalid_namespace() {
        let request_file = "test_data/stateful_set_creation_default_namespace.json";
        let tc = Testcase {
            name: String::from("Stateful set creation with default namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name
        );
    }

    #[test]
    fn reject_stateful_set_with_empty_namespace() {
        let request_file = "test_data/stateful_set_creation_empty_namespace.json";
        let tc = Testcase {
            name: String::from("Stateful set creation with empty namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name
        );
    }

    #[test]
    fn accept_deployment_with_custom_namespace() {
        let request_file = "test_data/deployment_creation_custom_namespace.json";
        let tc = Testcase {
            name: String::from("Deployment creation with valid namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name
        );
    }

    #[test]
    fn reject_deployment_with_invalid_namespace() {
        let request_file = "test_data/deployment_creation_default_namespace.json";
        let tc = Testcase {
            name: String::from("Deployment creation with default namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name
        );
    }

    #[test]
    fn reject_deployment_with_empty_namespace() {
        let request_file = "test_data/deployment_creation_empty_namespace.json";
        let tc = Testcase {
            name: String::from("Deployment creation with empty namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name
        );
    }

    #[test]
    fn accept_request_with_non_pod_resource() {
        let request_file = "test_data/ingress_creation.json";
        let tc = Testcase {
            name: String::from("Ingress creation"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name
        );
    }
}
