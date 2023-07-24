extern crate kubewarden_policy_sdk as kubewarden;

use guest::prelude::*;
use k8s_openapi::api::apps::v1 as apps;
use k8s_openapi::api::batch::v1 as batch;
use k8s_openapi::api::core::v1 as apicore;
use kubewarden::{logging, protocol_version_guest, request::ValidationRequest, validate_settings};
use kubewarden_policy_sdk::wapc_guest as guest;
use lazy_static::lazy_static;
use serde_json::Value;
use slog::{info, Logger, o, warn};

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
const NOT_A_WORKLOAD_ERROR: &str = "not a workload";

fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<Settings> = ValidationRequest::new(payload)?;
    let kind: String = validation_request.request.kind.kind;
    let object: Value = validation_request.request.object;

    return match extract_namespace(kind.clone(), object) {
        Ok(namespace) => {
            if namespace.is_empty() || namespace == DEFAULT_NAMESPACE {
                info!(LOG_DRAIN, "rejecting {} from 'default' namespace", kind);
                let message = format!("Kind {:?} can not be deployed to the 'default' namespace", kind);
                return kubewarden::reject_request(Some(message), None, None, None);
            }

            kubewarden::accept_request()
        }
        Err(err) => {
            if err == NOT_A_WORKLOAD_ERROR {
                return kubewarden::accept_request();
            }

            warn!(LOG_DRAIN, "rejecting invalid {} request: {}", kind, err);
            let message = Some(format!("Invalid {} request", kind));
            kubewarden::reject_request(message, Some(400), None, None)
        }
    }
}

fn extract_namespace(kind: String, object: Value) -> Result<String, String> {
    return match kind.as_ref() {
        "Pod" => serde_json::from_value::<apicore::Pod>(object).
            map(|pod| pod.metadata.namespace.unwrap_or_default()).
            map_err(|error| error.to_string()),

        "Job" => serde_json::from_value::<batch::Job>(object).
            map(|job| job.metadata.namespace.unwrap_or_default()).
            map_err(|error| error.to_string()),

        "Deployment" => serde_json::from_value::<apps::Deployment>(object).
            map(|deployment| deployment.metadata.namespace.unwrap_or_default()).
            map_err(|error| error.to_string()),

        "DaemonSet" => serde_json::from_value::<apps::DaemonSet>(object).
            map(|daemon_set| daemon_set.metadata.namespace.unwrap_or_default()).
            map_err(|error| error.to_string()),

        "StatefulSet" => serde_json::from_value::<apps::StatefulSet>(object).
            map(|stateful_set| stateful_set.metadata.namespace.unwrap_or_default()).
            map_err(|error| error.to_string()),

        _ => Err(NOT_A_WORKLOAD_ERROR.to_string())
    };
}

#[cfg(test)]
mod tests {
    use kubewarden_policy_sdk::test::Testcase;

    use super::*;

    #[test]
    fn accept_pod_with_custom_namespace() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_custom_namespace.json";
        let tc = Testcase {
            name: String::from("Pod creation with valid namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(res.mutated_object.is_none(), "Something mutated with test case: {}", tc.name);

        Ok(())
    }

    #[test]
    fn reject_pod_with_invalid_namespace() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_default_namespace.json";
        let tc = Testcase {
            name: String::from("Pod creation with default namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(res.mutated_object.is_none(), "Something mutated with test case: {}", tc.name);

        Ok(())
    }

    #[test]
    fn reject_pod_with_empty_namespace() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_empty_namespace.json";
        let tc = Testcase {
            name: String::from("Pod creation with empty namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(res.mutated_object.is_none(), "Something mutated with test case: {}", tc.name);

        Ok(())
    }

    #[test]
    fn accept_job_with_custom_namespace() -> Result<(), ()> {
        let request_file = "test_data/job_creation_custom_namespace.json";
        let tc = Testcase {
            name: String::from("Job creation with valid namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(res.mutated_object.is_none(), "Something mutated with test case: {}", tc.name);

        Ok(())
    }

    #[test]
    fn reject_job_with_invalid_namespace() -> Result<(), ()> {
        let request_file = "test_data/job_creation_default_namespace.json";
        let tc = Testcase {
            name: String::from("Job creation with default namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(res.mutated_object.is_none(), "Something mutated with test case: {}", tc.name);

        Ok(())
    }

    #[test]
    fn reject_job_with_empty_namespace() -> Result<(), ()> {
        let request_file = "test_data/job_creation_empty_namespace.json";
        let tc = Testcase {
            name: String::from("Job creation with empty namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(res.mutated_object.is_none(), "Something mutated with test case: {}", tc.name);

        Ok(())
    }

    #[test]
    fn accept_daemon_set_with_custom_namespace() -> Result<(), ()> {
        let request_file = "test_data/daemon_set_creation_custom_namespace.json";
        let tc = Testcase {
            name: String::from("Daemon set creation with valid namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(res.mutated_object.is_none(), "Something mutated with test case: {}", tc.name);

        Ok(())
    }

    #[test]
    fn reject_daemon_set_with_invalid_namespace() -> Result<(), ()> {
        let request_file = "test_data/daemon_set_creation_default_namespace.json";
        let tc = Testcase {
            name: String::from("Daemon set creation with default namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(res.mutated_object.is_none(), "Something mutated with test case: {}", tc.name);

        Ok(())
    }

    #[test]
    fn reject_daemon_set_with_empty_namespace() -> Result<(), ()> {
        let request_file = "test_data/daemon_set_creation_empty_namespace.json";
        let tc = Testcase {
            name: String::from("Daemon set creation with empty namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(res.mutated_object.is_none(), "Something mutated with test case: {}", tc.name);

        Ok(())
    }

    #[test]
    fn accept_stateful_set_with_custom_namespace() -> Result<(), ()> {
        let request_file = "test_data/stateful_set_creation_custom_namespace.json";
        let tc = Testcase {
            name: String::from("Stateful set creation with valid namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(res.mutated_object.is_none(), "Something mutated with test case: {}", tc.name);

        Ok(())
    }

    #[test]
    fn reject_stateful_set_with_invalid_namespace() -> Result<(), ()> {
        let request_file = "test_data/stateful_set_creation_default_namespace.json";
        let tc = Testcase {
            name: String::from("Stateful set creation with default namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(res.mutated_object.is_none(), "Something mutated with test case: {}", tc.name);

        Ok(())
    }

    #[test]
    fn reject_stateful_set_with_empty_namespace() -> Result<(), ()> {
        let request_file = "test_data/stateful_set_creation_empty_namespace.json";
        let tc = Testcase {
            name: String::from("Stateful set creation with empty namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(res.mutated_object.is_none(), "Something mutated with test case: {}", tc.name);

        Ok(())
    }

    #[test]
    fn accept_deployment_with_custom_namespace() -> Result<(), ()> {
        let request_file = "test_data/deployment_creation_custom_namespace.json";
        let tc = Testcase {
            name: String::from("Deployment creation with valid namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(res.mutated_object.is_none(), "Something mutated with test case: {}", tc.name);

        Ok(())
    }

    #[test]
    fn reject_deployment_with_invalid_namespace() -> Result<(), ()> {
        let request_file = "test_data/deployment_creation_default_namespace.json";
        let tc = Testcase {
            name: String::from("Deployment creation with default namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(res.mutated_object.is_none(), "Something mutated with test case: {}", tc.name);

        Ok(())
    }

    #[test]
    fn reject_deployment_with_empty_namespace() -> Result<(), ()> {
        let request_file = "test_data/deployment_creation_empty_namespace.json";
        let tc = Testcase {
            name: String::from("Deployment creation with empty namespace"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(res.mutated_object.is_none(), "Something mutated with test case: {}", tc.name);

        Ok(())
    }

    #[test]
    fn accept_request_with_non_pod_resource() -> Result<(), ()> {
        let request_file = "test_data/ingress_creation.json";
        let tc = Testcase {
            name: String::from("Ingress creation"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(res.mutated_object.is_none(), "Something mutated with test case: {}", tc.name);

        Ok(())
    }
}
