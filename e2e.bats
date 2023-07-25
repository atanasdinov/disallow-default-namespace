#!/usr/bin/env bats

@test "Accept a pod with custom namespace" {
	run kwctl run  --request-path test_data/pod_creation_custom_namespace.json  annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
 }

@test "Reject a pod with default namespace" {
	run kwctl run  --request-path test_data/pod_creation_default_namespace.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
	[ $(expr "$output" : '.*"message":"Kind .*Pod.* can not be deployed to the .default. namespace".*') -ne 0 ]
 }

@test "Reject a pod with empty namespace" {
	run kwctl run  --request-path test_data/pod_creation_empty_namespace.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
	[ $(expr "$output" : '.*"message":"Kind .*Pod.* can not be deployed to the .default. namespace".*') -ne 0 ]
 }

 @test "Accept a job with custom namespace" {
 	run kwctl run  --request-path test_data/job_creation_custom_namespace.json  annotated-policy.wasm
 	[ "$status" -eq 0 ]
 	echo "$output"
 	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
  }

 @test "Reject a job with default namespace" {
 	run kwctl run  --request-path test_data/job_creation_default_namespace.json annotated-policy.wasm
 	[ "$status" -eq 0 ]
 	echo "$output"
 	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
 	[ $(expr "$output" : '.*"message":"Kind .*Job.* can not be deployed to the .default. namespace".*') -ne 0 ]
  }

 @test "Reject a job with empty namespace" {
 	run kwctl run  --request-path test_data/job_creation_empty_namespace.json annotated-policy.wasm
 	[ "$status" -eq 0 ]
 	echo "$output"
 	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
 	[ $(expr "$output" : '.*"message":"Kind .*Job.* can not be deployed to the .default. namespace".*') -ne 0 ]
  }

  @test "Accept a deployment with custom namespace" {
  	run kwctl run  --request-path test_data/deployment_creation_custom_namespace.json  annotated-policy.wasm
  	[ "$status" -eq 0 ]
  	echo "$output"
  	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
   }

  @test "Reject a deployment with default namespace" {
  	run kwctl run  --request-path test_data/deployment_creation_default_namespace.json annotated-policy.wasm
  	[ "$status" -eq 0 ]
  	echo "$output"
  	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
  	[ $(expr "$output" : '.*"message":"Kind .*Deployment.* can not be deployed to the .default. namespace".*') -ne 0 ]
   }

  @test "Reject a deployment with empty namespace" {
  	run kwctl run  --request-path test_data/deployment_creation_empty_namespace.json annotated-policy.wasm
  	[ "$status" -eq 0 ]
  	echo "$output"
  	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
  	[ $(expr "$output" : '.*"message":"Kind .*Deployment.* can not be deployed to the .default. namespace".*') -ne 0 ]
   }

   @test "Accept a daemon set with custom namespace" {
   	run kwctl run  --request-path test_data/daemon_set_creation_custom_namespace.json  annotated-policy.wasm
   	[ "$status" -eq 0 ]
   	echo "$output"
   	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
    }

   @test "Reject a daemon set with default namespace" {
   	run kwctl run  --request-path test_data/daemon_set_creation_default_namespace.json annotated-policy.wasm
   	[ "$status" -eq 0 ]
   	echo "$output"
   	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
   	[ $(expr "$output" : '.*"message":"Kind .*DaemonSet.* can not be deployed to the .default. namespace".*') -ne 0 ]
    }

   @test "Reject a daemon set with empty namespace" {
   	run kwctl run  --request-path test_data/daemon_set_creation_empty_namespace.json annotated-policy.wasm
   	[ "$status" -eq 0 ]
   	echo "$output"
   	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
   	[ $(expr "$output" : '.*"message":"Kind .*DaemonSet.* can not be deployed to the .default. namespace".*') -ne 0 ]
    }

   @test "Accept a stateful set with custom namespace" {
   	run kwctl run  --request-path test_data/stateful_set_creation_custom_namespace.json  annotated-policy.wasm
   	[ "$status" -eq 0 ]
   	echo "$output"
   	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
    }

   @test "Reject a stateful set with default namespace" {
   	run kwctl run  --request-path test_data/stateful_set_creation_default_namespace.json annotated-policy.wasm
   	[ "$status" -eq 0 ]
   	echo "$output"
   	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
   	[ $(expr "$output" : '.*"message":"Kind .*StatefulSet.* can not be deployed to the .default. namespace".*') -ne 0 ]
    }

   @test "Reject a stateful set with empty namespace" {
   	run kwctl run  --request-path test_data/stateful_set_creation_empty_namespace.json annotated-policy.wasm
   	[ "$status" -eq 0 ]
   	echo "$output"
   	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
   	[ $(expr "$output" : '.*"message":"Kind .*StatefulSet.* can not be deployed to the .default. namespace".*') -ne 0 ]
    }

   @test "Accept a non-workload resource" {
   	run kwctl run  --request-path test_data/ingress_creation.json  annotated-policy.wasm
   	[ "$status" -eq 0 ]
   	echo "$output"
   	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
    }