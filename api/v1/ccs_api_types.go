// Copyright (c) 2024 Tigera, Inc. All rights reserved.
/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in CCS with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	v1 "k8s.io/api/core/v1"
)

// CCSAPIDeployment is the configuration for the CCS controller Deployment.
type CCSAPIDeployment struct {

	// Spec is the specification of the CCS controller Deployment.
	// +optional
	Spec *CCSAPIDeploymentSpec `json:"spec,omitempty"`
}

// CCSAPIDeploymentSpec defines configuration for the CCS controller Deployment.
type CCSAPIDeploymentSpec struct {

	// Template describes the CCS controller Deployment pod that will be created.
	// +optional
	Template *CCSAPIDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// CCSAPIDeploymentPodTemplateSpec is the CCS controller Deployment's PodTemplateSpec
type CCSAPIDeploymentPodTemplateSpec struct {

	// Spec is the CCS controller Deployment's PodSpec.
	// +optional
	Spec *CCSAPIDeploymentPodSpec `json:"spec,omitempty"`
}

// CCSAPIDeploymentPodSpec is the CCS controller Deployment's PodSpec.
type CCSAPIDeploymentPodSpec struct {
	// Containers is a list of CCS controller containers.
	// If specified, this overrides the specified CCS controller Deployment containers.
	// If omitted, the CCS controller Deployment will use its default values for its containers.
	// +optional
	Containers []CCSAPIDeploymentContainer `json:"containers,omitempty"`
}

// CCSAPIDeploymentContainer is a CCS controller Deployment container.
type CCSAPIDeploymentContainer struct {
	// Name is an enum which identifies the CCS controller Deployment container by name.
	// Supported values are: ccs-api
	// +kubebuilder:validation:Enum=ccs-api
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named CCS controller Deployment container's resources.
	// If omitted, the CCS controller Deployment will use its default value for this container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}
