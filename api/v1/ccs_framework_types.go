// Copyright (c) 2024 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BuiltInFrameworkName is the built-in framework for ccs engine to use.
// +kubebuilder:validation:Enum=MITRE,NSA,SOC2,cis-aks-t1.2.0,cis-eks-t1.2.0, cis-v1.23-t1.0.1
type BuiltInFrameworkName string

const (
	MITREFramework  BuiltInFrameworkName = "MITRE"
	NSAFramework    BuiltInFrameworkName = "NSA"
	SOC2Framework   BuiltInFrameworkName = "SOC2"
	CISFrameworkAKS BuiltInFrameworkName = "cis-aks-t1.2.0"
	CISFrameworkEKS BuiltInFrameworkName = "cis-eks-t1.2.0"
	CISFramework    BuiltInFrameworkName = "cis-v1.23-t1.0.1"
)

// ExcludedNamespace is a namespace name to be excluded from image scanning.
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=63
// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
type ExcludedNamespace string

type Control struct {
	// Unique identifier for the control.
	// TBD: Contro ID regex enforcement.
	ID string `json:"id" validate:"required"`
}

type BuiltInFramework struct {
	// Builtin is the built-in framework for ccs engine to use.
	// If controls are set along with this the API will reject the input.
	Name BuiltInFrameworkName `json:"name"`

	// ExcludedControls is a list of controls to exclude from evaluation.
	ExcludeControls []Control `json:"excludeControls,omitempty"`
}

// CustomFramework allows the user to define their own controls.
type CustomFramework struct {
	// Controls is a list of custom controls to evaluate.
	Controls []Control `json:"controls"`
}

// FrameworkSpec defines the desired state of the CCSFramework.
type FrameworkSpec struct {
	// DisplayId is the identifier shown in the UI.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	DisplayId string `json:"displayId"`

	// Builtin is the built-in framework for CCS engine to use.
	// If this is set, custom cannot be set.
	BuiltIn *BuiltInFramework `json:"builtin,omitempty"`

	// Custom is the custom framework for CCS engine to use.
	// If this is set, builtin cannot be set.
	Custom *CustomFramework `json:"custom,omitempty"`

	// ExcludeNamespaces is a list of namespaces to exclude from evaluation.
	ExcludeNamespaces []ExcludedNamespace `json:"excludeNamespaces,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Framework is the Schema for the framework API
type Framework struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec FrameworkSpec `json:"spec,omitempty"`
}

//+kubebuilder:object:root=true

// FrameworkList contains a list of Framework
type FrameworkList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Framework `json:"items"`
}
