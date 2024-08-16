// Copyright (c) 2024 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
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

type ComplianceEngine string

type Framework string

// CCSFrameworkSpec defines the desired state of CCSFramework
type CCSFrameworkSpec struct {

	// Engine is the compliance engine to use.
	// +kubebuilder:validation:Items:=Enum=kubescape
	Engine ComplianceEngine `json:"engine"`

	// Controls is a list of controls to evaluate.
	Controls []Control `json:"controls"`

	// Builtin is the built-in framework for compliance engine to use.
	// Controls will be ignored if this is set.
	// +kubebuilder:validation:Items:=Enum=MITRE,NSA,CIS
	BuiltIn Framework `json:"builtin"`

	// ExcludeNamespaces is a list of namespaces to exclude from evaluation.
	ExcludeNamespaces []string `json:"excludeNamespaces,omitempty" validate:"omitempty,dive,min=1"`

	// Frequency is the frequency at which to run the compliance checks.
	Frequency metav1.Duration `json:"duration,omitempty" validate:"required" default:"24h"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// CCSFramework is the Schema for the ccsreports API
type CCSFramework struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec CCSFrameworkSpec `json:"spec,omitempty"`
}

type Control struct {
	// Unique identifier for the control.
	ID string `json:"id" validate:"required"`
}

//+kubebuilder:object:root=true

// CCSReportList contains a list of CCSReport
type CCSReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CCSFramework `json:"items"`
}
