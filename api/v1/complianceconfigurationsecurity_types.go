// Copyright (c) 2024 Tigera, Inc. All rights reserved.
/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ComplianceConfigurationSecuritySpec defines the desired state of ComplianceConfigurationSecurity
type ComplianceConfigurationSecuritySpec struct {
}

// ComplianceConfigurationSecurityStatus defines the observed state of ComplianceConfigurationSecurity
type ComplianceConfigurationSecurityStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// ComplianceConfigurationSecurity is the Schema for the complianceconfigurationsecurities API
type ComplianceConfigurationSecurity struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ComplianceConfigurationSecuritySpec   `json:"spec,omitempty"`
	Status ComplianceConfigurationSecurityStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ComplianceConfigurationSecurityList contains a list of ComplianceConfigurationSecurity
type ComplianceConfigurationSecurityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ComplianceConfigurationSecurity `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ComplianceConfigurationSecurity{}, &ComplianceConfigurationSecurityList{})
}
