// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

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

package ccs

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	calicov3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/tigera/operator/pkg/render"
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
)

const ControllerResourceName = "tigera-ccs-controller"

func (c *ccsComponent) controllerServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ControllerResourceName, Namespace: c.cfg.Namespace},
	}
}

func (c *ccsComponent) controllerRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta:   metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ControllerResourceName, Namespace: c.cfg.Namespace},
		Rules:      []rbacv1.PolicyRule{},
	}
}

func (c *ccsComponent) controllerRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ControllerResourceName, Namespace: c.cfg.Namespace},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     ControllerResourceName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      ControllerResourceName,
				Namespace: c.cfg.Namespace,
			},
		},
	}
}

func ccsControllerDP() *appsv1.Deployment {
	return nil
}

func (c *ccsComponent) controllerDeployment() *appsv1.Deployment {
	var certPath string
	if c.cfg.APIKeyPair != nil {
		certPath = c.cfg.APIKeyPair.VolumeMountCertificateFilePath()
	}

	envVars := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "info"},
		{Name: "CCS_API_CA", Value: certPath},
		{Name: "CCS_API_URL", Value: "https://tigera-ccs-api.tigera-ccs.svc"},
	}

	if c.cfg.Tenant != nil && c.cfg.Tenant.MultiTenant() {
		envVars = append(envVars, corev1.EnvVar{Name: "CCS_API_URL", Value: fmt.Sprintf("https://tigera-ccs-api.%s.svc", c.cfg.Tenant.Namespace)})
	}

	annots := c.cfg.TrustedBundle.HashAnnotations()
	if c.cfg.APIKeyPair != nil {
		annots[c.cfg.APIKeyPair.HashAnnotationKey()] = c.cfg.APIKeyPair.HashAnnotationValue()
	}

	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:        ControllerResourceName,
			Namespace:   c.cfg.Namespace,
			Labels:      map[string]string{"k8s-app": APIResourceName},
			Annotations: annots,
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: ControllerResourceName,
			NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
			ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
			Containers: []corev1.Container{
				{
					Name:            ControllerResourceName,
					Image:           "gcr.io/unique-caldron-775/suresh/ccs-controller:demo-v1", // TODO c.controllerImage,
					ImagePullPolicy: render.ImagePullPolicy(),
					Env:             envVars,
					SecurityContext: securitycontext.NewNonRootContext(),
					VolumeMounts: append(
						c.cfg.TrustedBundle.VolumeMounts(c.SupportedOSType()),
						c.cfg.APIKeyPair.VolumeMount(c.SupportedOSType()),
					)},
			},
			Volumes: []corev1.Volume{
				c.cfg.APIKeyPair.Volume(),
				c.cfg.TrustedBundle.Volume(),
			}},
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ControllerResourceName,
			Namespace: c.cfg.Namespace,
			Labels:    map[string]string{"k8s-app": ControllerResourceName},
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"k8s-app": ControllerResourceName},
			},
			Template: *podTemplate,
		},
	}

	if c.cfg.ComplianceConfigurationSecurity != nil {
		if overrides := c.cfg.ComplianceConfigurationSecurity.Spec.CCSControllerDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(d, overrides)
		}
	}
	return d
}

func (c *ccsComponent) controllerAllowTigeraNetworkPolicy() *calicov3.NetworkPolicy {
	return nil
}
