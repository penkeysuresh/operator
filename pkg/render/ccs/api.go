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
	"k8s.io/apimachinery/pkg/util/intstr"

	calicov3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/operator/pkg/render"
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	APIResourceName   = "tigera-ccs-api"
	APICertSecretName = "tigera-ccs-api-tls"
)

func (c *ccsComponent) apiServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: APIResourceName, Namespace: c.cfg.Namespace},
	}
}

func (c *ccsComponent) apiRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta:   metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: APIResourceName, Namespace: c.cfg.Namespace},
		Rules:      []rbacv1.PolicyRule{},
	}
}

func (c *ccsComponent) apiRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: APIResourceName, Namespace: c.cfg.Namespace},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     APIResourceName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      APIResourceName,
				Namespace: c.cfg.Namespace,
			},
		},
	}
}

func (c *ccsComponent) apiDeployment() *appsv1.Deployment {
	var keyPath, certPath string
	if c.cfg.APIKeyPair != nil {
		keyPath, certPath = c.cfg.APIKeyPair.VolumeMountKeyFilePath(), c.cfg.APIKeyPair.VolumeMountCertificateFilePath()
	}

	envVars := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "info"},
		{Name: "HTTPS_ENABLED", Value: "true"},
		{Name: "HTTPS_CERT", Value: certPath},
		{Name: "HTTPS_KEY", Value: keyPath},
		{Name: "LINSEED_URL", Value: "https://tigera-linseed.tigera-elasticsearch.svc"},
		{Name: "LINSEED_CA", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
		{Name: "LINSEED_CLIENT_CERT", Value: certPath},
		{Name: "LINSEED_CLIENT_KEY", Value: keyPath},
		{Name: "LINSEED_TOKEN", Value: render.GetLinseedTokenPath(c.cfg.ManagementClusterConnection != nil)},
		{Name: "MULTI_CLUSTER_FORWARDING_CA", Value: certificatemanagement.TrustedCertBundleMountPath},
	}

	if c.cfg.Tenant != nil {
		// Configure the tenant id in order to read /write linseed data using the correct tenant ID
		// Multi-tenant and single tenant with external elastic needs this variable set
		if c.cfg.ExternalElastic {
			envVars = append(envVars, corev1.EnvVar{Name: "TENANT_ID", Value: c.cfg.Tenant.Spec.ID})
		}
		if c.cfg.Tenant.MultiTenant() {
			envVars = append(envVars, corev1.EnvVar{Name: "TENANT_NAMESPACE", Value: c.cfg.Tenant.Namespace})
			envVars = append(envVars, corev1.EnvVar{Name: "LINSEED_URL", Value: fmt.Sprintf("https://tigera-linseed.%s.svc", c.cfg.Tenant.Namespace)})
			envVars = append(envVars, corev1.EnvVar{Name: "MULTI_CLUSTER_FORWARDING_ENDPOINT", Value: render.ManagerService(c.cfg.Tenant)})
		}
	}

	annots := c.cfg.TrustedBundle.HashAnnotations()
	if c.cfg.APIKeyPair != nil {
		annots[c.cfg.APIKeyPair.HashAnnotationKey()] = c.cfg.APIKeyPair.HashAnnotationValue()
	}

	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:        APIResourceName,
			Namespace:   c.cfg.Namespace,
			Labels:      map[string]string{"k8s-app": APIResourceName},
			Annotations: annots,
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: APIResourceName,
			NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
			ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
			Containers: []corev1.Container{
				{
					Name:            APIResourceName,
					Image:           "gcr.io/unique-caldron-775/suresh/ccs-api:demo-v1.1", // TODO c.apiImage,
					ImagePullPolicy: render.ImagePullPolicy(),
					Env:             envVars,
					Ports:           []corev1.ContainerPort{{ContainerPort: 5557}},
					SecurityContext: securitycontext.NewNonRootContext(),
					VolumeMounts: append(
						c.cfg.TrustedBundle.VolumeMounts(c.SupportedOSType()),
						c.cfg.APIKeyPair.VolumeMount(c.SupportedOSType()),
					),
				},
			},
			RestartPolicy: corev1.RestartPolicyAlways,
			Volumes: []corev1.Volume{
				c.cfg.APIKeyPair.Volume(),
				c.cfg.TrustedBundle.Volume(),
			},
		},
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      APIResourceName,
			Namespace: c.cfg.Namespace,
			Labels:    map[string]string{"k8s-app": APIResourceName},
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"k8s-app": APIResourceName},
			},
			Template: *podTemplate,
		},
	}

	if c.cfg.ComplianceConfigurationSecurity != nil {
		if overrides := c.cfg.ComplianceConfigurationSecurity.Spec.CCSAPIDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(d, overrides)
		}
	}

	return d
}

func (c *ccsComponent) apiService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      APIResourceName,
			Namespace: c.cfg.Namespace,
			Labels:    map[string]string{"k8s-app": APIResourceName},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": APIResourceName},
			Ports: []corev1.ServicePort{
				{
					Protocol:   corev1.ProtocolTCP,
					Port:       80,
					TargetPort: intstr.FromInt32(5557),
				},
			},
			Type: corev1.ServiceTypeClusterIP,
		},
	}
}

func (c *ccsComponent) apiAllowTigeraNetworkPolicy() *calicov3.NetworkPolicy {
	return nil
}
