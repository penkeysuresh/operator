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
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/authentication"
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	"github.com/tigera/operator/pkg/render/common/configmap"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/pkg/tls/certkeyusage"
)

const (
	CcsNamespace = "tigera-ccs"

	ComplianceServerName                                      = "compliance-server"
	ComplianceControllerName                                  = "compliance-controller"
	ComplianceSnapshotterName                                 = "compliance-snapshotter"
	ComplianceReporterName                                    = "compliance-reporter"
	ComplianceBenchmarkerName                                 = "compliance-benchmarker"
	ComplianceAccessPolicyName                                = networkpolicy.TigeraComponentPolicyPrefix + "compliance-access"
	ComplianceServerPolicyName                                = networkpolicy.TigeraComponentPolicyPrefix + ComplianceServerName
	MultiTenantComplianceManagedClustersAccessRoleBindingName = "compliance-server-managed-cluster-access"

	// ServiceAccount names.
	ComplianceServerServiceAccount      = "tigera-compliance-server"
	ComplianceSnapshotterServiceAccount = "tigera-compliance-snapshotter"
	ComplianceBenchmarkerServiceAccount = "tigera-compliance-benchmarker"
	ComplianceReporterServiceAccount    = "tigera-compliance-reporter"
	ComplianceControllerServiceAccount  = "tigera-compliance-controller"
)

const (
	ElasticsearchCuratorUserSecret = "tigera-ee-curator-elasticsearch-access"

	ComplianceServerCertSecret  = "tigera-compliance-server-tls"
	ComplianceSnapshotterSecret = "tigera-compliance-snapshotter-tls"
	ComplianceBenchmarkerSecret = "tigera-compliance-benchmarker-tls"
	ComplianceControllerSecret  = "tigera-compliance-controller-tls"
	ComplianceReporterSecret    = "tigera-compliance-reporter-tls"
)

// Register secret/certs that need Server and Client Key usage
func init() {
	certkeyusage.SetCertKeyUsage(ComplianceServerCertSecret, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
	certkeyusage.SetCertKeyUsage(ComplianceSnapshotterSecret, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
	certkeyusage.SetCertKeyUsage(ComplianceBenchmarkerSecret, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
	certkeyusage.SetCertKeyUsage(ComplianceReporterSecret, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
}

func CCS(cfg *Configuration) (render.Component, error) {
	return &ccsComponent{
		cfg: cfg,
	}, nil
}

// ComplianceConfiguration contains all the config information needed to render the component.
type Configuration struct {
	Installation                *operatorv1.InstallationSpec
	PullSecrets                 []*corev1.Secret
	OpenShift                   bool
	ManagementCluster           *operatorv1.ManagementCluster
	ManagementClusterConnection *operatorv1.ManagementClusterConnection
	KeyValidatorConfig          authentication.KeyValidatorConfig
	ClusterDomain               string
	HasNoLicense                bool

	// Trusted certificate bundle for all compliance pods.
	TrustedBundle certificatemanagement.TrustedBundleRO

	// Key pairs used for mTLS.
	ServerKeyPair      certificatemanagement.KeyPairInterface
	BenchmarkerKeyPair certificatemanagement.KeyPairInterface
	ReporterKeyPair    certificatemanagement.KeyPairInterface
	SnapshotterKeyPair certificatemanagement.KeyPairInterface
	ControllerKeyPair  certificatemanagement.KeyPairInterface

	Namespace         string
	BindingNamespaces []string

	// Whether to run the rendered components in multi-tenant, single-tenant, or zero-tenant mode
	Tenant                          *operatorv1.Tenant
	ExternalElastic                 bool
	ComplianceConfigurationSecurity *operatorv1.ComplianceConfigurationSecurity
}

type ccsComponent struct {
	cfg             *Configuration
	serverImage     string
	controllerImage string
	//benchmarkerImage string
	//snapshotterImage string
	//reporterImage    string
}

func (c *ccsComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix

	var err error
	errMsgs := []string{}
	c.serverImage, err = components.GetReference(components.ComponentComplianceServer, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	c.controllerImage, err = components.GetReference(components.ComponentComplianceController, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf("%s", strings.Join(errMsgs, ","))
	}
	return nil
}

func (c *ccsComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *ccsComponent) Objects() ([]client.Object, []client.Object) {
	var complianceObjs []client.Object
	if c.cfg.Tenant.MultiTenant() {
		complianceObjs = append(complianceObjs,
			// We always need a sa and crb, whether a deployment of compliance-server is present or not.
			// These two are used for rbac checks for managed clusters.
			c.complianceServerServiceAccount(),
			c.complianceServerClusterRoleBinding(),
		)
		complianceObjs = append(complianceObjs, c.multiTenantManagedClustersAccess()...)
		// We need to bind compliance components that run inside the managed cluster
		// to have the correct RBAC for linseed API
		complianceObjs = append(complianceObjs,
			c.complianceControllerClusterRole(),
			c.complianceControllerClusterRoleBinding(),
		)
	} else {
		complianceObjs = append(complianceObjs,
			c.complianceAccessAllowTigeraNetworkPolicy(),
			networkpolicy.AllowTigeraDefaultDeny(c.cfg.Namespace),
		)
		complianceObjs = append(complianceObjs, secret.ToRuntimeObjects(secret.CopyToNamespace(c.cfg.Namespace, c.cfg.PullSecrets...)...)...)
		complianceObjs = append(complianceObjs,
			c.complianceControllerServiceAccount(),
			c.complianceControllerRole(),
			c.complianceControllerClusterRole(),
			c.complianceControllerRoleBinding(),
			c.complianceControllerClusterRoleBinding(),
			c.complianceControllerDeployment(),

			// We always need a sa and crb, whether a deployment of compliance-server is present or not.
			// These two are used for rbac checks for managed clusters.
			c.complianceServerServiceAccount(),
			c.complianceServerClusterRoleBinding(),
		)
	}

	if c.cfg.KeyValidatorConfig != nil {
		complianceObjs = append(complianceObjs, secret.ToRuntimeObjects(c.cfg.KeyValidatorConfig.RequiredSecrets(c.cfg.Namespace)...)...)
		complianceObjs = append(complianceObjs, configmap.ToRuntimeObjects(c.cfg.KeyValidatorConfig.RequiredConfigMaps(c.cfg.Namespace)...)...)
	}

	var objsToDelete []client.Object
	if c.cfg.ManagementClusterConnection == nil {
		complianceObjs = append(complianceObjs,
			c.complianceServerAllowTigeraNetworkPolicy(),
			c.complianceServerClusterRole(),
			c.complianceServerService(),
			c.complianceServerDeployment(),
		)
	} else {
		// Compliance server is only for Standalone or Management clusters
		objsToDelete = append(objsToDelete, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: ComplianceServerName, Namespace: c.cfg.Namespace}})
		complianceObjs = append(complianceObjs,
			c.complianceServerManagedClusterRole(),
			c.externalLinseedRoleBinding(),
		)
	}

	// Need to grant cluster admin permissions in DockerEE to the controller since a pod starting pods with
	// host path volumes requires cluster admin permissions.
	if c.cfg.Installation.KubernetesProvider.IsDockerEE() && !c.cfg.Tenant.MultiTenant() {
		complianceObjs = append(complianceObjs, c.complianceControllerClusterAdminClusterRoleBinding())
	}

	if c.cfg.HasNoLicense {
		return nil, complianceObjs
	}

	return complianceObjs, objsToDelete
}

func (c *ccsComponent) Ready() bool {
	return true
}

var (
	complianceReplicas int32 = 1
)

const complianceServerPort = 5443

func (c *ccsComponent) complianceControllerServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ComplianceControllerServiceAccount, Namespace: c.cfg.Namespace},
	}
}

func (c *ccsComponent) complianceControllerRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta:   metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ComplianceControllerServiceAccount, Namespace: c.cfg.Namespace},
		Rules:      []rbacv1.PolicyRule{},
	}
}

func (c *ccsComponent) complianceControllerClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ComplianceControllerServiceAccount},
		Rules:      []rbacv1.PolicyRule{},
	}
}

func (c *ccsComponent) complianceControllerRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ComplianceControllerServiceAccount, Namespace: c.cfg.Namespace},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     ComplianceControllerServiceAccount,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      ComplianceControllerServiceAccount,
				Namespace: c.cfg.Namespace,
			},
		},
	}
}

func (c *ccsComponent) complianceControllerClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return rcomponents.ClusterRoleBinding(ComplianceControllerServiceAccount, ComplianceControllerServiceAccount, ComplianceControllerServiceAccount, c.cfg.BindingNamespaces)
}

// This clusterRoleBinding is only needed in DockerEE since a pod starting pods with host path volumes requires cluster admin permissions.
func (c *ccsComponent) complianceControllerClusterAdminClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-compliance-controller-cluster-admin"},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "cluster-admin",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      ComplianceControllerServiceAccount,
				Namespace: c.cfg.Namespace,
			},
		},
	}
}

func (c *ccsComponent) complianceControllerDeployment() *appsv1.Deployment {
	var keyPath, certPath string
	if c.cfg.ControllerKeyPair != nil {
		// This should never be nil, but we check it anyway just to be safe.
		keyPath, certPath = c.cfg.ControllerKeyPair.VolumeMountKeyFilePath(), c.cfg.ControllerKeyPair.VolumeMountCertificateFilePath()
	}

	volumes := []corev1.Volume{
		c.cfg.ControllerKeyPair.Volume(),
		c.cfg.TrustedBundle.Volume(),
	}
	volumeMounts := append(c.cfg.TrustedBundle.VolumeMounts(c.SupportedOSType()), c.cfg.ControllerKeyPair.VolumeMount(c.SupportedOSType()))
	if c.cfg.ManagementClusterConnection != nil {
		// For managed clusters, we need to mount the token for Linseed access.
		volumes = append(volumes,
			corev1.Volume{
				Name: render.LinseedTokenVolumeName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: fmt.Sprintf(render.LinseedTokenSecret, ComplianceControllerServiceAccount),
						Items:      []corev1.KeyToPath{{Key: render.LinseedTokenKey, Path: render.LinseedTokenSubPath}},
					},
				},
			})
		volumeMounts = append(volumeMounts,
			corev1.VolumeMount{
				Name:      render.LinseedTokenVolumeName,
				MountPath: render.LinseedVolumeMountPath,
			})
	}

	envVars := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "info"},
		{Name: "TIGERA_COMPLIANCE_JOB_NAMESPACE", Value: c.cfg.Namespace},
		{Name: "TIGERA_COMPLIANCE_MAX_FAILED_JOBS_HISTORY", Value: "3"},
		{Name: "TIGERA_COMPLIANCE_MAX_JOB_RETRIES", Value: "6"},
		{Name: "LINSEED_CLIENT_CERT", Value: certPath},
		{Name: "LINSEED_CLIENT_KEY", Value: keyPath},
		{Name: "LINSEED_TOKEN", Value: render.GetLinseedTokenPath(c.cfg.ManagementClusterConnection != nil)},
	}
	if c.cfg.Tenant != nil {
		// Configure the tenant id in order to read /write linseed data using the correct tenant ID
		// Multi-tenant and single tenant with external elastic needs this variable set
		if c.cfg.ExternalElastic {
			envVars = append(envVars, corev1.EnvVar{Name: "TENANT_ID", Value: c.cfg.Tenant.Spec.ID})
		}
	}

	var initContainers []corev1.Container
	if c.cfg.ControllerKeyPair != nil && c.cfg.ControllerKeyPair.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.ControllerKeyPair.InitContainer(c.cfg.Namespace))
	}

	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ComplianceControllerName,
			Namespace: c.cfg.Namespace,
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: ComplianceControllerServiceAccount,
			Tolerations:        tolerations,
			NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
			ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
			InitContainers:     initContainers,
			Containers: []corev1.Container{
				{
					Name:            ComplianceControllerName,
					Image:           c.controllerImage,
					ImagePullPolicy: render.ImagePullPolicy(),
					Env:             envVars,
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Path: "/liveness",
								Port: intstr.FromInt(9099),
							},
						},
					},
					SecurityContext: securitycontext.NewNonRootContext(),
					VolumeMounts:    volumeMounts,
				},
			},
			Volumes: volumes,
		},
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ComplianceControllerName,
			Namespace: c.cfg.Namespace,
			Labels: map[string]string{
				"k8s-app": ComplianceControllerName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &complianceReplicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: *podTemplate,
		},
	}

	if c.cfg.ComplianceConfigurationSecurity != nil {
		if overrides := c.cfg.ComplianceConfigurationSecurity.Spec.ComplianceControllerDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(d, overrides)
		}
	}
	return d
}

func (c *ccsComponent) complianceServerServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ComplianceServerServiceAccount, Namespace: c.cfg.Namespace},
	}
}

func (c *ccsComponent) externalLinseedRoleBinding() *rbacv1.RoleBinding {
	// For managed clusters, we must create a role binding to allow Linseed to manage access token secrets
	// in our namespace.
	linseed := "tigera-linseed"
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      linseed,
			Namespace: c.cfg.Namespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     render.TigeraLinseedSecretsClusterRole,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      linseed,
				Namespace: render.ElasticsearchNamespace,
			},
		},
	}
}

func (c *ccsComponent) complianceServerClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return rcomponents.ClusterRoleBinding(ComplianceServerServiceAccount, ComplianceServerServiceAccount, ComplianceServerServiceAccount, c.cfg.BindingNamespaces)
}

func (c *ccsComponent) complianceServerService() *corev1.Service {
	return &corev1.Service{
		TypeMeta:   metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "compliance", Namespace: c.cfg.Namespace},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name:       "compliance-api",
					Port:       443,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(complianceServerPort),
				},
			},
			Selector: map[string]string{"k8s-app": ComplianceServerName},
		},
	}
}

func (c *ccsComponent) complianceServerDeployment() *appsv1.Deployment {
	var keyPath, certPath string
	if c.cfg.ServerKeyPair != nil {
		// This should never be nil, but we check it anyway just to be safe.
		keyPath, certPath = c.cfg.ServerKeyPair.VolumeMountKeyFilePath(), c.cfg.ServerKeyPair.VolumeMountCertificateFilePath()
	}

	envVars := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "info"},
		{Name: "TIGERA_COMPLIANCE_JOB_NAMESPACE", Value: c.cfg.Namespace},
		{Name: "MULTI_CLUSTER_FORWARDING_CA", Value: certificatemanagement.TrustedCertBundleMountPath},
		{Name: "LINSEED_CLIENT_CERT", Value: certPath},
		{Name: "LINSEED_CLIENT_KEY", Value: keyPath},
		{Name: "LINSEED_TOKEN", Value: render.GetLinseedTokenPath(c.cfg.ManagementClusterConnection != nil)},
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

	if c.cfg.KeyValidatorConfig != nil {
		envVars = append(envVars, c.cfg.KeyValidatorConfig.RequiredEnv("TIGERA_COMPLIANCE_")...)
	}
	var initContainers []corev1.Container
	if c.cfg.ServerKeyPair.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.ServerKeyPair.InitContainer(c.cfg.Namespace))
	}

	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:        ComplianceServerName,
			Namespace:   c.cfg.Namespace,
			Annotations: complianceAnnotations(c),
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: ComplianceServerServiceAccount,
			Tolerations:        tolerations,
			NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
			ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
			InitContainers:     initContainers,
			Containers: []corev1.Container{
				{
					Name:            ComplianceServerName,
					Image:           c.serverImage,
					ImagePullPolicy: render.ImagePullPolicy(),
					Env:             envVars,
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Path:   "/compliance/version",
								Port:   intstr.FromInt(complianceServerPort),
								Scheme: corev1.URISchemeHTTPS,
							},
						},
						FailureThreshold:    5,
						InitialDelaySeconds: 5,
					},
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Path:   "/compliance/version",
								Port:   intstr.FromInt(complianceServerPort),
								Scheme: corev1.URISchemeHTTPS,
							},
						},
						FailureThreshold:    5,
						InitialDelaySeconds: 5,
					},
					Args: []string{
						fmt.Sprintf("-certpath=%s", c.cfg.ServerKeyPair.VolumeMountCertificateFilePath()),
						fmt.Sprintf("-keypath=%s", c.cfg.ServerKeyPair.VolumeMountKeyFilePath()),
					},
					SecurityContext: securitycontext.NewNonRootContext(),
					VolumeMounts: append(
						c.cfg.TrustedBundle.VolumeMounts(c.SupportedOSType()),
						c.cfg.ServerKeyPair.VolumeMount(c.SupportedOSType()),
					),
				},
			},
			Volumes: []corev1.Volume{
				c.cfg.ServerKeyPair.Volume(),
				c.cfg.TrustedBundle.Volume(),
			},
		},
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ComplianceServerName,
			Namespace: c.cfg.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &complianceReplicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: *podTemplate,
		},
	}

	if c.cfg.ComplianceConfigurationSecurity != nil {
		if overrides := c.cfg.ComplianceConfigurationSecurity.Spec.ComplianceServerDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(d, overrides)
		}
	}
	return d
}

func complianceAnnotations(c *ccsComponent) map[string]string {
	annotations := c.cfg.TrustedBundle.HashAnnotations()
	if c.cfg.ServerKeyPair != nil {
		annotations[c.cfg.ServerKeyPair.HashAnnotationKey()] = c.cfg.ServerKeyPair.HashAnnotationValue()
	}
	return annotations
}

// Allow internal communication from compliance-benchmarker, compliance-controller, compliance-snapshotter, compliance-reporter
// to apiserver, coredns, linseed, and elasticsearch.
func (c *ccsComponent) complianceAccessAllowTigeraNetworkPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerServiceSelectorEntityRule,
		},
	}

	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, c.cfg.OpenShift)

	if c.cfg.ManagementClusterConnection == nil {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.DefaultHelper().LinseedEntityRule(),
		})
	} else {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: render.GuardianEntityRule,
		})
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ComplianceAccessPolicyName,
			Namespace: c.cfg.Namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(ComplianceBenchmarkerName, ComplianceControllerName, ComplianceSnapshotterName, ComplianceReporterName),
			Types:    []v3.PolicyType{v3.PolicyTypeEgress},
			Egress:   egressRules,
		},
	}
}

// Allow internal communication to compliance-server from Manager.
func (c *ccsComponent) complianceServerAllowTigeraNetworkPolicy() *v3.NetworkPolicy {
	networkpolicyHelper := networkpolicy.Helper(c.cfg.Tenant.MultiTenant(), c.cfg.Namespace)
	egressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerServiceSelectorEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicyHelper.LinseedEntityRule(),
		},
	}

	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, c.cfg.OpenShift)

	// add oidc egress rule
	if c.cfg.KeyValidatorConfig != nil {
		if parsedURL, err := url.Parse(c.cfg.KeyValidatorConfig.Issuer()); err == nil {
			egressRules = append(egressRules, networkpolicy.GetOIDCEgressRule(parsedURL))
		}
	}

	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: render.DexEntityRule,
		},
		// compliance-server does RBAC checks for managed cluster compliance reports via guardian.
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicyHelper.ManagerEntityRule(),
		},
	}...)

	ingressRules := []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source:   networkpolicyHelper.ManagerSourceEntityRule(),
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(complianceServerPort),
			},
		},
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ComplianceServerPolicyName,
			Namespace: c.cfg.Namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(ComplianceServerName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  ingressRules,
			Egress:   egressRules,
		},
	}
}

func (c *ccsComponent) multiTenantManagedClustersAccess() []client.Object {
	var objects []client.Object

	// In a single tenant setup we want to create a cluster role that binds using service account
	// tigera-compliance-server from tigera-compliance namespace. In a multi-tenant setup
	// Compliance server from the tenant's namespace impersonates service tigera-compliance-server
	// from tigera-compliance namespace
	objects = append(objects, &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: MultiTenantComplianceManagedClustersAccessRoleBindingName, Namespace: c.cfg.Namespace},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     render.MultiTenantManagedClustersAccessClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			// requests for compliance to managed clusters are done using service account tigera-compliance-server
			// from tigera-compliance namespace regardless of tenancy mode (single tenant or multi-tenant)
			{
				Kind:      "ServiceAccount",
				Name:      ComplianceServerServiceAccount,
				Namespace: CcsNamespace,
			},
		},
	})

	return objects
}
