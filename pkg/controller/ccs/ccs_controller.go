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

package ccs

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/tenancy"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/dns"
	commonrender "github.com/tigera/operator/pkg/render"
	ccsrender "github.com/tigera/operator/pkg/render/ccs"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const ResourceName = "complianceconfigurationsecurity"

var log = logf.Log.WithName("controller_ccs")

// Add creates a new CCSController and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		// No need to start this controller.
		return nil
	}
	licenseAPIReady := &utils.ReadyFlag{}
	tierWatchReady := &utils.ReadyFlag{}

	// create the reconciler
	reconciler := newReconciler(mgr, opts, licenseAPIReady, tierWatchReady)

	// Create a new controller
	ccsController, err := ctrlruntime.NewController("ccs-controller", mgr, controller.Options{Reconciler: reconciler})
	if err != nil {
		return err
	}

	// Determine how to handle watch events for cluster-scoped resources. For multi-tenant clusters,
	// we should update all tenants whenever one changes. For single-tenant clusters, we can just queue the object.
	var eventHandler handler.EventHandler = &handler.EnqueueRequestForObject{}
	if opts.MultiTenant {
		eventHandler = utils.EnqueueAllTenants(mgr.GetClient())
		if err = ccsController.WatchObject(&operatorv1.Tenant{}, &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("ccs-controller failed to watch Tenant resource: %w", err)
		}
	}

	k8sClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		log.Error(err, "Failed to establish a connection to k8s")
		return err
	}

	installNS, _, watchNamespaces := tenancy.GetWatchNamespaces(opts.MultiTenant, commonrender.PolicyRecommendationNamespace)

	go utils.WaitToAddLicenseKeyWatch(ccsController, k8sClient, log, licenseAPIReady)

	go utils.WaitToAddTierWatch(networkpolicy.TigeraComponentTierName, ccsController, k8sClient, log, tierWatchReady)
	go utils.WaitToAddNetworkPolicyWatches(ccsController, k8sClient, log, []types.NamespacedName{
		//{Name: ccsrender.CCSAPIPolicyName, Namespace: installNS},
		//{Name: ccsrender.CCSControllerPolicyName, Namespace: installNS},
		{Name: networkpolicy.TigeraComponentDefaultDenyPolicyName, Namespace: installNS},
	})

	// Watch for changes to primary resource CCS
	err = ccsController.WatchObject(&operatorv1.ComplianceConfigurationSecurity{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	if err = ccsController.WatchObject(&operatorv1.Installation{}, eventHandler); err != nil {
		return fmt.Errorf("ccs-controller failed to watch Installation resource: %w", err)
	}

	if err = ccsController.WatchObject(&operatorv1.ImageSet{}, eventHandler); err != nil {
		return fmt.Errorf("ccs-controller failed to watch ImageSet: %w", err)
	}

	if err = ccsController.WatchObject(&operatorv1.APIServer{}, eventHandler); err != nil {
		return fmt.Errorf("ccs-controller failed to watch APIServer resource: %w", err)
	}

	// Watch the given secrets in each both the CCSand operator namespaces
	for _, namespace := range watchNamespaces {
		for _, secretName := range []string{
			ccsrender.APICertSecretName, certificatemanagement.CASecretName, commonrender.ManagerInternalTLSSecretName,
			commonrender.VoltronLinseedTLS, commonrender.VoltronLinseedPublicCert,
		} {
			if err = utils.AddSecretsWatch(ccsController, secretName, namespace); err != nil {
				return fmt.Errorf("ccs-controller failed to watch the secret '%s' in '%s' namespace: %w", secretName, namespace, err)
			}
		}
	}

	// Watch for changes to primary resource ManagementCluster
	if err = ccsController.WatchObject(&operatorv1.ManagementCluster{}, eventHandler); err != nil {
		return fmt.Errorf("ccs-controller failed to watch primary resource: %w", err)
	}

	// Watch for changes to primary resource ManagementClusterConnection
	if err = ccsController.WatchObject(&operatorv1.ManagementClusterConnection{}, eventHandler); err != nil {
		return fmt.Errorf("ccs-controller failed to watch primary resource: %w", err)
	}

	if err = ccsController.WatchObject(&operatorv1.Authentication{}, eventHandler); err != nil {
		return fmt.Errorf("ccs-controller failed to watch resource: %w", err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(ccsController, ResourceName); err != nil {
		return fmt.Errorf("ccs-controller failed to watch CCS Tigerastatus: %w", err)
	}

	return nil
}

// newReconciler returns a new *reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.AddOptions, licenseAPIReady *utils.ReadyFlag, tierWatchReady *utils.ReadyFlag) reconcile.Reconciler {
	r := &ReconcileCCS{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		provider:        opts.DetectedProvider,
		status:          status.New(mgr.GetClient(), "ccs", opts.KubernetesVersion),
		clusterDomain:   opts.ClusterDomain,
		licenseAPIReady: licenseAPIReady,
		tierWatchReady:  tierWatchReady,
		multiTenant:     opts.MultiTenant,
		externalElastic: opts.ElasticExternal,
	}
	r.status.Run(opts.ShutdownContext)
	return r
}

// blank assignment to verify that ReconcileCCS reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileCCS{}

type ReconcileCCS struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client          client.Client
	scheme          *runtime.Scheme
	provider        operatorv1.Provider
	status          status.StatusManager
	clusterDomain   string
	licenseAPIReady *utils.ReadyFlag
	tierWatchReady  *utils.ReadyFlag
	multiTenant     bool
	externalElastic bool
}

func GetCCS(ctx context.Context, cli client.Client, mt bool, ns string) (*operatorv1.ComplianceConfigurationSecurity, error) {
	key := client.ObjectKey{Name: "tigera-secure"}
	if mt {
		key.Namespace = ns
	}
	instance := &operatorv1.ComplianceConfigurationSecurity{}
	err := cli.Get(ctx, key, instance)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

// Reconcile reads that state of the cluster for a CCS object and makes changes based on the state read
// and what is in the CCS.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileCCS) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	helper := utils.NewNamespaceHelper(r.multiTenant, ccsrender.Namespace, request.Namespace)
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name, "installNS", helper.InstallNamespace(), "truthNS", helper.TruthNamespace())
	reqLogger.Info("Reconciling CCS")

	// We skip requests without a namespace specified in multi-tenant setups.
	if r.multiTenant && request.Namespace == "" {
		return reconcile.Result{}, nil
	}

	// Check if this is a tenant-scoped request.
	tenant, _, err := utils.GetTenant(ctx, r.multiTenant, r.client, request.Namespace)
	if errors.IsNotFound(err) {
		reqLogger.Info("No Tenant in this Namespace, skip")
		return reconcile.Result{}, nil
	} else if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Tenant", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Fetch the CCS instance
	instance, err := GetCCS(ctx, r.client, r.multiTenant, request.Namespace)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			reqLogger.Info("ComplianceConfigurationSecurity not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying ccs", err, reqLogger)
		return reconcile.Result{}, err
	}
	r.status.OnCRFound()
	reqLogger.V(2).Info("Loaded config", "config", instance)

	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&instance.ObjectMeta)

	// Changes for updating CCSstatus conditions.
	if request.Name == ResourceName && request.Namespace == "" {
		ts := &operatorv1.TigeraStatus{}
		err := r.client.Get(ctx, types.NamespacedName{Name: ResourceName}, ts)
		if err != nil {
			return reconcile.Result{}, err
		}
		//instance.Status.Conditions = status.UpdateStatusCondition(instance.Status.Conditions, ts.Status.Conditions)
		if err := r.client.Status().Update(ctx, instance); err != nil {
			log.WithValues("reason", err).Info("Failed to create CCSstatus conditions.")
			return reconcile.Result{}, err
		}
	}

	if !utils.IsAPIServerReady(r.client, reqLogger) {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tigera API server to be ready", nil, reqLogger)
		return reconcile.Result{}, err
	}

	// Validate that the tier watch is ready before querying the tier to ensure we utilize the cache.
	if !r.tierWatchReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tier watch to be established", err, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Ensure the allow-tigera tier exists, before rendering any network policies within it.
	if err := r.client.Get(ctx, client.ObjectKey{Name: networkpolicy.TigeraComponentTierName}, &v3.Tier{}); err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for allow-tigera tier to be created, see the 'tiers' TigeraStatus for more information", err, reqLogger)
			return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
		} else {
			log.Error(err, "Error querying allow-tigera tier")
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying allow-tigera tier", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	if !r.licenseAPIReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for LicenseKeyAPI to be ready", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	license, err := utils.FetchLicenseKey(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "License not found", err, reqLogger)
			return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying license", err, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Query for the installation object.
	variant, network, err := utils.GetInstallation(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(network, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to retrieve pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	managementCluster, err := utils.GetManagementCluster(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementCluster", err, reqLogger)
		return reconcile.Result{}, err
	}

	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementClusterConnection", err, reqLogger)
		return reconcile.Result{}, err
	}

	if managementClusterConnection != nil && managementCluster != nil {
		err = fmt.Errorf("having both a ManagementCluster and a ManagementClusterConnection is not supported")
		r.status.SetDegraded(operatorv1.ResourceValidationError, "", err, reqLogger)
		return reconcile.Result{}, err
	}

	var opts []certificatemanager.Option
	opts = append(opts, certificatemanager.WithTenant(tenant), certificatemanager.WithLogger(reqLogger))
	certificateManager, err := certificatemanager.Create(r.client, network, r.clusterDomain, helper.TruthNamespace(), opts...)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}
	var managerInternalTLSSecret certificatemanagement.CertificateInterface
	if managementCluster != nil {
		managerInternalTLSSecret, err = certificateManager.GetCertificate(r.client, commonrender.ManagerInternalTLSSecretName, helper.TruthNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceValidationError, fmt.Sprintf("failed to retrieve / validate  %s", commonrender.ManagerInternalTLSSecretName), err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// The location of the Linseed certificate varies based on if this is a managed cluster or not.
	// For standalone and management clusters, we just use Linseed's actual certificate.
	linseedCertLocation := commonrender.TigeraLinseedSecret
	if managementClusterConnection != nil {
		// For managed clusters, we need to add the certificate of the Voltron endpoint. This certificate is copied from the
		// management cluster into the managed cluster by kube-controllers.
		linseedCertLocation = commonrender.VoltronLinseedPublicCert
	}
	linseedCertificate, err := certificateManager.GetCertificate(r.client, linseedCertLocation, helper.TruthNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, fmt.Sprintf("Failed to retrieve / validate  %s", commonrender.TigeraLinseedSecret), err, reqLogger)
		return reconcile.Result{}, err
	} else if linseedCertificate == nil {
		log.Info("Linseed certificate is not available yet, waiting until it becomes available")
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Linseed certificate is not available yet, waiting until it becomes available", nil, reqLogger)
		return reconcile.Result{}, nil
	}
	bundleMaker := certificateManager.CreateTrustedBundle(managerInternalTLSSecret, linseedCertificate)
	trustedBundle := bundleMaker.(certificatemanagement.TrustedBundleRO)
	// TODO - Copied from compliance, verify if this is the case for CCS as well.
	if r.multiTenant {
		// For multi-tenant systems, we load the pre-created bundle for this tenant instead of using the one we built here.
		trustedBundle, err = certificateManager.LoadMultiTenantTrustedBundleWithRootCertificates(ctx, r.client, helper.InstallNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting trusted bundle", err, reqLogger)
			return reconcile.Result{}, err
		}
		bundleMaker = nil
	}

	var apiKeyPair certificatemanagement.KeyPairInterface
	// TODO: To support MCM cluster we need MCC components creating this separately into operator namespace.
	// TODO: After creating MCM component we wait on these secrets.
	// create tls key pair for ccs api.
	apiKeyPair, err = certificateManager.GetOrCreateKeyPair(
		r.client,
		ccsrender.APICertSecretName,
		helper.TruthNamespace(),
		dns.GetServiceDNSNames(ccsrender.APIResourceName, helper.InstallNamespace(), r.clusterDomain))
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, fmt.Sprintf("failed to retrieve / validate  %s", ccsrender.APICertSecretName), err, reqLogger)
		return reconcile.Result{}, err
	}
	certificateManager.AddToStatusManager(r.status, helper.InstallNamespace())

	// Fetch the Authentication spec. If present, we use to configure user authentication.
	authenticationCR, err := utils.GetAuthentication(ctx, r.client)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying Authentication", err, reqLogger)
		return reconcile.Result{}, err
	}
	if authenticationCR != nil && authenticationCR.Status.State != operatorv1.TigeraStatusReady {
		r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Authentication is not ready - authenticationCR status: %s", authenticationCR.Status.State), nil, reqLogger)
		return reconcile.Result{}, nil
	}

	// Determine the namespaces to which we must bind the cluster role.
	// For multi-tenant, the cluster role will be bind to the service account in the tenant namespace
	bindNamespaces, err := helper.TenantNamespaces(r.client)
	if err != nil {
		return reconcile.Result{}, err
	}

	keyValidatorConfig, err := utils.GetKeyValidatorConfig(ctx, r.client, authenticationCR, r.clusterDomain)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Failed to process the authentication CR.", err, reqLogger)
		return reconcile.Result{}, err
	}

	reqLogger.V(3).Info("rendering components")

	namespaceComp := commonrender.NewPassthrough(commonrender.CreateNamespace(helper.InstallNamespace(), network.KubernetesProvider, commonrender.PSSBaseline, network.Azure))

	hasNoLicense := !utils.IsFeatureActive(license, common.ComplianceFeature)
	openshift := r.provider.IsOpenShift()
	cfg := &ccsrender.Config{
		TrustedBundle:                   trustedBundle,
		Installation:                    network,
		APIKeyPair:                      apiKeyPair,
		PullSecrets:                     pullSecrets,
		OpenShift:                       openshift,
		ManagementCluster:               managementCluster,
		ManagementClusterConnection:     managementClusterConnection,
		KeyValidatorConfig:              keyValidatorConfig,
		ClusterDomain:                   r.clusterDomain,
		HasNoLicense:                    hasNoLicense,
		Namespace:                       helper.InstallNamespace(),
		BindingNamespaces:               bindNamespaces,
		Tenant:                          tenant,
		ComplianceConfigurationSecurity: instance,
		ExternalElastic:                 r.externalElastic,
	}

	// Render the desired objects from the CRD and create or update them.
	ccsComponent := ccsrender.CCS(cfg)
	if err = imageset.ApplyImageSet(ctx, r.client, variant, ccsComponent); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}
	certificateComponent := rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace:       helper.InstallNamespace(),
		TruthNamespace:  helper.TruthNamespace(),
		ServiceAccounts: []string{ccsrender.APIResourceName},
		KeyPairOptions: []rcertificatemanagement.KeyPairOption{
			rcertificatemanagement.NewKeyPairOption(apiKeyPair, true, true),
		},
		TrustedBundle: bundleMaker,
	})

	hdlr := utils.NewComponentHandler(log, r.client, r.scheme, instance)
	for _, c := range []commonrender.Component{namespaceComp, certificateComponent, ccsComponent} {
		if err := hdlr.CreateOrUpdateOrDelete(ctx, c, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating / deleting resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	if hasNoLicense {
		log.V(4).Info("CCS is not activated as part of this license")
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Feature is not active - License does not support this feature", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future. Hopefully by then
		// things will be available.
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Everything is available - update the CRD status.
	instance.Status.State = operatorv1.TigeraStatusReady
	if err = r.client.Status().Update(ctx, instance); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}