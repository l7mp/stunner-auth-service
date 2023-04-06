/*
Copyright 2022 The l7mp/stunner team.

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

package controllers

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	stnrv1a1 "github.com/l7mp/stunner/pkg/apis/v1alpha1"

	"github.com/l7mp/stunner-auth-service/internal/config"
	"github.com/l7mp/stunner-auth-service/internal/store"
)

// configMapReconciler reconciles a ConfigMap object.
type configMapReconciler struct {
	client.Client
	log logr.Logger
}

func RegisterConfigMapController(mgr manager.Manager, log logr.Logger) error {
	r := &configMapReconciler{
		Client: mgr.GetClient(),
		log:    log.WithName("configmap-controller"),
	}

	c, err := controller.New("configmap", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}
	r.log.Info("created configmap controller")

	if err := c.Watch(
		&source.Kind{Type: &corev1.ConfigMap{}},
		&handler.EnqueueRequestForObject{},
		// trigger when the ConfigMap spec changes
		predicate.NewPredicateFuncs(r.validateConfigMapForReconcile),
	); err != nil {
		return err
	}
	r.log.Info("watching gatewayconfig objects")

	return nil
}

func (r *configMapReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := r.log.WithValues("gateway-config", req.String())
	log.Info("reconciling")

	cms := []*stnrv1a1.StunnerConfig{}

	// find all ConfigMaps
	cmList := &corev1.ConfigMapList{}
	if err := r.List(ctx, cmList); err != nil {
		return reconcile.Result{}, err
	}

	for _, cm := range cmList.Items {
		cm := cm
		if !r.validateConfigMapForReconcile(&cm) {
			continue
		}

		stnrconf, err := UnpackConfigMap(&cm)
		if err != nil {
			log.Error(err, "cannot unpack Stunner dataplane ConfigMap")
			continue
		}

		cms = append(cms, &stnrconf)
	}

	store.ConfigMaps.Reset(cms)
	r.log.V(2).Info("reset ConfigMap store", "configs", store.ConfigMaps.String())

	return reconcile.Result{}, nil
}

// validateConfigMapForReconcile checks whether the ConfigMap contains a valid STUNner dataplane
// config. All dataplane configs should have a "related-gateway" annotation.
func (r *configMapReconciler) validateConfigMapForReconcile(o client.Object) bool {
	_, found := o.GetAnnotations()[config.DefaultRelatedGatewayAnnotationKey]
	return found
}

// unpacks a stunner config
func UnpackConfigMap(cm *corev1.ConfigMap) (stnrv1a1.StunnerConfig, error) {
	conf := stnrv1a1.StunnerConfig{}

	jsonConf, found := cm.Data[config.DefaultStunnerdConfigfileName]
	if !found {
		return conf, fmt.Errorf("error unpacking configmap data: %s not found",
			config.DefaultStunnerdConfigfileName)
	}

	if err := json.Unmarshal([]byte(jsonConf), &conf); err != nil {
		return stnrv1a1.StunnerConfig{}, err
	}

	return conf, nil
}
