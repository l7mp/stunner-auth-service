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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	opdefault "github.com/l7mp/stunner-gateway-operator/pkg/config"
	stnrv1 "github.com/l7mp/stunner/pkg/apis/v1"

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

	// a label-selector predicate to select the loadbalancer services we are interested in
	configMapPredicate, err := predicate.LabelSelectorPredicate(
		metav1.LabelSelector{
			MatchLabels: map[string]string{
				// "app:stunner"
				opdefault.OwnedByLabelKey: opdefault.OwnedByLabelValue,
			},
		})
	if err != nil {
		return err
	}

	if err := c.Watch(
		source.Kind(mgr.GetCache(), &corev1.ConfigMap{}),
		&handler.EnqueueRequestForObject{},
		// trigger when the ConfigMap spec changes
		configMapPredicate,
	); err != nil {
		return err
	}
	r.log.Info("watching gatewayconfig objects")

	return nil
}

func (r *configMapReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := r.log.WithValues("gateway-config", req.String())
	log.Info("reconciling")

	cms := []*stnrv1.StunnerConfig{}

	// find all ConfigMaps
	cmList := &corev1.ConfigMapList{}
	if err := r.List(ctx, cmList, client.MatchingLabels{opdefault.OwnedByLabelKey: opdefault.OwnedByLabelValue}); err != nil {
		return reconcile.Result{}, err
	}

	for _, cm := range cmList.Items {
		cm := cm
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

// unpacks a stunner config
func UnpackConfigMap(cm *corev1.ConfigMap) (stnrv1.StunnerConfig, error) {
	conf := stnrv1.StunnerConfig{}

	jsonConf, found := cm.Data[config.DefaultStunnerdConfigfileName]
	if !found {
		return conf, fmt.Errorf("error unpacking configmap data: %s not found",
			config.DefaultStunnerdConfigfileName)
	}

	if err := json.Unmarshal([]byte(jsonConf), &conf); err != nil {
		return stnrv1.StunnerConfig{}, err
	}

	return conf, nil
}
