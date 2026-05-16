// Package v1alpha1 contains API schema definitions for the jwtmint.io v1alpha1 API group.
//
// +kubebuilder:object:generate=true
// +groupName=jwtmint.io
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// GroupVersion is the group version used to register these objects.
var GroupVersion = schema.GroupVersion{Group: "jwtmint.io", Version: "v1alpha1"}

// SchemeBuilder collects functions that add the v1alpha1 types to a scheme.
var SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

// AddToScheme registers v1alpha1 types with the given scheme.
var AddToScheme = SchemeBuilder.AddToScheme

func init() {
	SchemeBuilder.Register(&JWTRequest{}, &JWTRequestList{})
}
