package controller

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	v1alpha1 "github.com/azemoning/corso/api/v1alpha1"
)

var (
	// SchemeGroupVersion is the group version for corso.io
	SchemeGroupVersion = schema.GroupVersion{Group: "corso.io", Version: "v1alpha1"}

	// SchemeBuilder is used to add corso types to the scheme
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme applies all stored functions to the scheme
	AddToScheme = SchemeBuilder.AddToScheme
)

// addKnownTypes registers corso.io/v1alpha1 types with the given scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&v1alpha1.BPFProgramAllowlist{},
		&v1alpha1.BPFProgramAllowlistList{},
	)
	return nil
}
