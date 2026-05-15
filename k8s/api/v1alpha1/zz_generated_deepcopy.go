// Hand-written DeepCopy methods for JWTRequest, JWTRequestSpec, JWTRequestStatus,
// and JWTRequestList. Keeps controller-runtime happy without dragging in code-generation
// tooling. Update these any time you change the corresponding type definitions.
package v1alpha1

import (
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto copies the receiver into out, doing a deep copy of all referenced fields.
func (in *JWTRequest) DeepCopyInto(out *JWTRequest) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy returns a deep copy of the JWTRequest.
func (in *JWTRequest) DeepCopy() *JWTRequest {
	if in == nil {
		return nil
	}
	out := new(JWTRequest)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject returns a generic deep copy as a runtime.Object.
func (in *JWTRequest) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	return in.DeepCopy()
}

// DeepCopyInto copies the receiver into out.
func (in *JWTRequestSpec) DeepCopyInto(out *JWTRequestSpec) {
	*out = *in
	if in.Audience != nil {
		out.Audience = append([]string(nil), in.Audience...)
	}
	if in.Groups != nil {
		out.Groups = append([]string(nil), in.Groups...)
	}
	if in.Roles != nil {
		out.Roles = append([]string(nil), in.Roles...)
	}
	if in.Entitlements != nil {
		out.Entitlements = append([]string(nil), in.Entitlements...)
	}
	if in.ExtraClaims != nil {
		out.ExtraClaims = make(map[string]apiextensionsv1.JSON, len(in.ExtraClaims))
		for k, v := range in.ExtraClaims {
			out.ExtraClaims[k] = *v.DeepCopy()
		}
	}
	if in.RefreshThreshold != nil {
		v := *in.RefreshThreshold
		out.RefreshThreshold = &v
	}
}

// DeepCopy returns a deep copy of the JWTRequestSpec.
func (in *JWTRequestSpec) DeepCopy() *JWTRequestSpec {
	if in == nil {
		return nil
	}
	out := new(JWTRequestSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies the receiver into out.
func (in *JWTRequestStatus) DeepCopyInto(out *JWTRequestStatus) {
	*out = *in
	if in.LastMintedAt != nil {
		t := *in.LastMintedAt
		out.LastMintedAt = &t
	}
	if in.ExpiresAt != nil {
		t := *in.ExpiresAt
		out.ExpiresAt = &t
	}
	if in.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(in.Conditions))
		for i := range in.Conditions {
			in.Conditions[i].DeepCopyInto(&out.Conditions[i])
		}
	}
}

// DeepCopy returns a deep copy of the JWTRequestStatus.
func (in *JWTRequestStatus) DeepCopy() *JWTRequestStatus {
	if in == nil {
		return nil
	}
	out := new(JWTRequestStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies the receiver into out.
func (in *JWTRequestList) DeepCopyInto(out *JWTRequestList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]JWTRequest, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

// DeepCopy returns a deep copy of the JWTRequestList.
func (in *JWTRequestList) DeepCopy() *JWTRequestList {
	if in == nil {
		return nil
	}
	out := new(JWTRequestList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject returns a generic deep copy as a runtime.Object.
func (in *JWTRequestList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	return in.DeepCopy()
}
