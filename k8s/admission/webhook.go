package admission

import (
	"encoding/json"
	"fmt"
	"net/http"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dcadolph/jwtmint/internal/jsonutil"
	v1alpha1 "github.com/dcadolph/jwtmint/k8s/api/v1alpha1"
	"github.com/dcadolph/jwtmint/pkgerr"
)

// PathValidate is the conventional path for the validating admission webhook.
const PathValidate = "/admission/validate-jwtrequest"

// Handler returns an http.Handler that validates JWTRequest admission reviews against policy.
//
// Panics on construction if policy is nil — required dependency.
func Handler(policy Policy) http.Handler {

	if policy == nil {
		panic("admission.Handler: policy required")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var review admissionv1.AdmissionReview
		if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
			writeReview(w, http.StatusBadRequest, deniedReview(nil, fmt.Sprintf("invalid AdmissionReview body: %s", err)))
			return
		}
		if review.Request == nil {
			writeReview(w, http.StatusBadRequest, deniedReview(nil, "AdmissionReview.request required"))
			return
		}

		jr := &v1alpha1.JWTRequest{}
		if err := json.Unmarshal(review.Request.Object.Raw, jr); err != nil {
			writeReview(w, http.StatusOK, deniedReview(review.Request, fmt.Sprintf("could not decode JWTRequest: %s", err)))
			return
		}

		if err := policy.Allow(review.Request.UserInfo, jr); err != nil {
			writeReview(w, http.StatusOK, deniedReview(review.Request, err.Error()))
			return
		}

		writeReview(w, http.StatusOK, allowedReview(review.Request))
	})
}

// allowedReview builds an AdmissionReview with allowed=true.
func allowedReview(req *admissionv1.AdmissionRequest) admissionv1.AdmissionReview {
	return admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{Kind: "AdmissionReview", APIVersion: "admission.k8s.io/v1"},
		Response: &admissionv1.AdmissionResponse{
			UID:     req.UID,
			Allowed: true,
		},
	}
}

// deniedReview builds an AdmissionReview with allowed=false and the given reason.
func deniedReview(req *admissionv1.AdmissionRequest, reason string) admissionv1.AdmissionReview {
	resp := &admissionv1.AdmissionResponse{
		Allowed: false,
		Result: &metav1.Status{
			Status:  "Failure",
			Message: reason,
			Reason:  metav1.StatusReasonForbidden,
			Code:    http.StatusForbidden,
		},
	}
	if req != nil {
		resp.UID = req.UID
	}
	return admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{Kind: "AdmissionReview", APIVersion: "admission.k8s.io/v1"},
		Response: resp,
	}
}

// writeReview marshals the review and writes it with the given status code.
func writeReview(w http.ResponseWriter, status int, review admissionv1.AdmissionReview) {
	if err := jsonutil.Write(w, status, review); err != nil {
		// Fallback if encoding fails: a minimal Forbidden body so the apiserver does not hang.
		http.Error(w, fmt.Sprintf(`{"error":%q}`, fmt.Errorf("%w: encoding review: %w", pkgerr.ErrEncode, err)), http.StatusInternalServerError)
	}
}
