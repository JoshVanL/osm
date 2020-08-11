package certmanager

import (
	"fmt"
	"strconv"
	"time"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1beta1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/certificate/pem"
	"github.com/openservicemesh/osm/pkg/certificate/rotor"
)

// NewRootCertificateFromPEM is a helper returning a certificate.Certificater
// from the PEM components given.
func NewRootCertificateFromPEM(pemCert pem.Certificate) (certificate.Certificater, error) {
	cert, err := certificate.DecodePEMCertificate(pemCert)
	if err != nil {
		return nil, fmt.Errorf("failed to decoded root certificate: %s", err)
	}

	return Certificate{
		commonName: certificate.CommonName(cert.Subject.CommonName),
		certChain:  pemCert,
		expiration: cert.NotAfter,
		issuingCA:  pem.RootCertificate(pemCert),
	}, nil
}

func (cm *CertManager) fetchCertificates() ([]certificate.Certificater, error) {
	crs, err := cm.crLister.List(labels.SelectorFromSet(
		map[string]string{
			CertificateRequestManagedLabelKey: "true",
		},
	))
	if err != nil {
		return nil, err
	}

	crMap := make(map[string]certificateRequestRevisionPair)
	for i, cr := range crs {
		// Skip if certificate request is not ready
		if !certificateRequestIsReady(cr) {
			continue
		}

		// If the CertificateRequest is a higher or same revison, override existing
		if nextRevision, err := strconv.Atoi(cr.Annotations[CertificateRequestRevisionAnnotationKey]); err == nil &&
			nextRevision >= crMap[cr.Labels[CertificateRequestCommonNameLabelKey]].revision {
			crMap[cr.Labels[CertificateRequestCommonNameLabelKey]] = certificateRequestRevisionPair{nextRevision, crs[i]}
		}
	}

	var certs []certificate.Certificater
	for _, pair := range crMap {
		cert, err := cm.certificaterFromCertificateRequest(pair.cr, nil)
		if err != nil {
			return nil, err
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

func (cm *CertManager) fetchFromCertificateRequest(cn certificate.CommonName) (*Certificate, int, error) {
	crs, err := cm.crLister.List(labels.SelectorFromSet(
		map[string]string{
			CertificateRequestManagedLabelKey:    "true",
			CertificateRequestCommonNameLabelKey: cn.String(),
		},
	))
	if err != nil || len(crs) == 0 {
		return nil, -1, err
	}

	var (
		latestCR       *cmapi.CertificateRequest
		latestRevision int
	)
	for i, cr := range crs {
		if nextRevision, err := strconv.Atoi(cr.Annotations[CertificateRequestRevisionAnnotationKey]); err == nil &&
			nextRevision >= latestRevision {
			latestCR = crs[i]
		}
	}

	cert, err := cm.certificaterFromCertificateRequest(latestCR, nil)
	if err != nil {
		return nil, -1, err
	}

	if rotor.ShouldRotate(cert) {
		return nil, latestRevision, nil
	}

	return cert, latestRevision, nil
}

// waitForCertificateRequestReady waits for the CertificateRequest resource to
// enter a Ready state.
func (cm *CertManager) waitForCertificateReady(name string, timeout time.Duration) (*cmapi.CertificateRequest, error) {
	var (
		cr  *cmapi.CertificateRequest
		err error
	)

	err = wait.PollImmediate(time.Second, timeout,
		func() (bool, error) {
			cr, err = cm.crLister.Get(name)
			if apierrors.IsNotFound(err) {
				log.Info().Msgf("Failed to find CertificateRequest %s/%s", cm.namespace, name)
				return false, nil
			}

			if err != nil {
				return false, fmt.Errorf("error getting CertificateRequest %s: %v", name, err)
			}

			if !certificateRequestIsReady(cr) {
				log.Info().Msgf("CertificateRequest not ready %s/%s: %+v",
					cm.namespace, name, cr.Status.Conditions)
				return false, nil
			}

			return true, nil
		},
	)

	// return CertificateRequest even when error to use for debugging
	return cr, err
}

// certificaterFromCertificateRequest will construct a certificate.Certificater
// from a give CertificateRequest and private key.
func (cm *CertManager) certificaterFromCertificateRequest(cr *cmapi.CertificateRequest, privateKey []byte) (*Certificate, error) {
	cert, err := certificate.DecodePEMCertificate(cr.Status.Certificate)
	if err != nil {
		return nil, err
	}

	return &Certificate{
		commonName:             certificate.CommonName(cert.Subject.CommonName),
		expiration:             cert.NotAfter,
		certChain:              cr.Status.Certificate,
		privateKey:             privateKey,
		issuingCA:              cm.ca.GetIssuingCA(),
		certificateRequestName: cr.Name,
	}, nil
}

// certificateRequestIsReady returns true if the given CertificateRequest is in
// a ready state.
func certificateRequestIsReady(cr *cmapi.CertificateRequest) bool {
	if cr == nil {
		return false
	}

	readyCondidition := cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionTrue,
	}

	existingConditions := cr.Status.Conditions
	for _, cond := range existingConditions {
		if cond.Type == readyCondidition.Type && cond.Status == readyCondidition.Status {
			return true
		}
	}

	return false
}
