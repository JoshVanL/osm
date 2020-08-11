package certmanager

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"strconv"
	"time"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1beta1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmversionedclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cminformers "github.com/jetstack/cert-manager/pkg/client/informers/externalversions"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/certificate/rotor"
)

// IssueCertificate implements certificate.Manager and returns a newly issued certificate.
func (cm *CertManager) IssueCertificate(cn certificate.CommonName, validityPeriod *time.Duration) (certificate.Certificater, error) {
	start := time.Now()

	cert, err := cm.issue(cn, validityPeriod)
	if err != nil {
		return nil, err
	}

	log.Info().Msgf("It took %+v to issue certificate with CN=%s", time.Since(start), cn)

	return cert, nil
}

// GetCertificate returns a certificate given its Common Name (CN)
func (cm *CertManager) GetCertificate(cn certificate.CommonName) (certificate.Certificater, error) {
	cert, _, err := cm.fetchFromCertificateRequest(cn)
	if err != nil || cert == nil {
		return nil, err
	}

	return cert, nil
}

// RotateCertificate implements certificate.Manager and rotates an existing
// certificate. When a certificate is successfully created, garbage collect
// old CertificateRequests.
func (cm *CertManager) RotateCertificate(cn certificate.CommonName) (certificate.Certificater, error) {
	log.Info().Msgf("Rotating certificate for CN=%s", cn)

	start := time.Now()

	cert, err := cm.issue(cn, &cm.validityPeriod)
	if err != nil {
		return cert, err
	}

	cm.announcements <- nil

	log.Info().Msgf("Rotating certificate CN=%s took %+v", cn, time.Since(start))

	return cert, nil
}

// GetRootCertificate returns the root certificate in PEM format and its expiration.
func (cm *CertManager) GetRootCertificate() (certificate.Certificater, error) {
	return cm.ca, nil
}

// ListCertificates lists all certificates issued
func (cm *CertManager) ListCertificates() ([]certificate.Certificater, error) {
	return cm.fetchCertificates()
}

// GetAnnouncementsChannel returns a channel, which is used to announce when
// changes have been made to the issued certificates.
func (cm *CertManager) GetAnnouncementsChannel() <-chan interface{} {
	return cm.announcements
}

// issue will request a new signed certificate from the configured cert-manager
// issuer.
func (cm *CertManager) issue(cn certificate.CommonName, validityPeriod *time.Duration) (certificate.Certificater, error) {
	oldCR, revision, err := cm.fetchFromCertificateRequest(cn)
	if err != nil {
		return nil, err
	}

	var duration *metav1.Duration
	if validityPeriod != nil {
		duration = &metav1.Duration{
			Duration: *validityPeriod,
		}
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		log.Error().Err(err).Msgf("Error generating private key for certificate with CN=%s", cn)
		return nil, fmt.Errorf("failed to generate private key for certificate with CN=%s: %s",
			cn, err)
	}

	privKeyPEM, err := certificate.EncodeKeyDERtoPEM(certPrivKey)
	if err != nil {
		log.Error().Err(err).Msgf("Error encoding private key for certificate with CN=%s", cn)
		return nil, err
	}

	csr := &x509.CertificateRequest{
		Version:            3,
		SignatureAlgorithm: x509.SHA512WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		Subject: pkix.Name{
			CommonName: cn.String(),
		},
		DNSNames: []string{cn.String()},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csr, certPrivKey)
	if err != nil {
		return nil, fmt.Errorf("error creating x509 certificate request: %s", err)
	}

	csrPEM, err := certificate.EncodeCertReqDERtoPEM(csrDER)
	if err != nil {
		return nil, fmt.Errorf("failed to encode certificate request DER to PEM CN=%s: %s",
			cn, err)
	}

	cr := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "osm-",
			Namespace:    cm.namespace,
			Labels: map[string]string{
				CertificateRequestCommonNameLabelKey: cn.String(),
				CertificateRequestManagedLabelKey:    "true",
			},
			Annotations: map[string]string{
				CertificateRequestRevisionAnnotationKey: strconv.Itoa(revision + 1),
			},
		},
		Spec: cmapi.CertificateRequestSpec{
			Duration: duration,
			IsCA:     false,
			Usages: []cmapi.KeyUsage{
				cmapi.UsageKeyEncipherment, cmapi.UsageDigitalSignature,
			},
			Request:   csrPEM,
			IssuerRef: cm.issuerRef,
		},
	}

	cr, err = cm.client.Create(context.TODO(), cr, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	log.Info().Msgf("Created CertificateRequest %s/%s for CN=%s", cm.namespace, cr.Name, cn)

	// TODO: add timeout option instead of 60s hard coded.
	cr, err = cm.waitForCertificateReady(cr.Name, time.Second*60)
	if err != nil {
		return nil, err
	}

	cert, err := cm.certificaterFromCertificateRequest(cr, privKeyPEM)
	if err != nil {
		return nil, err
	}

	if oldCR != nil && len(oldCR.certificateRequestName) > 0 {
		if err := cm.client.Delete(context.TODO(), oldCR.certificateRequestName, metav1.DeleteOptions{}); err != nil {
			log.Error().Err(err).Msgf("failed to delete old CertificateRequest %s/%s", cm.namespace, oldCR.certificateRequestName)
		}
	}

	return cert, nil
}

// NewCertManager will contruct a new certificate.Certificater implemented
// using Jetstack's cert-manager,
func NewCertManager(
	ca certificate.Certificater,
	client cmversionedclient.Interface,
	namespace string,
	validityPeriod time.Duration,
	issuerRef cmmeta.ObjectReference,
) (*CertManager, error) {
	informerFactory := cminformers.NewSharedInformerFactory(client, time.Second*30)
	crLister := informerFactory.Certmanager().V1beta1().CertificateRequests().Lister().CertificateRequests(namespace)

	log.Info().Msg("Syncing cert-manager CertificateRequest resource")

	// TODO: pass through graceful shutdown
	stopCh := make(chan struct{})
	informerFactory.Start(stopCh)
	informerFactory.WaitForCacheSync(stopCh)

	cm := &CertManager{
		ca:             ca,
		announcements:  make(chan interface{}),
		namespace:      namespace,
		client:         client.CertmanagerV1beta1().CertificateRequests(namespace),
		issuerRef:      issuerRef,
		crLister:       crLister,
		validityPeriod: validityPeriod,
	}

	// Instantiating a new certificate rotation mechanism will start a goroutine for certificate rotation.
	rotor.New(cm).Start(checkCertificateExpirationInterval)

	return cm, nil
}
