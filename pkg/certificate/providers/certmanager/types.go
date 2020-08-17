package certmanager

import (
	"errors"
	"time"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1beta1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1beta1"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1beta1"

	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/certificate/pem"
	"github.com/openservicemesh/osm/pkg/logger"
)

const (
	// How many bits to use for the RSA key
	rsaBits = 4096

	// checkCertificateExpirationInterval is the interval to check wether a
	// certificate is close to expiration and needs renewal.
	checkCertificateExpirationInterval = 5 * time.Second

	// Label for CommonName of Certificate Request used for listing
	CertificateRequestManagedLabelKey    = "openservicemesh.io/managed"
	CertificateRequestCommonNameLabelKey = "openservicemesh.io/common-name"

	// Revision denotes the "revision" of certificate for a given identity
	CertificateRequestRevisionAnnotationKey = "openservicemesh.io/revision"
)

var (
	log                          = logger.New("cert-manager")
	errNoCertificateRequestFound = errors.New("no CertificateRequests found match CN")
)

// CertManager implements certificate.Manager
type CertManager struct {
	// How long will newly issued certificates be valid for.
	validityPeriod time.Duration

	// The Certificate Authority root certificate to be used by this certificate
	// manager.
	ca certificate.Certificater

	// The channel announcing to the rest of the system when a certificate has
	// changed.
	announcements chan interface{}

	certificatesOrganization string

	// Control plane namespace where CertificateRequests are created.
	namespace string

	// cert-manager CertificateRequest client set.
	client cmclient.CertificateRequestInterface

	// Reference to the Issuer to sign certificates.
	issuerRef cmmeta.ObjectReference

	// crLister is used to list CertificateRequests in the given namespace.
	crLister cmlisters.CertificateRequestNamespaceLister
}

// Certificate implements certificate.Certificater
type Certificate struct {
	// The commonName of the certificate
	commonName certificate.CommonName

	// When the cert expires
	expiration time.Time

	// PEM encoded Certificate and Key (byte arrays)
	certChain  pem.Certificate
	privateKey pem.PrivateKey

	// Certificate authority signing this certificate.
	issuingCA pem.RootCertificate

	certificateRequestName string
}

// certificateRequestRevisionPair is used to hold a CertificateRequest and
// revision pair to construct a map containing the latest certificate requests
// made.
type certificateRequestRevisionPair struct {
	revision int
	cr       *cmapi.CertificateRequest
}
