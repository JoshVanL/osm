package certmanager

import (
	"github.com/openservicemesh/osm/pkg/certificate"
)

// ListIssuedCertificates implements CertificateDebugger interface and returns the list of issued certificates.
func (cm *CertManager) ListIssuedCertificates() []certificate.Certificater {
	certs, err := cm.ListCertificates()
	if err != nil {
		log.Error().Err(err).Msgf("Failed to list issued certificates")
		return nil
	}

	return certs
}
