// sanext.go: hand-built X.509 SubjectAltName extension carrying the
// TPM hardware details step-ca's ACME-tpm validator demands.
//
// step-ca looks for a directoryName SAN entry whose RDN sequence
// includes the three TCG OIDs (manufacturer / model / version)
// plus a URI SAN with the EK URN.
//
// Go's crypto/x509 doesn't let us set directoryName SANs via the
// Certificate template, so we build the raw extension and attach
// it via ExtraExtensions.

package attestca

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

var (
	oidTPMManufacturer = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	oidTPMModel        = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	oidTPMVersion      = asn1.ObjectIdentifier{2, 23, 133, 2, 3}

	oidExtensionSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

type tpmDetails struct {
	Manufacturer string
	Model        string
	Version      string
}

func buildSANExtension(ekURI string, td tpmDetails) (pkix.Extension, error) {
	dirName, err := buildTPMDirectoryName(td)
	if err != nil {
		return pkix.Extension{}, err
	}

	dirNameRaw, err := asn1.Marshal(dirName)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshal RDNSequence: %w", err)
	}

	directoryNameSAN := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        4,
		IsCompound: true,
		Bytes:      dirNameRaw,
	}
	uriSAN := asn1.RawValue{
		Class: asn1.ClassContextSpecific,
		Tag:   6,
		Bytes: []byte(ekURI),
	}

	extBytes, err := asn1.Marshal([]asn1.RawValue{directoryNameSAN, uriSAN})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshal SAN sequence: %w", err)
	}

	return pkix.Extension{
		Id:       oidExtensionSubjectAltName,
		Critical: true,
		Value:    extBytes,
	}, nil
}

// buildTPMDirectoryName constructs an RDN sequence (pkix.RDNSequence)
// with the three TCG OIDs as PrintableString values.
func buildTPMDirectoryName(td tpmDetails) (pkix.RDNSequence, error) {
	if td.Manufacturer == "" || td.Model == "" || td.Version == "" {
		return nil, fmt.Errorf("tpm details: all three fields required")
	}
	return pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type: oidTPMManufacturer,
				Value: asn1.RawValue{
					Tag:   asn1.TagUTF8String,
					Bytes: []byte(td.Manufacturer),
				},
			},
		},
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type: oidTPMModel,
				Value: asn1.RawValue{
					Tag:   asn1.TagUTF8String,
					Bytes: []byte(td.Model),
				},
			},
		},
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type: oidTPMVersion,
				Value: asn1.RawValue{
					Tag:   asn1.TagUTF8String,
					Bytes: []byte(td.Version),
				},
			},
		},
	}, nil
}
