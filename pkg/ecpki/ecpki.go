// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package ecpki provides helpers to manage a Public Key Infrastructure.
package ecpki

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"crypto/ecdsa"
	"crypto/elliptic"
	"github.com/agileinsider/easypki/pkg/certificate"
	"github.com/agileinsider/easypki/pkg/store"
)

// Signing errors.
var (
	ErrCannotSelfSignNonCA = errors.New("cannot self sign non CA request")
	ErrMaxPathLenReached   = errors.New("max path len reached")
)

// Request is a struct for providing configuration to
// GenerateCertificate when actioning a certification generation request.
type Request struct {
	Name                string
	IsClientCertificate bool
	Template            *x509.Certificate
}

// EcPki wraps helpers to handle a Public Key Infrastructure.
type EcPki struct {
	Store store.Store
}

// GetCA fetches and returns the named Certificate Authrority bundle
// from the store.
func (e *EcPki) GetCA(name string) (*certificate.Bundle, error) {
	return e.GetBundle(name, name)
}

// GetBundle fetches and returns a certificate bundle from the store.
func (e *EcPki) GetBundle(caName, name string) (*certificate.Bundle, error) {
	k, c, err := e.Store.Fetch(caName, name)
	if err != nil {
		return nil, fmt.Errorf("failed fetching bundle %v within CA %v: %v", name, caName, err)
	}

	return certificate.RawToBundle(name, k, c)
}

var curve = elliptic.P521()

// Sign signs a generated certificate bundle based on the given request with
// the given signer.
func (e *EcPki) Sign(signer *certificate.Bundle, req *Request) error {
	if !req.Template.IsCA && signer == nil {
		return ErrCannotSelfSignNonCA
	}
	if req.Template.IsCA && signer != nil && signer.Cert.MaxPathLen == 0 {
		return ErrMaxPathLenReached
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return fmt.Errorf("failed generating private key: %v", err)
	}
	publicKey := privateKey.Public()

	if err := defaultTemplate(req, publicKey); err != nil {
		return fmt.Errorf("failed updating generation request: %v", err)
	}

	if req.Template.IsCA {
		var intermediateCA bool
		if signer != nil {
			intermediateCA = true
			if signer.Cert.MaxPathLen > 0 {
				req.Template.MaxPathLen = signer.Cert.MaxPathLen - 1
			}
		}
		if err := caTemplate(req, intermediateCA); err != nil {
			return fmt.Errorf("failed updating generation request for CA: %v", err)
		}
		if !intermediateCA {
			// Use the generated certificate template and private key (self-signing).
			signer = &certificate.Bundle{Name: req.Name, Cert: req.Template, Key: privateKey}
		}
	} else {
		nonCATemplate(req)
	}

	rawCert, err := x509.CreateCertificate(rand.Reader, req.Template, signer.Cert, publicKey, signer.Key)
	if err != nil {
		return fmt.Errorf("failed creating and signing certificate: %v", err)
	}

	keyBytes, error := x509.MarshalECPrivateKey(privateKey)
	if error != nil {
		return fmt.Errorf("failed saving generated bundle: %v", err)
	}
	if err := e.Store.Add(signer.Name, req.Name, req.Template.IsCA, keyBytes, rawCert); err != nil {
		return fmt.Errorf("failed saving generated bundle: %v", err)
	}
	return nil
}

// Revoke revokes the given certificate from the store.
func (e *EcPki) Revoke(caName string, cert *x509.Certificate) error {
	if err := e.Store.Update(caName, cert.SerialNumber, certificate.Revoked); err != nil {
		return fmt.Errorf("failed revoking certificate: %v", err)
	}
	return nil
}

// CRL builds a CRL for a given CA based on the revoked certs.
func (e *EcPki) CRL(caName string, expire time.Time) ([]byte, error) {
	revoked, err := e.Store.Revoked(caName)
	if err != nil {
		return nil, fmt.Errorf("failed retrieving revoked certificates for %v: %v", caName, err)
	}
	ca, err := e.GetCA(caName)
	if err != nil {
		return nil, fmt.Errorf("failed retrieving CA bundle %v: %v", caName, err)
	}

	crl, err := ca.Cert.CreateCRL(rand.Reader, ca.Key, revoked, time.Now(), expire)
	if err != nil {
		return nil, fmt.Errorf("failed creating crl for %v: %v", caName, err)
	}
	return crl, nil
}
