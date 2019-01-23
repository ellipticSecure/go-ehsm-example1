/*
 * Copyright (c) 2018 ellipticSecure - https://ellipticsecure.com
 *
 * All rights reserved.
 *
 * You may only use this code under the terms of the ellipticSecure software license.
 *
 */

// ECC example code for the eHSM Hardware Security Module
package main

import (
	"github.com/miekg/pkcs11"
	"log"
	"os"
)

// Test sign and verify using the ECDSA mechanism
func signVerifyData(logger *log.Logger, p *pkcs11.Ctx, session pkcs11.SessionHandle,
	pvk pkcs11.ObjectHandle, pbk pkcs11.ObjectHandle) error {

	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}
	var data = []byte{1, 2, 3, 4, 5, 6, 7, 8}

	var err = p.SignInit(session, mechanism, pvk)
	if err != nil {
		logger.Println("Sign init failed.", err)
	} else {
		var sig []byte
		sig, err = p.Sign(session, data)
		if err == nil {
			log.Print("Signed data.")
			err = p.VerifyInit(session, mechanism, pbk)
			if err == nil {
				err = p.Verify(session, data, sig)
				if err == nil {
					log.Print("Verified data.")
				}
			}
		}
	}
	return err
}

// Generate an ECC keypair on curve P256 for testing in volatile storage (ie. CKA_TOKEN is false)
func generateECPair(p *pkcs11.Ctx, session pkcs11.SessionHandle) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {

	publicKeyTemplate := []*pkcs11.Attribute{
		// oid of P256
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "example1_test"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, 99),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, false),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "example1_test"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, 99),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, false),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	}

	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}

	return p.GenerateKeyPair(session, mechanism, publicKeyTemplate, privateKeyTemplate)
}

func main() {
	// change to your user (SU) password
	password := "testsu"

	// change to point to the shared library for your platform
	// or set EHSM_LIB environment variable
	libname := "/usr/local/lib/libehsm.dylib"
	if temp := os.Getenv("EHSM_LIB"); temp != "" {
		libname = temp
	}
	var logger = log.New(os.Stdout, "", log.LstdFlags)
	logger.Printf("Loading shared library %s.", libname)

	p := pkcs11.New(libname)
	if p != nil {
		var err error
		err = p.Initialize()
		if err == nil {
			defer p.Destroy()
			defer p.Finalize()
			var slots []uint
			slots, err = p.GetSlotList(true)
			if err == nil {
				logger.Printf("Slot count: %d.", len(slots))
				if len(slots) > 0 {
					logger.Println("Using slot 0.")
					var session pkcs11.SessionHandle
					session, err = p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
					if err == nil {
						err = p.Login(session, pkcs11.CKU_USER, password)
						if err == nil {
							logger.Print("Logged in, generating ECC key.")
							var pbk pkcs11.ObjectHandle
							var pvk pkcs11.ObjectHandle
							pbk, pvk, err = generateECPair(p, session)
							if err == nil {
								logger.Print("ECC Key Generated.")
								err = signVerifyData(logger, p, session, pvk, pbk)
							}
						}
					}
				} else {
					logger.Println("No tokens found.")
				}
			}
		}
		if err != nil {
			logger.Panicln(err)
		}
	} else {
		logger.Panicln("Could not load eHSM shared library.")
	}
}
