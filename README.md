# kmssigner

[![Go Report Card](https://goreportcard.com/badge/github.com/adrianosela/kmsca-signer)](https://goreportcard.com/report/github.com/adrianosela/kmsca-signer)
[![Documentation](https://godoc.org/github.com/adrianosela/kmsca-signer?status.svg)](https://godoc.org/github.com/adrianosela/kmsca-signer)
[![license](https://img.shields.io/github/license/adrianosela/kmsca-signer.svg)](https://github.com/adrianosela/kmsca-signer/blob/master/LICENSE)

A [`crypto.Signer`](https://pkg.go.dev/crypto#Signer) implementation based on an AWS KMS key.

With AWS KMS keys, the private key never leaves KMS and all signing operations also occur within KMS. This comes with several benefits:

- with KMS the private key cannot be retrieved and thus it cannot be lost or stolen
- under-the-hood KMS uses a [FIPS 140-2 L3 certified Hardware Security Module (HSM)](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4523) to store the key
- all signing operations result in an audit log (via AWS CloudTrail)
- role based access control for signing operations (via AWS IAM)
- multiple region high-availability (if using a multi-region KMS key)

See https://github.com/adrianosela/kmsca for more info.
