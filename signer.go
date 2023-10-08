package kmssigner

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const (
	defaultGetPublicKeyTimeout = time.Second * 10
	defaultSignTimeout         = time.Second * 10
)

// Signer can sign arbitrary bytes.
type Signer struct {
	kmsClient   *kms.Client
	kmsKeyId    string
	signingAlgo types.SigningAlgorithmSpec

	getPublicKeyTimeout time.Duration
	signTimeout         time.Duration

	publicKey crypto.PublicKey
}

// ensure Signer implements crypto.Signer.
var _ crypto.Signer = (*Signer)(nil)

// Option represents a configuration option for the signer.
type Option func(s *Signer)

// WithGetPublicKeyTimeout sets the timeout for the GetPublicKey operation (aws kms api call).
func WithGetPublicKeyTimeout(timeout time.Duration) Option {
	return func(s *Signer) { s.getPublicKeyTimeout = timeout }
}

// WithSignTimeout sets the timeout for the Sign operation (aws kms api call).
func WithSignTimeout(timeout time.Duration) Option {
	return func(s *Signer) { s.signTimeout = timeout }
}

// NewSigner returns a new signer
func NewSigner(
	cfg aws.Config,
	kmsKeyId string,
	signingAlgo types.SigningAlgorithmSpec,
	opts ...Option,
) (*Signer, error) {
	signer := &Signer{
		kmsClient:   kms.NewFromConfig(cfg),
		kmsKeyId:    kmsKeyId,
		signingAlgo: signingAlgo,

		getPublicKeyTimeout: defaultGetPublicKeyTimeout,
		signTimeout:         defaultSignTimeout,

		publicKey: nil, // retrieved after settings opts
	}

	for _, opt := range opts {
		opt(signer)
	}

	if err := signer.retrieveAndCachePublicKey(); err != nil {
		return nil, fmt.Errorf("failed to retrieve public key for signer: %v", err)
	}

	return signer, nil
}

// retrieveAndCachePublicKey retrieves and stores the public key for the signer's aws kms key.
func (s *Signer) retrieveAndCachePublicKey() error {
	ctx, cancel := context.WithTimeout(context.Background(), s.getPublicKeyTimeout)
	defer cancel()

	getPublicKeyOutput, err := s.kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(s.kmsKeyId)})
	if err != nil {
		return fmt.Errorf("failed to get public key %s from KMS: %v", s.kmsKeyId, err)
	}

	publicKey, err := x509.ParsePKIXPublicKey(getPublicKeyOutput.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key bytes from KMS as a PKIX public key: %s", err)
	}

	s.publicKey = publicKey
	return nil
}

// Public returns the public key for the signer.
func (s *Signer) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs a digest using the private key for the signer (aws kms api call).
func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.signTimeout)
	defer cancel()

	signOutput, err := s.kmsClient.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(s.kmsKeyId),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: s.signingAlgo,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign digest with KMS: %v", err)
	}

	return signOutput.Signature, err
}
