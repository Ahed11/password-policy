package history

import "time"

type Record struct {
	Subject       string    `json:"subject"`
	Salt          []byte    `json:"salt"`
	Hash          []byte    `json:"hash"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	PolicyName    string    `json:"policy_name"`
	PolicyVersion string    `json:"policy_version"`
}
