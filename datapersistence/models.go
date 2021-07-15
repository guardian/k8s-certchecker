package datapersistence

import (
	"time"
)

type ValidationResult int

const (
	Errored = iota
	NotValidYet
	WithinRange
	NearExpiry
	AfterExpiry
	TooLongForChrome
)

type CheckRecord struct {
	Namespace        string           `json:"namespace"`
	SecretName       string           `json:"secretName"`
	CheckedAt        time.Time        `json:"checkedAt"`
	CheckResult      ValidationResult `json:"result"`
	ValidUntil       time.Time        `json:"validUntil"`
	PercentUsed      float64          `json:"percentUsed"`
	TooLongForChrome bool             `json:"tooLongForChrome"`
}

type PersistenceRecord struct {
	CheckedAt time.Time     `json:"checkedAt"`
	Results   []CheckRecord `json:"results"`
}
