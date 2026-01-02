package models

import "time"

// Confidence represents the certainty of a takeover vulnerability
type Confidence string

const (
	ConfidenceLow    Confidence = "Low"
	ConfidenceMedium Confidence = "Medium"
	ConfidenceHigh   Confidence = "High"
)

// Result represents a single subdomain scanning result
type Result struct {
	Subdomain      string     `json:"subdomain"`
	Provider       string     `json:"provider"`
	IPs            []string   `json:"ips,omitempty"`
	CNAMEs         []string   `json:"cnames,omitempty"`
	NS             []string   `json:"ns,omitempty"`
	HTTPStatus     int        `json:"http_status,omitempty"`
	Fingerprint    string     `json:"fingerprint,omitempty"`
	Confidence     Confidence `json:"confidence"`
	TakeoverPossible bool     `json:"takeover_possible"`
	Evidence       string     `json:"evidence,omitempty"`
	Timestamp      time.Time  `json:"timestamp"`
}

// Fingerprint represents a service signature
type Fingerprint struct {
	Service          string   `yaml:"service"`
	CNAMEPatterns    []string `yaml:"cname_patterns"`
	HTTPStatus       int      `yaml:"http_status,omitempty"`
	BodyContains     []string `yaml:"body_contains,omitempty"`
	TakeoverPossible bool     `yaml:"takeover_possible"`
}
