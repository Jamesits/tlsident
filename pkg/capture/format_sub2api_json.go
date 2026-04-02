package capture

import (
	"encoding/json"
	"time"
)

// Sub2APIJSONFormatter writes records in the upstream /api/latest JSON shape.
type Sub2APIJSONFormatter struct{}

func (Sub2APIJSONFormatter) Suffix() string { return ".sub2api.json" }

func (Sub2APIJSONFormatter) Format(record Record) ([]byte, error) {
	payload := sub2APILatestResponse{
		Count:        1,
		Fingerprints: []sub2APIFingerprint{newSub2APIFingerprint(record)},
	}
	return json.MarshalIndent(payload, "", "  ")
}

type sub2APILatestResponse struct {
	Count        int                  `json:"count"`
	Fingerprints []sub2APIFingerprint `json:"fingerprints"`
}

type sub2APIFingerprint struct {
	ID                      string   `json:"id"`
	Timestamp               string   `json:"timestamp"`
	Model                   string   `json:"model"`
	JA3Raw                  string   `json:"ja3_raw"`
	JA3Hash                 string   `json:"ja3_hash"`
	JA4                     string   `json:"ja4"`
	HTTP2                   string   `json:"http2"`
	UserAgent               string   `json:"user_agent"`
	ClientIP                string   `json:"client_ip"`
	CipherSuites            []int    `json:"cipher_suites"`
	Curves                  []int    `json:"curves"`
	PointFormats            []int    `json:"point_formats"`
	Extensions              []int    `json:"extensions"`
	SignatureAlgorithms     []int    `json:"signature_algorithms"`
	ALPNProtocols           []string `json:"alpn_protocols"`
	SupportedVersions       []int    `json:"supported_versions"`
	KeyShareGroups          []int    `json:"key_share_groups"`
	PSKModes                []int    `json:"psk_modes"`
	CompressCertAlgos       []int    `json:"compress_cert_algos"`
	EnableGREASE            bool     `json:"enable_grease"`
	StainlessOS             string   `json:"stainless_os"`
	StainlessArch           string   `json:"stainless_arch"`
	StainlessRuntime        string   `json:"stainless_runtime"`
	StainlessRuntimeVersion string   `json:"stainless_runtime_version"`
	StainlessLang           string   `json:"stainless_lang"`
	StainlessPackageVersion string   `json:"stainless_package_version"`
}

func newSub2APIFingerprint(rec Record) sub2APIFingerprint {
	return sub2APIFingerprint{
		ID:                      "",
		Timestamp:               formatSub2APITimestamp(rec.Connection.Timestamp),
		Model:                   rec.HTTP.Model,
		JA3Raw:                  rec.TLS.JA3,
		JA3Hash:                 rec.TLS.JA3Hash,
		JA4:                     rec.TLS.JA4,
		HTTP2:                   sub2APIHTTP2Fingerprint(rec.HTTP2),
		UserAgent:               rec.HTTP.UserAgent,
		ClientIP:                rec.Connection.ClientIP,
		CipherSuites:            toIntSlice(rec.TLS.CipherSuites),
		Curves:                  toIntSlice(rec.TLS.Curves),
		PointFormats:            append([]int(nil), rec.TLS.PointFormats...),
		Extensions:              toIntSlice(rec.TLS.Extensions),
		SignatureAlgorithms:     toIntSlice(rec.TLS.SignatureAlgorithms),
		ALPNProtocols:           append([]string(nil), rec.TLS.ALPNProtocols...),
		SupportedVersions:       toIntSlice(rec.TLS.SupportedVersions),
		KeyShareGroups:          toIntSlice(rec.TLS.KeyShareGroups),
		PSKModes:                append([]int(nil), rec.TLS.PSKModes...),
		CompressCertAlgos:       toOptionalIntSlice(rec.TLS.CompressCertAlgos),
		EnableGREASE:            rec.TLS.EnableGREASE,
		StainlessOS:             rec.HTTP.OS,
		StainlessArch:           rec.HTTP.Arch,
		StainlessRuntime:        rec.HTTP.Runtime,
		StainlessRuntimeVersion: rec.HTTP.RuntimeVersion,
		StainlessLang:           rec.HTTP.Lang,
		StainlessPackageVersion: rec.HTTP.SDKVersion,
	}
}

func formatSub2APITimestamp(timestamp int64) string {
	if timestamp <= 0 {
		return ""
	}
	return time.Unix(timestamp, 0).UTC().Format(time.RFC3339Nano)
}

func sub2APIHTTP2Fingerprint(http2 HTTP2Info) string {
	return http2.Fingerprint
}

func toOptionalIntSlice(u []uint16) []int {
	if u == nil {
		return nil
	}
	return toIntSlice(u)
}
