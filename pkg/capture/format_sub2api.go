package capture

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Sub2APIFormatter writes records as Sub2API YAML profiles.
type Sub2APIFormatter struct{}

func (Sub2APIFormatter) Suffix() string { return ".sub2api.yml" }

func (Sub2APIFormatter) Format(record Record) ([]byte, error) {
	var buf strings.Builder
	if err := formatSub2APIRecord(&buf, record); err != nil {
		return nil, fmt.Errorf("format record: %w", err)
	}
	return []byte(buf.String()), nil
}

func formatSub2APIRecord(buf *strings.Builder, rec Record) error {
	key := buildProfileKey(rec)
	name := buildProfileName(rec)

	fmt.Fprintf(buf, "# TLS Fingerprint Profile for Sub2API\n")
	fmt.Fprintf(buf, "# JA3 Hash: %s\n", rec.TLS.JA3Hash)
	fmt.Fprintf(buf, "# JA4: %s\n", rec.TLS.JA4)
	fmt.Fprintf(buf, "# Model: %s\n", rec.HTTP.Model)
	fmt.Fprintf(buf, "# Platform: OS: %s, Arch: %s, Runtime: %s, Runtime Version: %s, Lang: %s, SDK Version: %s\n",
		rec.HTTP.OS, rec.HTTP.Arch, rec.HTTP.Runtime,
		rec.HTTP.RuntimeVersion, rec.HTTP.Lang, rec.HTTP.SDKVersion,
	)

	profile := sub2apiProfile{
		Name:                name,
		EnableGREASE:        rec.TLS.EnableGREASE,
		CipherSuites:        toIntSlice(rec.TLS.CipherSuites),
		Curves:              toIntSlice(rec.TLS.Curves),
		PointFormats:        rec.TLS.PointFormats,
		SignatureAlgorithms: toIntSlice(rec.TLS.SignatureAlgorithms),
		ALPNProtocols:       rec.TLS.ALPNProtocols,
		SupportedVersions:   toIntSlice(rec.TLS.SupportedVersions),
		KeyShareGroups:      toIntSlice(rec.TLS.KeyShareGroups),
		PSKModes:            rec.TLS.PSKModes,
	}

	body, err := yaml.Marshal(map[string]*sub2apiProfile{key: &profile})
	if err != nil {
		return err
	}
	buf.Write(body)

	fmt.Fprintf(buf, "  # -- Reference (extension order, cert compression) --\n")
	fmt.Fprintf(buf, "  # extensions: %s\n", formatIntSlice(toIntSlice(rec.TLS.Extensions)))

	return nil
}

type sub2apiProfile struct {
	Name                string   `yaml:"name"`
	EnableGREASE        bool     `yaml:"enable_grease"`
	CipherSuites        []int    `yaml:"cipher_suites,flow"`
	Curves              []int    `yaml:"curves,flow"`
	PointFormats        []int    `yaml:"point_formats,flow"`
	SignatureAlgorithms []int    `yaml:"signature_algorithms,flow"`
	ALPNProtocols       []string `yaml:"alpn_protocols,flow"`
	SupportedVersions   []int    `yaml:"supported_versions,flow"`
	KeyShareGroups      []int    `yaml:"key_share_groups,flow"`
	PSKModes            []int    `yaml:"psk_modes,flow"`
}

func buildProfileKey(rec Record) string {
	os := sanitize(rec.HTTP.OS)
	arch := sanitize(rec.HTTP.Arch)
	runtime := sanitize(rec.HTTP.Runtime)
	version := sanitize(rec.HTTP.RuntimeVersion)
	return fmt.Sprintf("%s_%s_%s_%s", os, arch, runtime, version)
}

func buildProfileName(rec Record) string {
	os := capitalize(sanitize(rec.HTTP.OS))
	arch := sanitize(rec.HTTP.Arch)
	runtime := sanitize(rec.HTTP.Runtime)
	version := sanitize(rec.HTTP.RuntimeVersion)
	return fmt.Sprintf("%s_%s_%s_%s", os, arch, runtime, version)
}

func sanitize(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, ".", "")
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "-", "_")
	return s
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func toIntSlice(u []uint16) []int {
	out := make([]int, len(u))
	for i, v := range u {
		out[i] = int(v)
	}
	return out
}

func formatIntSlice(vals []int) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
