package capture

type Record struct {
	TLSIdent   TLSIdentInfo   `json:"tlsident" yaml:"tlsident" toml:"tlsident"`
	Connection ConnectionInfo `json:"connection" yaml:"connection" toml:"connection"`
	TLS        TLSInfo        `json:"tls" yaml:"tls" toml:"tls"`
	HTTP2      HTTP2Info      `json:"http2" yaml:"http2" toml:"http2"`
	HTTP       HTTPInfo       `json:"http" yaml:"http" toml:"http"`
}

type TLSIdentInfo struct {
	Version string `json:"version" yaml:"version" toml:"version"`
	Commit  string `json:"commit" yaml:"commit" toml:"commit"`
}

type ConnectionInfo struct {
	ClientIP  string `json:"client_ip" yaml:"client_ip" toml:"client_ip"`
	Timestamp int64  `json:"timestamp" yaml:"timestamp" toml:"timestamp"`
}

type TLSInfo struct {
	JA3Hash             string   `json:"ja3_hash" yaml:"ja3_hash" toml:"ja3_hash"`
	JA3                 string   `json:"ja3" yaml:"ja3" toml:"ja3"`
	JA4                 string   `json:"ja4" yaml:"ja4" toml:"ja4"`
	EnableGREASE        bool     `json:"enable_grease" yaml:"enable_grease" toml:"enable_grease"`
	CipherSuites        []uint16 `json:"cipher_suites" yaml:"cipher_suites" toml:"cipher_suites"`
	Curves              []uint16 `json:"curves" yaml:"curves" toml:"curves"`
	PointFormats        []int    `json:"point_formats" yaml:"point_formats" toml:"point_formats"`
	SignatureAlgorithms []uint16 `json:"signature_algorithms" yaml:"signature_algorithms" toml:"signature_algorithms"`
	ALPNProtocols       []string `json:"alpn_protocols" yaml:"alpn_protocols" toml:"alpn_protocols"`
	SupportedVersions   []uint16 `json:"supported_versions" yaml:"supported_versions" toml:"supported_versions"`
	KeyShareGroups      []uint16 `json:"key_share_groups" yaml:"key_share_groups" toml:"key_share_groups"`
	PSKModes            []int    `json:"psk_modes" yaml:"psk_modes" toml:"psk_modes"`
	Extensions          []uint16 `json:"extensions" yaml:"extensions" toml:"extensions"`
	CompressCertAlgos   []uint16 `json:"compress_cert_algos" yaml:"compress_cert_algos" toml:"compress_cert_algos"`
}

type HTTP2Info struct {
	Fingerprint string `json:"fingerprint" yaml:"fingerprint" toml:"fingerprint"`
}

type HTTPInfo struct {
	Program        string              `json:"program" yaml:"program" toml:"program"`
	UserAgent      string              `json:"user_agent" yaml:"user_agent" toml:"user_agent"`
	Model          string              `json:"model" yaml:"model" toml:"model"`
	OS             string              `json:"os" yaml:"os" toml:"os"`
	Arch           string              `json:"arch" yaml:"arch" toml:"arch"`
	Runtime        string              `json:"runtime" yaml:"runtime" toml:"runtime"`
	RuntimeVersion string              `json:"runtime_version" yaml:"runtime_version" toml:"runtime_version"`
	Lang           string              `json:"lang" yaml:"lang" toml:"lang"`
	SDKVersion     string              `json:"sdk_version" yaml:"sdk_version" toml:"sdk_version"`
	Method         string              `json:"method" yaml:"method" toml:"method"`
	Path           string              `json:"path" yaml:"path" toml:"path"`
	Headers        map[string][]string `json:"headers,omitempty" yaml:"headers,omitempty" toml:"headers,omitempty"`
}
