package peetws

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	apicommon "tlsident/pkg/api/common"
	"tlsident/pkg/tlsfp"
)

const donateMessage = "Please consider donating to keep this API running. Visit https://tls.peet.ws"

type Service struct{}

func NewService() *Service {
	return &Service{}
}

func (s *Service) Handle(ctx apicommon.RequestContext) apicommon.Response {
	switch {
	case ctx.Method != "GET":
		return jsonResponse(405, map[string]string{"error": "method not allowed"})
	case ctx.Path == "/api/all":
		return jsonResponse(200, buildAllResponse(ctx))
	case ctx.Path == "/api/clean":
		return jsonResponse(200, buildCleanResponse(ctx))
	case ctx.Path == "/api/tls":
		return jsonResponse(200, buildTLSOnlyResponse(ctx))
	default:
		return jsonResponse(404, map[string]string{"error": "not found"})
	}
}

type allResponse struct {
	Donate      string         `json:"donate"`
	IP          string         `json:"ip"`
	HTTPVersion string         `json:"http_version"`
	Method      string         `json:"method"`
	UserAgent   string         `json:"user_agent"`
	TLS         tlsResponse    `json:"tls"`
	HTTP1       *http1Response `json:"http1,omitempty"`
	HTTP2       *http2Response `json:"http2,omitempty"`
	TCPIP       tcpipResponse  `json:"tcpip"`
}

type cleanResponse struct {
	JA3           string `json:"ja3"`
	JA3Hash       string `json:"ja3_hash"`
	JA4           string `json:"ja4"`
	JA4R          string `json:"ja4_r"`
	Akamai        string `json:"akamai"`
	AkamaiHash    string `json:"akamai_hash"`
	Peetprint     string `json:"peetprint"`
	PeetprintHash string `json:"peetprint_hash"`
	HTTPVersion   string `json:"http_version"`
}

type tlsOnlyResponse struct {
	Donate      string        `json:"donate"`
	IP          string        `json:"ip"`
	HTTPVersion string        `json:"http_version"`
	Method      string        `json:"method"`
	TLS         tlsResponse   `json:"tls"`
	TCPIP       tcpipResponse `json:"tcpip"`
}

type tlsResponse struct {
	Ciphers              []string         `json:"ciphers"`
	Extensions           []map[string]any `json:"extensions"`
	TLSVersionRecord     string           `json:"tls_version_record"`
	TLSVersionNegotiated string           `json:"tls_version_negotiated"`
	JA3                  string           `json:"ja3"`
	JA3Hash              string           `json:"ja3_hash"`
	JA4                  string           `json:"ja4"`
	JA4R                 string           `json:"ja4_r"`
	Peetprint            string           `json:"peetprint"`
	PeetprintHash        string           `json:"peetprint_hash"`
	ClientRandom         string           `json:"client_random"`
	SessionID            string           `json:"session_id"`
}

type http1Response struct {
	Headers []string `json:"headers"`
}

type http2Response struct {
	AkamaiFingerprint     string           `json:"akamai_fingerprint"`
	AkamaiFingerprintHash string           `json:"akamai_fingerprint_hash"`
	SentFrames            []map[string]any `json:"sent_frames"`
}

type tcpipResponse struct {
	SrcPort int            `json:"src_port,omitempty"`
	IP      map[string]any `json:"ip"`
	TCP     map[string]any `json:"tcp"`
}

func buildAllResponse(ctx apicommon.RequestContext) allResponse {
	response := allResponse{
		Donate:      donateMessage,
		IP:          remoteAddress(ctx.Connection.ClientIP, ctx.ClientPort),
		HTTPVersion: ctx.Protocol,
		Method:      ctx.Method,
		UserAgent:   firstHeader(ctx.Headers, "user-agent"),
		TLS:         buildTLSResponse(ctx),
		TCPIP:       tcpipResponse{SrcPort: ctx.ClientPort, IP: map[string]any{}, TCP: map[string]any{}},
	}

	if ctx.Protocol == "h2" {
		payload := buildHTTP2Response(ctx)
		response.HTTP2 = &payload
	} else {
		response.HTTP1 = &http1Response{Headers: append([]string(nil), ctx.HTTP1.HeaderLines...)}
	}

	return response
}

func buildCleanResponse(ctx apicommon.RequestContext) cleanResponse {
	akamai := "-"
	akamaiHash := "-"
	if ctx.Protocol == "h2" {
		akamai = ctx.HTTP2.Fingerprint
		akamaiHash = md5Hex(akamai)
	}

	tlsPayload := buildTLSResponse(ctx)
	return cleanResponse{
		JA3:           tlsPayload.JA3,
		JA3Hash:       tlsPayload.JA3Hash,
		JA4:           tlsPayload.JA4,
		JA4R:          tlsPayload.JA4R,
		Akamai:        akamai,
		AkamaiHash:    akamaiHash,
		Peetprint:     tlsPayload.Peetprint,
		PeetprintHash: tlsPayload.PeetprintHash,
		HTTPVersion:   ctx.Protocol,
	}
}

func buildTLSOnlyResponse(ctx apicommon.RequestContext) tlsOnlyResponse {
	return tlsOnlyResponse{
		Donate:      "",
		IP:          "",
		HTTPVersion: "",
		Method:      "",
		TLS:         buildTLSResponse(ctx),
		TCPIP:       tcpipResponse{IP: map[string]any{}, TCP: map[string]any{}},
	}
}

func buildTLSResponse(ctx apicommon.RequestContext) tlsResponse {
	hello := ctx.ClientHello

	ja4r := ""
	clientRandom := ""
	sessionID := ""
	if hello != nil {
		ja4r = hello.JA4R()
		clientRandom = hex.EncodeToString(hello.Random)
		sessionID = hex.EncodeToString(hello.SessionID)
	}
	if ja4r == "" {
		ja4r = ctx.TLS.JA4
	}

	peetprint := buildPeetprint(ctx, hello)
	return tlsResponse{
		Ciphers:              cipherNames(ctx.TLS.CipherSuites),
		Extensions:           extensionPayloads(hello),
		TLSVersionRecord:     strconv.Itoa(legacyVersion(hello, ctx.TLS.JA3)),
		TLSVersionNegotiated: strconv.Itoa(negotiatedVersion(hello)),
		JA3:                  ctx.TLS.JA3,
		JA3Hash:              ctx.TLS.JA3Hash,
		JA4:                  ctx.TLS.JA4,
		JA4R:                 ja4r,
		Peetprint:            peetprint,
		PeetprintHash:        md5Hex(peetprint),
		ClientRandom:         clientRandom,
		SessionID:            sessionID,
	}
}

func buildHTTP2Response(ctx apicommon.RequestContext) http2Response {
	frames := make([]map[string]any, 0, 3)
	settings, increment := parseAkamaiFingerprint(ctx.HTTP2.Fingerprint)

	if len(settings) > 0 {
		formatted := make([]string, 0, len(settings))
		for _, setting := range settings {
			formatted = append(formatted, formatHTTP2Setting(setting.id, setting.value))
		}
		frames = append(frames, map[string]any{
			"frame_type": "SETTINGS",
			"length":     len(settings) * 6,
			"settings":   formatted,
		})
	}

	if increment != "" && increment != "00" {
		frames = append(frames, map[string]any{
			"frame_type": "WINDOW_UPDATE",
			"length":     4,
			"increment":  mustAtoi(increment),
		})
	}

	headers := make([]string, 0, len(ctx.HTTP2Req.HeaderFields))
	for _, field := range ctx.HTTP2Req.HeaderFields {
		headers = append(headers, field.Name+": "+field.Value)
	}
	flags := []string{"EndHeaders (0x4)"}
	if ctx.HTTP2Req.EndStream {
		flags = append([]string{"EndStream (0x1)"}, flags...)
	}
	frames = append(frames, map[string]any{
		"frame_type": "HEADERS",
		"stream_id":  ctx.HTTP2Req.StreamID,
		"length":     ctx.HTTP2Req.HeaderBlockLength,
		"headers":    headers,
		"flags":      flags,
	})

	return http2Response{
		AkamaiFingerprint:     ctx.HTTP2.Fingerprint,
		AkamaiFingerprintHash: md5Hex(ctx.HTTP2.Fingerprint),
		SentFrames:            frames,
	}
}

func buildPeetprint(ctx apicommon.RequestContext, hello *tlsfp.ClientHello) string {
	if hello == nil {
		return ""
	}

	extensions := append([]uint16(nil), hello.Extensions...)
	sort.Slice(extensions, func(i, j int) bool { return extensions[i] < extensions[j] })

	parts := []string{
		strconv.Itoa(negotiatedVersion(hello)),
		strconv.Itoa(legacyVersion(hello, ctx.TLS.JA3)),
	}

	protocols := make([]string, 0, len(hello.ALPNProtocols))
	for _, protocol := range hello.ALPNProtocols {
		protocols = append(protocols, peetALPN(protocol))
	}

	segments := []string{
		strings.Join(parts, "-"),
		strings.Join(protocols, "-"),
		joinUint16(hello.Curves),
		joinUint16(hello.SignatureAlgorithms),
		joinUint8Ints(hello.PSKModes),
		joinUint16(hello.CompressCertAlgos),
		joinUint16(hello.CipherSuites),
		joinUint16(extensions),
	}
	return strings.Join(segments, "|")
}

func extensionPayloads(hello *tlsfp.ClientHello) []map[string]any {
	if hello == nil {
		return nil
	}

	payloads := make([]map[string]any, 0, len(hello.RawExtensions))
	for _, ext := range hello.RawExtensions {
		name := extensionName(ext.Type)
		switch ext.Type {
		case 0:
			payloads = append(payloads, map[string]any{
				"name":        name,
				"server_name": hello.ServerName,
			})
		case 10:
			groups := make([]string, 0, len(hello.Curves))
			for _, group := range hello.Curves {
				groups = append(groups, namedGroup(group))
			}
			payloads = append(payloads, map[string]any{
				"name":             name,
				"supported_groups": groups,
			})
		case 11:
			formats := make([]string, 0, len(hello.PointFormats))
			for _, value := range hello.PointFormats {
				formats = append(formats, fmt.Sprintf("0x%02x", value))
			}
			payloads = append(payloads, map[string]any{
				"name":                          name,
				"elliptic_curves_point_formats": formats,
			})
		case 13:
			algorithms := make([]string, 0, len(hello.SignatureAlgorithms))
			for _, value := range hello.SignatureAlgorithms {
				algorithms = append(algorithms, signatureAlgorithmName(value))
			}
			payloads = append(payloads, map[string]any{
				"name":                 name,
				"signature_algorithms": algorithms,
			})
		case 16:
			payloads = append(payloads, map[string]any{
				"name":      name,
				"protocols": append([]string(nil), hello.ALPNProtocols...),
			})
		case 23:
			payloads = append(payloads, map[string]any{
				"name":                        name,
				"master_secret_data":          "",
				"extended_master_secret_data": "",
			})
		case 43:
			versions := make([]string, 0, len(hello.SupportedVersions))
			for _, value := range hello.SupportedVersions {
				versions = append(versions, tls.VersionName(value))
			}
			payloads = append(payloads, map[string]any{
				"name":     name,
				"versions": versions,
			})
		case 45:
			payloads = append(payloads, map[string]any{
				"name":                  name,
				"PSK_Key_Exchange_Mode": pskModesString(hello.PSKModes),
			})
		case 51:
			sharedKeys := make([]map[string]string, 0, len(hello.KeyShares))
			for _, keyShare := range hello.KeyShares {
				sharedKeys = append(sharedKeys, map[string]string{
					namedGroup(keyShare.Group): hex.EncodeToString(keyShare.Data),
				})
			}
			payloads = append(payloads, map[string]any{
				"name":        name,
				"shared_keys": sharedKeys,
			})
		default:
			payloads = append(payloads, map[string]any{
				"name": name,
				"data": hex.EncodeToString(ext.Data),
			})
		}
	}

	return payloads
}

func cipherNames(values []uint16) []string {
	names := make([]string, 0, len(values))
	for _, value := range values {
		if name, ok := cipherSuiteNames[value]; ok {
			names = append(names, name)
			continue
		}
		names = append(names, tls.CipherSuiteName(value))
	}
	return names
}

func remoteAddress(host string, port int) string {
	if host == "" {
		return ""
	}
	if port <= 0 {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func legacyVersion(hello *tlsfp.ClientHello, ja3 string) int {
	if hello != nil {
		return int(hello.LegacyVersion)
	}
	parts := strings.SplitN(ja3, ",", 2)
	if len(parts) == 0 {
		return 0
	}
	return mustAtoi(parts[0])
}

func negotiatedVersion(hello *tlsfp.ClientHello) int {
	if hello == nil {
		return 0
	}
	maxVersion := int(hello.LegacyVersion)
	for _, version := range hello.SupportedVersions {
		if int(version) > maxVersion {
			maxVersion = int(version)
		}
	}
	return maxVersion
}

func peetALPN(protocol string) string {
	switch protocol {
	case "h2":
		return "2"
	case "http/1.1":
		return "1.1"
	default:
		return protocol
	}
}

func joinUint16(values []uint16) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Itoa(int(value)))
	}
	return strings.Join(parts, "-")
}

func joinUint8Ints(values []uint8) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Itoa(int(value)))
	}
	return strings.Join(parts, "-")
}

func extensionName(id uint16) string {
	switch id {
	case 0:
		return "server_name (0)"
	case 10:
		return "supported_groups (10)"
	case 11:
		return "ec_point_formats (11)"
	case 13:
		return "signature_algorithms (13)"
	case 16:
		return "application_layer_protocol_negotiation (16)"
	case 22:
		return "encrypt_then_mac (22)"
	case 23:
		return "extended_master_secret (23)"
	case 43:
		return "supported_versions (43)"
	case 45:
		return "psk_key_exchange_modes (45)"
	case 49:
		return "post_handshake_auth (49)"
	case 51:
		return "key_share (51)"
	case 65281:
		return "extensionRenegotiationInfo (boringssl) (65281)"
	default:
		return fmt.Sprintf("extension (%d)", id)
	}
}

func namedGroup(value uint16) string {
	if name, ok := namedGroupNames[value]; ok {
		return fmt.Sprintf("%s (%d)", name, value)
	}
	return fmt.Sprintf("%s (%d)", tls.CurveID(value), value)
}

func signatureAlgorithmName(value uint16) string {
	if name, ok := signatureAlgorithmNames[value]; ok {
		return name
	}
	return fmt.Sprintf("0x%x", value)
}

var signatureAlgorithmNames = map[uint16]string{
	0x0401: "rsa_pkcs1_sha256",
	0x0501: "rsa_pkcs1_sha384",
	0x0601: "rsa_pkcs1_sha512",
	0x0301: "rsa_pkcs1_sha1",
	0x0403: "ecdsa_secp256r1_sha256",
	0x0503: "ecdsa_secp384r1_sha384",
	0x0603: "ecdsa_secp521r1_sha512",
	0x0303: "ecdsa_sha1",
	0x0804: "rsa_pss_rsae_sha256",
	0x0805: "rsa_pss_rsae_sha384",
	0x0806: "rsa_pss_rsae_sha512",
	0x0807: "ed25519",
	0x0808: "ed448",
	0x0809: "rsa_pss_pss_sha256",
	0x080a: "rsa_pss_pss_sha384",
	0x080b: "rsa_pss_pss_sha512",
	0x081a: "ecdsa_brainpoolP256r1tls13_sha256",
	0x081b: "ecdsa_brainpoolP384r1tls13_sha384",
	0x081c: "ecdsa_brainpoolP512r1tls13_sha512",
}

var cipherSuiteNames = map[uint16]string{
	0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	0x003d: "TLS_RSA_WITH_AES_256_CBC_SHA256",
	0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	0x006b: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
	0x009e: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	0x009f: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	0xc024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	0xc028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	0xccaa: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
}

var namedGroupNames = map[uint16]string{
	23:   "P-256",
	24:   "P-384",
	25:   "P-521",
	29:   "X25519",
	30:   "X448",
	256:  "ffdhe2048",
	257:  "ffdhe3072",
	4588: "X25519MLKEM768",
}

func pskModesString(values []uint8) string {
	if len(values) == 0 {
		return ""
	}
	if len(values) == 1 {
		return pskModeName(values[0])
	}
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, pskModeName(value))
	}
	return strings.Join(parts, ", ")
}

func pskModeName(value uint8) string {
	switch value {
	case 0:
		return "PSK-only key establishment (psk_ke) (0)"
	case 1:
		return "PSK with (EC)DHE key establishment (psk_dhe_ke) (1)"
	default:
		return fmt.Sprintf("0x%x", value)
	}
}

type http2Setting struct {
	id    int
	value int
}

func parseAkamaiFingerprint(fingerprint string) ([]http2Setting, string) {
	parts := strings.Split(fingerprint, "|")
	if len(parts) < 2 {
		return nil, ""
	}

	var settings []http2Setting
	if parts[0] != "" {
		for _, part := range strings.Split(parts[0], ";") {
			left, right, ok := strings.Cut(part, ":")
			if !ok {
				continue
			}
			settings = append(settings, http2Setting{
				id:    mustAtoi(left),
				value: mustAtoi(right),
			})
		}
	}

	return settings, parts[1]
}

func formatHTTP2Setting(id, value int) string {
	switch id {
	case 1:
		return fmt.Sprintf("HEADER_TABLE_SIZE = %d", value)
	case 2:
		return fmt.Sprintf("ENABLE_PUSH = %d", value)
	case 3:
		return fmt.Sprintf("MAX_CONCURRENT_STREAMS = %d", value)
	case 4:
		return fmt.Sprintf("INITIAL_WINDOW_SIZE = %d", value)
	case 5:
		return fmt.Sprintf("MAX_FRAME_SIZE = %d", value)
	case 6:
		return fmt.Sprintf("MAX_HEADER_LIST_SIZE = %d", value)
	default:
		return fmt.Sprintf("%d = %d", id, value)
	}
}

func firstHeader(headers map[string][]string, key string) string {
	values := headers[strings.ToLower(key)]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func jsonResponse(status int, payload any) apicommon.Response {
	body, _ := json.Marshal(payload)
	return apicommon.Response{
		StatusCode: status,
		Headers: map[string]string{
			"content-type":           "application/json",
			"x-content-type-options": "nosniff",
		},
		Body: body,
	}
}

func md5Hex(value string) string {
	sum := md5.Sum([]byte(value))
	return hex.EncodeToString(sum[:])
}

func mustAtoi(value string) int {
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return parsed
}
