package tlsfp

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"tlsident/pkg/capture"
)

type ClientHello struct {
	LegacyVersion       uint16
	ServerName          string
	CipherSuites        []uint16
	Extensions          []uint16
	Curves              []uint16
	PointFormats        []uint8
	SignatureAlgorithms []uint16
	ALPNProtocols       []string
	SupportedVersions   []uint16
	KeyShareGroups      []uint16
	PSKModes            []uint8
	CompressCertAlgos   []uint16
	EnableGREASE        bool
}

func ParseClientHello(message []byte) (*ClientHello, error) {
	if len(message) < 2+32+1 {
		return nil, fmt.Errorf("client hello too short")
	}

	parsed := &ClientHello{}
	parsed.LegacyVersion = binary.BigEndian.Uint16(message[:2])
	offset := 2 + 32

	sessionIDLen := int(message[offset])
	offset++
	if offset+sessionIDLen > len(message) {
		return nil, fmt.Errorf("invalid session id length")
	}
	offset += sessionIDLen

	if offset+2 > len(message) {
		return nil, fmt.Errorf("missing cipher suites length")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(message[offset : offset+2]))
	offset += 2
	if cipherSuitesLen%2 != 0 || offset+cipherSuitesLen > len(message) {
		return nil, fmt.Errorf("invalid cipher suites length")
	}
	for i := offset; i < offset+cipherSuitesLen; i += 2 {
		value := binary.BigEndian.Uint16(message[i : i+2])
		parsed.CipherSuites = append(parsed.CipherSuites, value)
		if IsGREASE16(value) {
			parsed.EnableGREASE = true
		}
	}
	offset += cipherSuitesLen

	if offset >= len(message) {
		return parsed, nil
	}
	compressionMethodsLen := int(message[offset])
	offset++
	if offset+compressionMethodsLen > len(message) {
		return nil, fmt.Errorf("invalid compression methods length")
	}
	offset += compressionMethodsLen

	if offset == len(message) {
		return parsed, nil
	}
	if offset+2 > len(message) {
		return nil, fmt.Errorf("missing extensions length")
	}
	extensionsLen := int(binary.BigEndian.Uint16(message[offset : offset+2]))
	offset += 2
	if offset+extensionsLen > len(message) {
		return nil, fmt.Errorf("invalid extensions length")
	}

	end := offset + extensionsLen
	for offset+4 <= end {
		extType := binary.BigEndian.Uint16(message[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(message[offset+2 : offset+4]))
		offset += 4
		if offset+extLen > end {
			return nil, fmt.Errorf("extension %d overruns client hello", extType)
		}

		parsed.Extensions = append(parsed.Extensions, extType)
		if IsGREASE16(extType) {
			parsed.EnableGREASE = true
		}

		payload := message[offset : offset+extLen]
		if err := parseExtension(parsed, extType, payload); err != nil {
			return nil, err
		}
		offset += extLen
	}

	return parsed, nil
}

func parseExtension(parsed *ClientHello, extType uint16, payload []byte) error {
	switch extType {
	case 0:
		return parseSNI(parsed, payload)
	case 10:
		return parseSupportedGroups(parsed, payload)
	case 11:
		return parsePointFormats(parsed, payload)
	case 13:
		return parseSignatureAlgorithms(parsed, payload)
	case 16:
		return parseALPN(parsed, payload)
	case 27:
		return parseCompressCertificate(parsed, payload)
	case 43:
		return parseSupportedVersions(parsed, payload)
	case 45:
		return parsePSKModes(parsed, payload)
	case 51:
		return parseKeyShare(parsed, payload)
	default:
		return nil
	}
}

func parseSNI(parsed *ClientHello, payload []byte) error {
	if len(payload) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(payload[:2]))
	if 2+listLen > len(payload) {
		return fmt.Errorf("invalid sni extension")
	}
	offset := 2
	for offset+3 <= 2+listLen {
		nameType := payload[offset]
		nameLen := int(binary.BigEndian.Uint16(payload[offset+1 : offset+3]))
		offset += 3
		if offset+nameLen > 2+listLen {
			return fmt.Errorf("invalid sni entry")
		}
		if nameType == 0 && parsed.ServerName == "" {
			parsed.ServerName = string(payload[offset : offset+nameLen])
		}
		offset += nameLen
	}
	return nil
}

func parseSupportedGroups(parsed *ClientHello, payload []byte) error {
	if len(payload) < 2 {
		return nil
	}
	groupsLen := int(binary.BigEndian.Uint16(payload[:2]))
	if 2+groupsLen > len(payload) || groupsLen%2 != 0 {
		return fmt.Errorf("invalid supported groups extension")
	}
	for offset := 2; offset < 2+groupsLen; offset += 2 {
		value := binary.BigEndian.Uint16(payload[offset : offset+2])
		parsed.Curves = append(parsed.Curves, value)
		if IsGREASE16(value) {
			parsed.EnableGREASE = true
		}
	}
	return nil
}

func parsePointFormats(parsed *ClientHello, payload []byte) error {
	if len(payload) < 1 {
		return nil
	}
	listLen := int(payload[0])
	if 1+listLen > len(payload) {
		return fmt.Errorf("invalid point formats extension")
	}
	parsed.PointFormats = append(parsed.PointFormats, payload[1:1+listLen]...)
	return nil
}

func parseSignatureAlgorithms(parsed *ClientHello, payload []byte) error {
	if len(payload) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(payload[:2]))
	if 2+listLen > len(payload) || listLen%2 != 0 {
		return fmt.Errorf("invalid signature algorithms extension")
	}
	for offset := 2; offset < 2+listLen; offset += 2 {
		value := binary.BigEndian.Uint16(payload[offset : offset+2])
		parsed.SignatureAlgorithms = append(parsed.SignatureAlgorithms, value)
		if IsGREASE16(value) {
			parsed.EnableGREASE = true
		}
	}
	return nil
}

func parseALPN(parsed *ClientHello, payload []byte) error {
	if len(payload) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(payload[:2]))
	if 2+listLen > len(payload) {
		return fmt.Errorf("invalid alpn extension")
	}
	offset := 2
	for offset < 2+listLen {
		itemLen := int(payload[offset])
		offset++
		if offset+itemLen > 2+listLen {
			return fmt.Errorf("invalid alpn protocol")
		}
		parsed.ALPNProtocols = append(parsed.ALPNProtocols, string(payload[offset:offset+itemLen]))
		offset += itemLen
	}
	return nil
}

func parseCompressCertificate(parsed *ClientHello, payload []byte) error {
	if len(payload) < 1 {
		return nil
	}
	listLen := int(payload[0])
	if 1+listLen > len(payload) || listLen%2 != 0 {
		return fmt.Errorf("invalid compress certificate extension")
	}
	for offset := 1; offset < 1+listLen; offset += 2 {
		parsed.CompressCertAlgos = append(parsed.CompressCertAlgos, binary.BigEndian.Uint16(payload[offset:offset+2]))
	}
	return nil
}

func parseSupportedVersions(parsed *ClientHello, payload []byte) error {
	if len(payload) < 1 {
		return nil
	}
	listLen := int(payload[0])
	if 1+listLen > len(payload) || listLen%2 != 0 {
		return fmt.Errorf("invalid supported versions extension")
	}
	for offset := 1; offset < 1+listLen; offset += 2 {
		value := binary.BigEndian.Uint16(payload[offset : offset+2])
		parsed.SupportedVersions = append(parsed.SupportedVersions, value)
		if IsGREASE16(value) {
			parsed.EnableGREASE = true
		}
	}
	return nil
}

func parsePSKModes(parsed *ClientHello, payload []byte) error {
	if len(payload) < 1 {
		return nil
	}
	listLen := int(payload[0])
	if 1+listLen > len(payload) {
		return fmt.Errorf("invalid psk modes extension")
	}
	for _, value := range payload[1 : 1+listLen] {
		parsed.PSKModes = append(parsed.PSKModes, value)
		if IsGREASE8(value) {
			parsed.EnableGREASE = true
		}
	}
	return nil
}

func parseKeyShare(parsed *ClientHello, payload []byte) error {
	if len(payload) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(payload[:2]))
	if 2+listLen > len(payload) {
		return fmt.Errorf("invalid key share extension")
	}
	offset := 2
	for offset+4 <= 2+listLen {
		group := binary.BigEndian.Uint16(payload[offset : offset+2])
		exchangeLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		offset += 4
		if offset+exchangeLen > 2+listLen {
			return fmt.Errorf("invalid key share entry")
		}
		parsed.KeyShareGroups = append(parsed.KeyShareGroups, group)
		if IsGREASE16(group) {
			parsed.EnableGREASE = true
		}
		offset += exchangeLen
	}
	return nil
}

func (hello *ClientHello) CaptureTLSInfo() capture.TLSInfo {
	ja3 := hello.JA3()
	ja3HashBytes := md5.Sum([]byte(ja3))

	return capture.TLSInfo{
		JA3Hash:             hex.EncodeToString(ja3HashBytes[:]),
		JA3:                 ja3,
		JA4:                 hello.JA4(),
		EnableGREASE:        hello.EnableGREASE,
		CipherSuites:        append([]uint16(nil), hello.ciphersWithoutGREASE()...),
		Curves:              append([]uint16(nil), hello.curvesWithoutGREASE()...),
		PointFormats:        uint8SliceToInts(hello.PointFormats),
		SignatureAlgorithms: append([]uint16(nil), hello.signatureAlgorithmsWithoutGREASE()...),
		ALPNProtocols:       append([]string(nil), hello.ALPNProtocols...),
		SupportedVersions:   append([]uint16(nil), hello.supportedVersionsWithoutGREASE()...),
		KeyShareGroups:      append([]uint16(nil), hello.keySharesWithoutGREASE()...),
		PSKModes:            uint8SliceToInts(hello.pskModesWithoutGREASE()),
		Extensions:          append([]uint16(nil), hello.extensionsWithoutGREASE()...),
		CompressCertAlgos:   append([]uint16(nil), hello.CompressCertAlgos...),
	}
}

func (hello *ClientHello) JA3() string {
	sections := []string{
		strconv.Itoa(int(hello.LegacyVersion)),
		joinUint16Dash(hello.ciphersWithoutGREASE()),
		joinUint16Dash(hello.extensionsWithoutGREASE()),
		joinUint16Dash(hello.curvesWithoutGREASE()),
		joinUint8Dash(hello.PointFormats),
	}
	return strings.Join(sections, ",")
}

func (hello *ClientHello) JA4() string {
	versionCode := ja4VersionCode(hello.effectiveVersion())
	sniCode := "i"
	if hello.ServerName != "" {
		sniCode = "d"
	}
	cipherCount := min2Digits(len(hello.ciphersWithoutGREASE()))
	extensionCount := min2Digits(len(hello.extensionsWithoutGREASE()))
	alpnCode := ja4ALPNCode(hello.ALPNProtocols)
	cipherHash := hashListOrZeros(hello.sortedCipherHex())
	extensionHash := hashListOrZeros(hello.extensionSignatureString())
	return fmt.Sprintf("t%s%s%s%s%s_%s_%s", versionCode, sniCode, cipherCount, extensionCount, alpnCode, cipherHash, extensionHash)
}

func (hello *ClientHello) effectiveVersion() uint16 {
	versions := hello.supportedVersionsWithoutGREASE()
	if len(versions) == 0 {
		return hello.LegacyVersion
	}
	maxVersion := versions[0]
	for _, version := range versions[1:] {
		if version > maxVersion {
			maxVersion = version
		}
	}
	return maxVersion
}

func ja4VersionCode(version uint16) string {
	switch version {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	default:
		return "00"
	}
}

func ja4ALPNCode(protocols []string) string {
	if len(protocols) == 0 || protocols[0] == "" {
		return "00"
	}
	value := []byte(protocols[0])
	first := value[0]
	last := value[len(value)-1]
	if isASCIIAlnum(first) && isASCIIAlnum(last) {
		if len(value) == 1 {
			return strings.ToLower(string([]byte{first, first}))
		}
		return strings.ToLower(string([]byte{first, last}))
	}
	hexValue := strings.ToLower(hex.EncodeToString(value))
	if len(hexValue) == 1 {
		return hexValue + hexValue
	}
	return string([]byte{hexValue[0], hexValue[len(hexValue)-1]})
}

func isASCIIAlnum(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func min2Digits(count int) string {
	if count > 99 {
		count = 99
	}
	return fmt.Sprintf("%02d", count)
}

func hashListOrZeros(value string) string {
	if value == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:12]
}

func (hello *ClientHello) sortedCipherHex() string {
	ciphers := hello.ciphersWithoutGREASE()
	if len(ciphers) == 0 {
		return ""
	}
	values := make([]string, 0, len(ciphers))
	for _, value := range ciphers {
		values = append(values, fmt.Sprintf("%04x", value))
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}

func (hello *ClientHello) extensionSignatureString() string {
	extensions := hello.extensionsWithoutGREASE()
	filtered := make([]string, 0, len(extensions))
	for _, value := range extensions {
		if value == 0 || value == 16 {
			continue
		}
		filtered = append(filtered, fmt.Sprintf("%04x", value))
	}
	if len(filtered) == 0 {
		return ""
	}
	sort.Strings(filtered)

	var builder strings.Builder
	builder.WriteString(strings.Join(filtered, ","))

	sigAlgs := hello.signatureAlgorithmsWithoutGREASE()
	if len(sigAlgs) == 0 {
		return builder.String()
	}
	builder.WriteString("_")
	for i, value := range sigAlgs {
		if i > 0 {
			builder.WriteString(",")
		}
		fmt.Fprintf(&builder, "%04x", value)
	}
	return builder.String()
}

func (hello *ClientHello) ciphersWithoutGREASE() []uint16 {
	return filterUint16(hello.CipherSuites, IsGREASE16)
}

func (hello *ClientHello) extensionsWithoutGREASE() []uint16 {
	return filterUint16(hello.Extensions, IsGREASE16)
}

func (hello *ClientHello) curvesWithoutGREASE() []uint16 {
	return filterUint16(hello.Curves, IsGREASE16)
}

func (hello *ClientHello) signatureAlgorithmsWithoutGREASE() []uint16 {
	return filterUint16(hello.SignatureAlgorithms, IsGREASE16)
}

func (hello *ClientHello) supportedVersionsWithoutGREASE() []uint16 {
	return filterUint16(hello.SupportedVersions, IsGREASE16)
}

func (hello *ClientHello) keySharesWithoutGREASE() []uint16 {
	return filterUint16(hello.KeyShareGroups, IsGREASE16)
}

func (hello *ClientHello) pskModesWithoutGREASE() []uint8 {
	return filterUint8(hello.PSKModes, IsGREASE8)
}

func filterUint16(values []uint16, discard func(uint16) bool) []uint16 {
	filtered := make([]uint16, 0, len(values))
	for _, value := range values {
		if discard(value) {
			continue
		}
		filtered = append(filtered, value)
	}
	return filtered
}

func filterUint8(values []uint8, discard func(uint8) bool) []uint8 {
	filtered := make([]uint8, 0, len(values))
	for _, value := range values {
		if discard(value) {
			continue
		}
		filtered = append(filtered, value)
	}
	return filtered
}

func uint8SliceToInts(values []uint8) []int {
	converted := make([]int, 0, len(values))
	for _, value := range values {
		converted = append(converted, int(value))
	}
	return converted
}

func joinUint16Dash(values []uint16) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Itoa(int(value)))
	}
	return strings.Join(parts, "-")
}

func joinUint8Dash(values []uint8) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Itoa(int(value)))
	}
	return strings.Join(parts, "-")
}
