package tlsfp

func IsGREASE16(value uint16) bool {
	return value&0x0f0f == 0x0a0a && byte(value>>8) == byte(value)
}

func IsGREASE8(value uint8) bool {
	switch value {
	case 0x0b, 0x2a, 0x49, 0x68, 0x87, 0xa6, 0xc5, 0xe4:
		return true
	default:
		return false
	}
}
