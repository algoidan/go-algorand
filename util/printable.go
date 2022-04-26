package util

import (
	"fmt"
	"strings"
)

func ToCommaSeparatedString(b []byte) string {
	builder := strings.Builder{}
	builder.WriteString("[")
	for i := 0; i < len(b); i++ {
		if i != 0 {
			builder.WriteString(",")
		}
		builder.WriteString(fmt.Sprintf("0x%02x", b[i]))
	}
	builder.WriteString("]")
	return builder.String()
}
