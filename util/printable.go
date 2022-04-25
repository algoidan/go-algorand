package util

import (
	"fmt"
	"strings"
)

func ToCommaSeparatedString(b []byte) string {
	builder := strings.Builder{}
	builder.WriteString("[")
	if len(b) == 0 {
		builder.WriteString("]")
		return builder.String()
	}
	i := 0
	for ; i < len(b)-1; i++ {
		builder.WriteString(fmt.Sprintf("0x%x,", b[i]))
	}
	builder.WriteString(fmt.Sprintf("0x%x", b[i]))
	builder.WriteString("]")
	return builder.String()
}
