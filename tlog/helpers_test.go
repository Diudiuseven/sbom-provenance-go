package tlog

import (
	"encoding/json"
	"os"
)

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
func osWriteFile(p string, d []byte) error { return os.WriteFile(p, d, 0o600) }
