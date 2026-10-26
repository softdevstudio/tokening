package gateway

import (
	"encoding/json"
	"github.com/softdevstudio/tokening/internal/jsonobject"
)

func parseObject(data []byte) (map[string]json.RawMessage, error) { return jsonobject.Decode(data) }
