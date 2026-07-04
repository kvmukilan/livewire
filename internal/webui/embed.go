package webui

import _ "embed"

// indexHTML is the whole dashboard page, embedded into the binary.
//
//go:embed index.html
var indexHTML []byte
