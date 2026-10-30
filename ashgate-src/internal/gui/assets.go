package gui

import (
	"embed"
	"io/fs"
	"net/http"
	"sync"
)

//go:embed ui
var uiFS embed.FS

// static serves the embedded window files. It is built once: every request
// that is not an API call goes through it.
var static = sync.OnceValue(func() http.Handler {
	sub, err := fs.Sub(uiFS, "ui")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(sub))
})
