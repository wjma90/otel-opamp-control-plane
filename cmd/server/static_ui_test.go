package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

func TestStaticUIHandlerDoesNotMaskRemovedAPIEndpoints(t *testing.T) {
	handler := staticUIHandler(fstest.MapFS{
		"index.html": {Data: []byte("<html>o11y</html>")},
	})

	for _, endpoint := range []string{
		"/api/catalog",
		"/api/captures",
		"/api/capture-inventory",
	} {
		recorder := httptest.NewRecorder()
		handler(recorder, httptest.NewRequest(http.MethodGet, endpoint, nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s returned %d instead of 404", endpoint, recorder.Code)
		}
	}
}

func TestStaticUIHandlerRejectsTraversalPaths(t *testing.T) {
	handler := staticUIHandler(fstest.MapFS{
		"index.html": {Data: []byte("<html>o11y</html>")},
	})

	request := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	request.URL.Path = "/../../etc/passwd"
	recorder := httptest.NewRecorder()
	handler(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("traversal path returned %d instead of 404", recorder.Code)
	}
}

func TestStaticUIHandlerServesIndexForStableUIRoutes(t *testing.T) {
	handler := staticUIHandler(fstest.MapFS{
		"index.html": {Data: []byte("<html>o11y routes</html>")},
	})

	for _, route := range []string{
		"/policy-studio",
		"/agents",
		"/remote-management",
		"/versions",
		"/profile",
		"/settings",
	} {
		recorder := httptest.NewRecorder()
		handler(recorder, httptest.NewRequest(http.MethodGet, route, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s returned %d instead of 200", route, recorder.Code)
		}
		if recorder.Body.String() != "<html>o11y routes</html>" {
			t.Fatalf("%s did not receive the SPA index", route)
		}
	}
}
