package pktdump

import "testing"

func Test_reHttpCommonRequest(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"GET request HTTP/1.1", "GET /index.html HTTP/1.1\r\nHost: example.com", true},
		{"POST request HTTP/1.0", "POST /api/users HTTP/1.0\r\nHost: example.com", true},
		{"PUT request HTTP/2", "PUT /resource HTTP/1.1\r\nHost: example.com", true},
		{"DELETE request", "DELETE /api/users/123 HTTP/1.1\r\nHost: example.com", true},
		{"PATCH request", "PATCH /api/users/123 HTTP/1.1\r\nHost: example.com", true},
		{"OPTIONS request", "OPTIONS /api/cors HTTP/1.1\r\nHost: example.com", true},
		{"HEAD request", "HEAD /status HTTP/1.1\r\nHost: example.com", true},
		{"TRACE request", "TRACE /debug HTTP/1.1\r\nHost: example.com", true},
		{"Request with query params", "GET /search?q=test&page=1 HTTP/1.1\r\nHost: example.com", true},
		// Invalid cases
		{"Missing path", "GET HTTP/1.1", false},
		{"Invalid method", "INVALID /path HTTP/1.1", false},
		{"Missing HTTP version", "GET /path", false},
		{"Invalid HTTP version", "GET /path HTTP/3.0", false},
		{"No leading slash", "GET path HTTP/1.1", false},
		{"Empty string", "", false},
		{"Random text", "Just some random text", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := reHttpCommonRequest.FindString(tt.input)
			if (got != "") != tt.want {
				t.Errorf("reHttpCommonRequest.MatchString() = %v, want %v for input: %s", got, tt.want, tt.input)
			}
		})
	}
}

func Test_reHttpConnectRequest(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"Basic CONNECT request", "CONNECT example.com HTTP/1.1\r\nHost: example.com", true},
		{"CONNECT with port", "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com", true},
		{"CONNECT with IP", "CONNECT 192.168.1.1:8080 HTTP/1.1\r\nHost: 192.168.1.1:8080", true},
		{"CONNECT with subdomain", "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443", true},
		{"CONNECT HTTP/1.0", "CONNECT example.com:443 HTTP/1.0\r\nHost: example.com:443", true},
		// Invalid cases
		{"Missing host", "CONNECT HTTP/1.1\r\n", false},
		{"Invalid HTTP version", "CONNECT example.com HTTP/3.0\r\n", false},
		{"No headers", "CONNECT example.com HTTP/1.1", false},
		{"Empty string", "", false},
		{"Random text", "Just some random text", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := reHttpConnectRequest.FindString(tt.input)
			if (got != "") != tt.want {
				t.Errorf("reHttpConnectRequest.MatchString() = %v, want %v for input: %s", got, tt.want, tt.input)
			}
		})
	}
}

func Test_reHttpResponse(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"200 OK", "HTTP/1.1 200 OK\r\nContent-Type: text/html", true},
		{"404 Not Found", "HTTP/1.1 404 Not Found\r\nContent-Length: 0", true},
		{"500 Server Error", "HTTP/1.1 500 Internal Server Error\r\nConnection: close", true},
		{"201 Created", "HTTP/1.1 201 Created\r\nLocation: /resource/123", true},
		{"301 Redirect", "HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.com", true},
		{"HTTP/1.0", "HTTP/1.0 200 OK\r\nServer: test", true},
		{"HTTP/2", "HTTP/2 200 OK\r\nContent-Type: application/json", true},
		{"Long headers", "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nCache-Control: no-cache", true},
		{"Custom message", "HTTP/1.1 418 I'm a teapot\r\nX-Custom: value", true},
		// Invalid cases
		{"Missing status code", "HTTP/1.1 OK\r\n", false},
		{"Invalid HTTP version", "HTTP/3.0 200 OK\r\n", false},
		{"No headers", "HTTP/1.1 200 OK", false},
		{"Missing message", "HTTP/1.1 200\r\n", false},
		{"Empty string", "", false},
		{"Random text", "Just some random text", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := reHttpResponse.FindString(tt.input)
			if (got != "") != tt.want {
				t.Errorf("reHttpResponse.FindString() = %v, want %v for input: %s", got, tt.want, tt.input)
			}
		})
	}
}
