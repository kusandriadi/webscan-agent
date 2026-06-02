package scanner

import "testing"

func TestPathMatch(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"*", "/anything", true},
		{"/admin/delete", "/admin/delete", true},
		{"/admin/delete", "/admin/delete/123", true}, // exact also blocks beneath it
		{"/admin/delete", "/admin/deleted", false},   // not a path-segment match
		{"/admin/*", "/admin/users", true},
		{"/admin/*", "/public", false},
		{"/api", "/api", true},
		{"", "/api", false},
	}
	for _, c := range cases {
		if got := pathMatch(c.pattern, c.path); got != c.want {
			t.Errorf("pathMatch(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestScopeChecker(t *testing.T) {
	sc := &scopeChecker{
		include: []string{"*"},
		exclude: []string{"/admin/delete", "/admin/drop"},
	}
	if sc.allowed("https://t.com/admin/delete") {
		t.Error("excluded path /admin/delete should be blocked")
	}
	if sc.allowed("https://t.com/admin/delete/42") {
		t.Error("paths beneath an excluded path should be blocked")
	}
	if !sc.allowed("https://t.com/users") {
		t.Error("in-scope path /users should be allowed")
	}

	// include allowlist limits scanning to listed paths
	only := &scopeChecker{include: []string{"/api/*"}}
	if only.allowed("https://t.com/admin") {
		t.Error("path outside include_paths should be blocked")
	}
	if !only.allowed("https://t.com/api/v1/users") {
		t.Error("path inside include_paths should be allowed")
	}

	// a nil checker never blocks
	var nilSC *scopeChecker
	if !nilSC.allowed("https://t.com/anything") {
		t.Error("nil scopeChecker should allow everything")
	}
}

func TestParseSetCookie(t *testing.T) {
	cases := []struct {
		header, name, value string
	}{
		{"session=abc123; Path=/; HttpOnly", "session", "abc123"},
		{"token=xyz", "token", "xyz"},
		{"  spaced = val ; Secure", "spaced", "val"},
		{"novalue", "", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		n, v := parseSetCookie(c.header)
		if n != c.name || v != c.value {
			t.Errorf("parseSetCookie(%q) = (%q, %q), want (%q, %q)", c.header, n, v, c.name, c.value)
		}
	}
}

func TestSessionApplies(t *testing.T) {
	c := &HTTPClient{SessionHost: "target.com"}
	if !c.sessionApplies("target.com") {
		t.Error("session should apply to the target host")
	}
	if !c.sessionApplies("TARGET.COM") {
		t.Error("host match should be case-insensitive")
	}
	if c.sessionApplies("crt.sh") {
		t.Error("session creds must NOT be sent to a third-party host")
	}

	open := &HTTPClient{}
	if !open.sessionApplies("anything.com") {
		t.Error("empty SessionHost should apply everywhere")
	}
}
