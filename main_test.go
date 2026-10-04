package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sse(frames ...string) []byte {
	var b strings.Builder
	for _, f := range frames {
		b.WriteString("data: ")
		b.WriteString(f)
		b.WriteString("\n\n")
	}
	b.WriteString("data: [DONE]\n\n")
	return []byte(b.String())
}

// The free-tier cap arrives as prose the upstream already resolved for us.
func TestParseRetryHint(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{`Error 429: Daily free limit reached on model deepseek/deepseek-v4.1-flash. Try again in 6h 41m`, 6*time.Hour + 41*time.Minute},
		{`... Try again in 39m`, 39 * time.Minute},
		{`... Try again in 5h`, 5 * time.Hour},
		{`... Try again in 22h 34m`, 22*time.Hour + 34*time.Minute},
		{`rate limited, retry after 60s`, 60 * time.Second},
		{`no hint at all`, 0},
		{`Try again in 0m`, 0},
	}
	for _, c := range cases {
		if got := parseRetryHint([]byte(c.in)); got != c.want {
			t.Errorf("parseRetryHint(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// Cline's object-shaped error used to fall through to a generic 502 and lose
// the code that says "this account is out of quota until 6h41m".
func TestClassifyObjectErrorCarriesQuota(t *testing.T) {
	body := []byte(`{"error":{"code":"INFERENCE_CAP_ERROR","message":"Error 429: Daily free limit reached on model deepseek/deepseek-v4.1-flash. Try again in 6h 41m"}}`)

	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatal(err)
	}
	txt := failureOf(obj)
	if txt == "" {
		t.Fatal("failureOf returned nothing for an object-shaped error")
	}

	f := classifyFailure(200, []byte(txt))
	if f.err == nil {
		t.Fatal("200 + quota body should classify as a failure")
	}
	rpc, ok := f.err.(*rpcError)
	if !ok {
		t.Fatalf("err type = %T, want *rpcError", f.err)
	}
	if rpc.HTTPStatus != 429 {
		t.Errorf("status = %d, want 429", rpc.HTTPStatus)
	}
	if !f.limited {
		t.Error("quota failure must be gate-eligible")
	}
	if f.retryIn != 6*time.Hour+41*time.Minute {
		t.Errorf("retryIn = %v, want 6h41m", f.retryIn)
	}
}

// A permanent 403 must not be turned into a retryable 429.
func TestClassifyPermanentForbiddenStaysForbidden(t *testing.T) {
	f := classifyFailure(403, []byte(`{"error":{"code":"ENTITLEMENT_ERROR","message":"the user is not subscribed to required model plan"}}`))
	rpc, ok := f.err.(*rpcError)
	if !ok || rpc.HTTPStatus != 403 {
		t.Fatalf("want 403, got %+v", f.err)
	}
	if f.limited {
		t.Error("a subscription failure must not open a retry window")
	}
}

// Non-stream requests lost every tool call: aggregate only glued content and
// reasoning together.
func TestAggregateKeepsToolCalls(t *testing.T) {
	raw := sse(
		`{"id":"gen_1","created":1,"choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}`,
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_00_abc","type":"function","function":{"name":"bash","arguments":""}}]},"finish_reason":null}]}`,
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"command\":"}}]},"finish_reason":null}]}`,
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"ls /tmp\"}"}}]},"finish_reason":null}]}`,
		`{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
	)
	out, f := aggregate("cline-deepseek-v4.1-flash", raw)
	if f.err != nil {
		t.Fatalf("aggregate failed: %v", f.err)
	}
	var got struct {
		Choices []struct {
			Message struct {
				Content   string `json:"content"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Type     string `json:"type"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Choices) != 1 {
		t.Fatalf("choices = %d, want 1", len(got.Choices))
	}
	c := got.Choices[0]
	if len(c.Message.ToolCalls) != 1 {
		t.Fatalf("tool_calls = %d, want 1", len(c.Message.ToolCalls))
	}
	tc := c.Message.ToolCalls[0]
	if tc.ID != "call_00_abc" || tc.Function.Name != "bash" {
		t.Errorf("header fields lost: %+v", tc)
	}
	if tc.Function.Arguments != `{"command":"ls /tmp"}` {
		t.Errorf("arguments = %q", tc.Function.Arguments)
	}
	if c.FinishReason != "tool_calls" {
		t.Errorf("finish_reason = %q", c.FinishReason)
	}
}

// content and reasoning can share a frame; the old else-if chain dropped one.
func TestAggregateKeepsBothChannels(t *testing.T) {
	raw := sse(
		`{"choices":[{"index":0,"delta":{"reasoning":"thinking ","content":"hi"},"finish_reason":null}]}`,
		`{"choices":[{"index":0,"delta":{"content":" there"},"finish_reason":"stop"}]}`,
	)
	out, f := aggregate("m", raw)
	if f.err != nil {
		t.Fatal(f.err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	msg := got["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)
	if msg["content"] != "hi there" {
		t.Errorf("content = %v", msg["content"])
	}
	if msg["reasoning"] != "thinking " {
		t.Errorf("reasoning = %v", msg["reasoning"])
	}
}

func TestGateParksOnlyTheLimitedCredential(t *testing.T) {
	g := &rateGate{windows: map[string]*rateWindow{}}

	epoch, _, ok := g.admit("a")
	if !ok {
		t.Fatal("first admit should pass")
	}
	if epoch != 0 {
		t.Errorf("epoch = %d, want 0", epoch)
	}

	// other keys keep serving
	if _, _, ok := g.admit("b"); !ok {
		t.Fatal("an unrelated credential must not be blocked")
	}

	// a records the announced window
	g.settle("a", epoch, upstreamFailure{err: fail(429, "rate_limit_exceeded", "x"), limited: true, retryIn: time.Hour})

	if _, remaining, ok := g.admit("a"); ok || remaining <= 0 {
		t.Fatalf("a should be parked with a positive remaining window, got ok=%v remaining=%v", ok, remaining)
	}

	// expire the window: exactly one recovery probe may pass
	g.mu.Lock()
	g.windows["a"].until = time.Now().Add(-time.Second)
	g.mu.Unlock()

	if _, _, ok := g.admit("a"); !ok {
		t.Fatal("the first request after expiry should probe")
	}
	if _, _, ok := g.admit("a"); ok {
		t.Fatal("a second concurrent request must not stampede while probing")
	}

	// the probe succeeded -> window clears
	g.settle("a", g.windows["a"].epoch, upstreamFailure{})
	if _, _, ok := g.admit("a"); !ok {
		t.Fatal("window should be clear after a successful probe")
	}
}

func TestFrameFailureIgnoresOrdinaryFrames(t *testing.T) {
	var ok map[string]any
	_ = json.Unmarshal([]byte(`{"choices":[{"index":0,"delta":{"content":"hello"}}]}`), &ok)
	if got := frameFailure(ok); got != "" {
		t.Errorf("ordinary frame flagged as failure: %q", got)
	}

	var bad map[string]any
	_ = json.Unmarshal([]byte(`{"object":"chat.completion.chunk","error":{"code":502,"message":"Bad gateway","type":"api_error"},"choices":[{"index":0,"delta":{"content":""},"finish_reason":"error"}]}`), &bad)
	if got := frameFailure(bad); got == "" {
		t.Error("embedded error frame was not detected")
	}
}

// The management panel edits plugins.configs.clinefree. Presence decides:
// an api_keys array that is present but empty must really clear the keys, while
// an absent one must leave the settings.json baseline alone.
func TestApplyConfigNodePresenceSemantics(t *testing.T) {
	base := func() Settings {
		return Settings{DataDir: "d", BaseURL: defaultBaseURL, TimeoutSeconds: defaultTimeout,
			APIKeys: []string{"k1", "k2"}, Models: []ModelMap{{ID: "m", UpstreamID: "cline-free/m"}}}
	}

	// absent -> baseline untouched
	s := base()
	applyConfigNode(&s, []byte(`{"enabled":true}`))
	if len(s.APIKeys) != 2 || len(s.Models) != 1 {
		t.Errorf("absent fields must not clobber the baseline: keys=%v models=%v", s.APIKeys, s.Models)
	}

	// present and non-empty -> wins
	s = base()
	applyConfigNode(&s, []byte(`{"api_keys":["new1","new2","new3"]}`))
	if len(s.APIKeys) != 3 || s.APIKeys[0] != "new1" {
		t.Errorf("explicit keys must win: %v", s.APIKeys)
	}

	// present but empty -> clears (this is how the panel removes the last key)
	s = base()
	applyConfigNode(&s, []byte(`{"api_keys":[]}`))
	if len(s.APIKeys) != 0 {
		t.Errorf("an explicitly empty array must clear keys, got %v", s.APIKeys)
	}

	// camelCase spelling is tolerated too
	s = base()
	applyConfigNode(&s, []byte(`{"apiKeys":["camel"]}`))
	if len(s.APIKeys) != 1 || s.APIKeys[0] != "camel" {
		t.Errorf("camelCase key spelling not honoured: %v", s.APIKeys)
	}
}

func TestNormalizeKeysAndModels(t *testing.T) {
	keys := normalizeKeys([]string{"  a  ", "a", "", "b"})
	if len(keys) != 2 || keys[0] != "a" || keys[1] != "b" {
		t.Errorf("normalizeKeys = %v", keys)
	}
	models := normalizeModels([]ModelMap{
		{ID: " x ", UpstreamID: " up "},
		{ID: "x", UpstreamID: "dup"},
		{ID: "", UpstreamID: "up"},
		{ID: "y", UpstreamID: ""},
	})
	if len(models) != 1 || models[0].ID != "x" || models[0].UpstreamID != "up" {
		t.Errorf("normalizeModels = %v", models)
	}
}

// The management panel serialises the plugin node with yaml.v3; these fixtures
// mirror what it emits for the declared array fields.
const panelConfigYAML = `enabled: true
api_keys:
    - sk_test_key_one_0000000000000000000000000000
    - "sk_quoted_value"
models:
    - id: cline-deepseek-v4.1-flash
      upstream_id: cline-free/deepseek-v4.1-flash
data_dir: plugins/clinefree-data
base_url: https://api.cline.bot/api/v1
timeout_seconds: 600
`

func registerPayload(t *testing.T, yamlText string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"config_yaml": []byte(yamlText), "schema_version": 6})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseConfigNodeValue(t *testing.T) {
	yamlText := []byte(panelConfigYAML)

	var keys []string
	raw, ok := parseConfigNodeValue(yamlText, "api_keys")
	if !ok {
		t.Fatal("api_keys not found")
	}
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatalf("api_keys is not a JSON array: %v (%s)", err, raw)
	}
	if len(keys) != 2 || keys[0] != "sk_test_key_one_0000000000000000000000000000" {
		t.Errorf("api_keys = %v", keys)
	}
	if keys[1] != "sk_quoted_value" {
		t.Errorf("quoted scalar not unquoted: %q", keys[1])
	}

	var models []ModelMap
	raw, ok = parseConfigNodeValue(yamlText, "models")
	if !ok {
		t.Fatal("models not found")
	}
	if err := json.Unmarshal(raw, &models); err != nil {
		t.Fatalf("models is not a JSON array of objects: %v (%s)", err, raw)
	}
	if len(models) != 1 || models[0].ID != "cline-deepseek-v4.1-flash" || models[0].UpstreamID != "cline-free/deepseek-v4.1-flash" {
		t.Errorf("models = %+v", models)
	}

	var dataDir string
	raw, _ = parseConfigNodeValue(yamlText, "data_dir")
	if json.Unmarshal(raw, &dataDir) != nil || dataDir != "plugins/clinefree-data" {
		t.Errorf("data_dir = %s", raw)
	}

	// A URL value contains ':' and must survive intact.
	var baseURL string
	raw, _ = parseConfigNodeValue(yamlText, "base_url")
	if json.Unmarshal(raw, &baseURL) != nil || baseURL != "https://api.cline.bot/api/v1" {
		t.Errorf("base_url = %s", raw)
	}

	// Numbers must stay JSON numbers so they decode into int fields.
	raw, _ = parseConfigNodeValue(yamlText, "timeout_seconds")
	if string(raw) != "600" {
		t.Errorf("timeout_seconds = %s, want 600", raw)
	}

	if _, ok := parseConfigNodeValue(yamlText, "not_present"); ok {
		t.Error("absent key reported present")
	}
}

func TestParseConfigNodeEmptySequence(t *testing.T) {
	raw, ok := parseConfigNodeValue([]byte("api_keys: []\n"), "api_keys")
	if !ok || string(raw) != "[]" {
		t.Fatalf("empty flow sequence = %s ok=%v", raw, ok)
	}
}

// End to end through the host envelope: what the panel writes must reach the
// settings the plugin actually runs with.
func TestHostConfigFieldsDrivesSettings(t *testing.T) {
	s := defaults()
	s.APIKeys = []string{"sk_old_value_left_over_from_settings_json"}
	applyConfigNode(&s, hostConfigFields(registerPayload(t, panelConfigYAML)))

	if len(s.APIKeys) != 2 {
		t.Fatalf("panel keys did not win: %v", s.APIKeys)
	}
	if len(s.Models) != 1 || s.Models[0].ID != "cline-deepseek-v4.1-flash" {
		t.Errorf("models = %+v", s.Models)
	}
	if s.TimeoutSeconds != 600 {
		t.Errorf("timeout = %d", s.TimeoutSeconds)
	}
	if s.DataDir != "plugins/clinefree-data" {
		t.Errorf("data_dir = %s", s.DataDir)
	}

	// An envelope without config_yaml must leave the baseline alone.
	s2 := defaults()
	s2.APIKeys = []string{"keep-me"}
	applyConfigNode(&s2, hostConfigFields([]byte(`{"config_yaml":""}`)))
	if len(s2.APIKeys) != 1 || s2.APIKeys[0] != "keep-me" {
		t.Errorf("empty envelope clobbered settings: %v", s2.APIKeys)
	}
}

// The host auto-generates an OAuth entry for every auth_provider plugin and
// offers no way to remove it, so the usable interface has to come from the
// plugin: a management route set plus a browser page.
func TestManagementRegisterShape(t *testing.T) {
	reg := managementRegister()
	routes, _ := reg["routes"].([]map[string]string)
	if len(routes) == 0 {
		t.Fatal("no routes registered")
	}
	seen := map[string]bool{}
	for _, r := range routes {
		seen[r["Method"]+" "+r["Path"]] = true
	}
	for _, want := range []string{
		"GET " + consoleAPIPath + "/keys",
		"POST " + consoleAPIPath + "/keys",
		"DELETE " + consoleAPIPath + "/keys",
	} {
		if !seen[want] {
			t.Errorf("route missing: %s", want)
		}
	}
	resources, _ := reg["resources"].([]map[string]string)
	if len(resources) != 1 || resources[0]["Path"] != "/console" {
		t.Fatalf("resources = %v", resources)
	}
}

func stubSettings(keys []string) {
	mu.Lock()
	current.APIKeys = keys
	mu.Unlock()
}

func TestConsolePageIsServed(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"Method": "GET", "Path": consolePagePath})
	out, err := managementHandle(raw)
	if err != nil {
		t.Fatal(err)
	}
	resp, ok := out.(managementResponse)
	if !ok {
		t.Fatalf("unexpected response type %T", out)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Headers.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("content-type = %q", ct)
	}
	body := string(resp.Body)
	// The page references the API base; the /keys suffix is appended in JS.
	if !strings.Contains(body, consoleAPIPath) {
		t.Error("page does not reference the management API base")
	}
	if !strings.Contains(body, "<textarea") {
		t.Error("page has no input for new keys")
	}
}

func TestKeysSnapshotsMasksSecrets(t *testing.T) {
	k1 := "sk_test_key_one_0000000000000000000000000000"
	k2 := "sk_test_key_two_0000000000000000000000000000"
	stubSettings([]string{k1, k2})

	snap := keysSnapshot()
	if snap["count"] != 2 {
		t.Fatalf("count = %v", snap["count"])
	}
	items, _ := snap["keys"].([]map[string]any)
	if len(items) != 2 {
		t.Fatalf("items = %v", items)
	}
	for i, item := range items {
		masked, _ := item["masked"].(string)
		if masked == k1 || masked == k2 {
			t.Fatalf("raw key leaked into the snapshot: %s", masked)
		}
		if len(masked) > 20 {
			t.Errorf("masked value looks too long: %s", masked)
		}
		wantID := credID([]string{k1, k2}[i])
		if item["id"] != wantID {
			t.Errorf("id = %v, want %s", item["id"], wantID)
		}
	}
	if strings.Contains(strings.Join([]string{items[0]["masked"].(string), items[0]["id"].(string)}, ""), k1) {
		t.Error("snapshot must never carry the raw key")
	}
	stubSettings(nil)
}

func TestMergeAndDropKeys(t *testing.T) {
	merged, added := mergeKeys([]string{"a", "b"}, []string{"b", "c", " c ", ""})
	if added != 1 || len(merged) != 3 {
		t.Fatalf("mergeKeys = %v added=%d", merged, added)
	}

	keys := []string{"key_one_value", "key_two_value"}
	target := credID(keys[0])
	left, removed := dropKey(keys, target)
	if removed != 1 || len(left) != 1 || left[0] != keys[1] {
		t.Fatalf("dropKey = %v removed=%d", left, removed)
	}
	if _, missing := dropKey(keys, "clinefree-doesnotexist"); missing != 0 {
		t.Error("dropping an unknown id must not remove anything")
	}
}

func TestManagementHandleListKeys(t *testing.T) {
	stubSettings([]string{"sk_test_key_three"})
	raw, _ := json.Marshal(map[string]any{"Method": "GET", "Path": consoleAPIPath + "/keys"})
	out, err := managementHandle(raw)
	if err != nil {
		t.Fatal(err)
	}
	resp := out.(managementResponse)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, resp.Body)
	}
	var decoded struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(resp.Body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Count != 1 {
		t.Errorf("count = %d", decoded.Count)
	}
	stubSettings(nil)
}

func TestManagementHandleRejectsUnknownRoute(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"Method": "GET", "Path": consoleAPIPath + "/nope"})
	out, err := managementHandle(raw)
	if err != nil {
		t.Fatal(err)
	}
	if resp := out.(managementResponse); resp.StatusCode != 404 {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestFirstQueryValue(t *testing.T) {
	q := decodeMap([]byte(`{"id":["abc"],"plain":"xyz"}`))
	if got := firstQueryValue(q, "id"); got != "abc" {
		t.Errorf("list form = %q", got)
	}
	if got := firstQueryValue(q, "plain"); got != "xyz" {
		t.Errorf("scalar form = %q", got)
	}
	if got := firstQueryValue(q, "absent"); got != "" {
		t.Errorf("absent = %q", got)
	}
}

// Removing a key in the panel only takes effect if the stale credential file
// disappears — and foreign files must survive.
func TestPruneAuthsRemovesOnlyOurStaleCredentials(t *testing.T) {
	dir := t.TempDir()
	ours := pluginID + "-aaaa"
	stale := pluginID + "-bbbb"
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(ours+".json", `{"type":"`+pluginID+`","id":"`+ours+`"}`)
	write(stale+".json", `{"type":"`+pluginID+`","id":"`+stale+`"}`)
	// same prefix but someone else's record: must not be touched
	write(pluginID+"-cccc.json", `{"type":"other","id":"x"}`)
	// unrelated provider file: must not be touched
	write("xai-1.json", `{"type":"xai"}`)

	pruneAuths(dir, map[string]string{ours: ours + ".json"})

	assertExists := func(name string, want bool) {
		t.Helper()
		_, err := os.Stat(filepath.Join(dir, name))
		if got := err == nil; got != want {
			t.Errorf("%s exists=%v, want %v", name, got, want)
		}
	}
	assertExists(ours+".json", true)
	assertExists(stale+".json", false)
	assertExists(pluginID+"-cccc.json", true)
	assertExists("xai-1.json", true)
}

