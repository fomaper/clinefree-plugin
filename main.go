// clinefree - a CPA plugin that exposes Cline's free-tier models ("cline-free/*")
// as a first-class provider.
//
// Why this exists instead of a side-car HTTP bridge: Cline gates the free tier
// behind product-surface headers (HTTP-Referer / X-Title / X-CLIENT-TYPE) and
// returns non-streaming answers wrapped in a {"data":...,"success":true}
// envelope. Doing that inside CPA's process removes the extra hop, lets the
// executor return a real SSE stream, and keeps upstream failures classifiable
// (the plugin sets http_status so CPA maps 401/403/429 instead of degrading to
// 500).
package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);

static cliproxy_host_api stored_host;
static int host_ready;

static void store_host_api(const cliproxy_host_api* host) {
	if (host == NULL) {
		host_ready = 0;
		return;
	}
	stored_host = *host;
	host_ready = 1;
}

static int call_host_api(const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	if (!host_ready || stored_host.call == NULL) {
		return 1;
	}
	return stored_host.call(stored_host.host_ctx, method, request, request_len, response);
}

static void free_host_buffer(void* ptr, size_t len) {
	if (host_ready && stored_host.free_buffer != NULL && ptr != NULL) {
		stored_host.free_buffer(ptr, len);
	}
}
*/
import "C"

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
)

const (
	abiVersion      = 1
	pluginID        = "clinefree"
	// Keep this in lockstep with the packaged library name
	// (plugins/linux/amd64/clinefree-v<version>.so): the host reports the file
	// name on load and this constant on register, and the panel shows both.
	pluginVersion   = "0.2.0"
	defaultBaseURL  = "https://api.cline.bot/api/v1"
	defaultDataDir  = "plugins/clinefree-data"
	defaultTimeout  = 600
	sseContentType  = "text/event-stream"
	jsonContentType = "application/json"
)

// ---------------------------------------------------------------------------
// RPC envelope shared with the host
// ---------------------------------------------------------------------------

type rpcError struct {
	ErrorCode  string `json:"code"`
	Message    string `json:"message"`
	Retryable  bool   `json:"retryable,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

func (e *rpcError) Error() string     { return e.Message }
func (e *rpcError) StatusCode() int   { return e.HTTPStatus }
func (e *rpcError) Code() string      { return e.ErrorCode }
func (e *rpcError) RetryableFlag() bool { return e.Retryable }

func fail(status int, code, message string) *rpcError {
	return &rpcError{ErrorCode: code, Message: message, HTTPStatus: status}
}

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *rpcError       `json:"error,omitempty"`
}

// ---------------------------------------------------------------------------
// Settings (read from the plugin config node and/or <data_dir>/settings.json)
// ---------------------------------------------------------------------------

type ModelMap struct {
	ID         string `json:"id"`
	UpstreamID string `json:"upstream_id"`
}

type Settings struct {
	DataDir        string     `json:"data_dir"`
	BaseURL        string     `json:"base_url"`
	TimeoutSeconds int        `json:"timeout_seconds"`
	APIKeys        []string   `json:"api_keys"`
	Models         []ModelMap `json:"models"`
}

type Credential struct {
	Type          string `json:"type"`
	ID            string `json:"id"`
	Label         string `json:"label"`
	APIKey        string `json:"api_key"`
	Disabled      bool   `json:"disabled"`
	ModelRevision string `json:"model_revision,omitempty"`
}

var (
	mu       sync.RWMutex
	current  = Settings{DataDir: defaultDataDir, BaseURL: defaultBaseURL, TimeoutSeconds: defaultTimeout}
	authFile = map[string]string{}
	loaded   bool
)

func defaults() Settings {
	return Settings{DataDir: defaultDataDir, BaseURL: defaultBaseURL, TimeoutSeconds: defaultTimeout}
}

// mergeSettings applies a settings.json snapshot: empty values never erase what
// is already known, so the file acts as a baseline rather than an override.
func mergeSettings(dst *Settings, raw []byte) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return
	}
	var in Settings
	if err := json.Unmarshal(raw, &in); err != nil {
		return
	}
	if strings.TrimSpace(in.DataDir) != "" {
		dst.DataDir = strings.TrimSpace(in.DataDir)
	}
	if strings.TrimSpace(in.BaseURL) != "" {
		dst.BaseURL = strings.TrimRight(strings.TrimSpace(in.BaseURL), "/")
	}
	if in.TimeoutSeconds >= 10 && in.TimeoutSeconds <= 1800 {
		dst.TimeoutSeconds = in.TimeoutSeconds
	}
	if len(in.APIKeys) > 0 {
		dst.APIKeys = in.APIKeys
	}
	if len(in.Models) > 0 {
		dst.Models = in.Models
	}
}

// applyConfigNode layers the host config node (what the management panel edits)
// on top of the settings.json baseline. Presence, not truthiness, decides: an
// api_keys array that is present but empty genuinely means "no keys left",
// which is how the panel removes the last one.
func applyConfigNode(dst *Settings, raw []byte) {
	fields := decodeMap(raw)
	if len(fields) == 0 {
		return
	}
	var in Settings
	if b, err := json.Marshal(fields); err == nil {
		_ = json.Unmarshal(b, &in)
	}
	if strings.TrimSpace(in.DataDir) != "" {
		dst.DataDir = strings.TrimSpace(in.DataDir)
	}
	if strings.TrimSpace(in.BaseURL) != "" {
		dst.BaseURL = strings.TrimRight(strings.TrimSpace(in.BaseURL), "/")
	}
	if in.TimeoutSeconds >= 10 && in.TimeoutSeconds <= 1800 {
		dst.TimeoutSeconds = in.TimeoutSeconds
	}
	// lookup tolerates the panel's key spelling (api_keys / apiKeys / api-keys),
	// so decode the raw value directly instead of relying on struct tags.
	if raw := lookup(fields, "api_keys", "apiKeys"); raw != nil {
		var keys []string
		if json.Unmarshal(raw, &keys) == nil {
			dst.APIKeys = normalizeKeys(keys)
		} else {
			dst.APIKeys = nil
		}
	}
	if raw := lookup(fields, "models"); raw != nil {
		var models []ModelMap
		if json.Unmarshal(raw, &models) == nil {
			dst.Models = normalizeModels(models)
		} else {
			dst.Models = nil
		}
	}
}

func normalizeKeys(keys []string) []string {
	out := make([]string, 0, len(keys))
	seen := map[string]bool{}
	for _, raw := range keys {
		key := strings.TrimSpace(raw)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	return out
}

func normalizeModels(models []ModelMap) []ModelMap {
	out := make([]ModelMap, 0, len(models))
	seen := map[string]bool{}
	for _, m := range models {
		id := strings.TrimSpace(m.ID)
		upstream := strings.TrimSpace(m.UpstreamID)
		if id == "" || upstream == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, ModelMap{ID: id, UpstreamID: upstream})
	}
	return out
}

// persistSettings mirrors the merged result back to the data dir so the file
// always describes the running configuration.
func persistSettings(s Settings) {
	if strings.TrimSpace(s.DataDir) == "" {
		return
	}
	if err := os.MkdirAll(s.DataDir, 0o700); err != nil {
		return
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(s.DataDir, "settings.json"), b, 0o600)
}

// ---------------------------------------------------------------------------
// Host config node
//
// The host hands plugin.register / plugin.reconfigure a{"config_yaml": ...}
// envelope holding the plugin's own node, serialised as YAML. Reading it lets
// the management panel edit api_keys / models directly instead of requiring a
// hand-written settings.json.
//
// The build environment has no Go module proxy, so yaml.v3 cannot be pulled in.
// A targeted reader over the shapes the panel actually emits (top-level scalars
// and block sequences of scalars or small maps) is enough, and it hands back
// JSON so the rest of the plugin keeps using encoding/json.
// ---------------------------------------------------------------------------

func yamlScalar(s string) string {
	s = strings.TrimSpace(s)
	// Drop a trailing comment that is not inside quotes.
	if len(s) > 0 && s[0] != '"' && s[0] != '\'' {
		if i := strings.Index(s, " #"); i >= 0 {
			s = strings.TrimSpace(s[:i])
		}
	}
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			inner := s[1 : len(s)-1]
			if s[0] == '"' {
				var out string
				if json.Unmarshal([]byte(s), &out) == nil {
					return out
				}
			}
			return inner
		}
	}
	return s
}

func splitYAMLKeyValue(s string) (string, string, bool) {
	i := strings.Index(s, ":")
	if i <= 0 {
		return "", "", false
	}
	if i+1 < len(s) && s[i+1] != ' ' {
		return "", "", false
	}
	return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
}

func yamlIndent(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

// isPlainScalar reports whether a scalar is already valid JSON (number, bool,
// null) and should therefore not be quoted.
func isPlainScalar(s string) bool {
	if s == "" {
		return false
	}
	var v any
	if json.Unmarshal([]byte(s), &v) != nil {
		return false
	}
	switch v.(type) {
	case float64, bool, nil:
		return true
	}
	return false
}

// parseConfigNodeValue converts one top-level key of the YAML node into JSON.
func parseConfigNodeValue(yaml []byte, key string) ([]byte, bool) {
	lines := strings.Split(string(yaml), "\n")
	start := -1
	baseIndent := 0
	for i, line := range lines {
		trimmed := strings.TrimRight(line, " \r")
		if strings.TrimSpace(trimmed) == "" || strings.HasPrefix(strings.TrimSpace(trimmed), "#") {
			continue
		}
		if yamlIndent(trimmed) != 0 {
			continue
		}
		body := strings.TrimSpace(trimmed)
		if !strings.HasPrefix(body, key+":") {
			continue
		}
		inline := strings.TrimSpace(strings.TrimPrefix(body, key+":"))
		if inline != "" {
			// http://... values contain ':' but never ': ', so they survive.
			if json.Valid([]byte(inline)) && (inline[0] == '[' || inline[0] == '{') {
				return []byte(inline), true
			}
			if inline == "[]" || inline == "{}" {
				return []byte("[]"), true
			}
			if inline == "~" || inline == "null" {
				return []byte("null"), true
			}
			scalar := yamlScalar(inline)
			// Numbers and booleans must stay JSON scalars, otherwise they are
			// rejected when decoded into int / bool settings fields.
			if isPlainScalar(scalar) {
				return []byte(scalar), true
			}
			out, _ := json.Marshal(scalar)
			return out, true
		}
		start, baseIndent = i, yamlIndent(trimmed)
		break
	}
	if start < 0 {
		return nil, false
	}

	var seq []json.RawMessage
	var current map[string]string
	flush := func() {
		if current != nil {
			b, _ := json.Marshal(current)
			seq = append(seq, b)
			current = nil
		}
	}
	for _, line := range lines[start+1:] {
		trimmed := strings.TrimRight(line, " \r")
		if strings.TrimSpace(trimmed) == "" || strings.HasPrefix(strings.TrimSpace(trimmed), "#") {
			continue
		}
		if yamlIndent(trimmed) <= baseIndent {
			break
		}
		body := strings.TrimSpace(trimmed)
		if body == "-" || strings.HasPrefix(body, "- ") {
			item := strings.TrimSpace(strings.TrimPrefix(body, "-"))
			if item == "" {
				flush()
				current = map[string]string{}
				continue
			}
			if k, v, ok := splitYAMLKeyValue(item); ok {
				flush()
				current = map[string]string{k: yamlScalar(v)}
				continue
			}
			flush()
			b, _ := json.Marshal(yamlScalar(item))
			seq = append(seq, b)
			continue
		}
		if current != nil {
			if k, v, ok := splitYAMLKeyValue(body); ok {
				current[k] = yamlScalar(v)
			}
		}
	}
	flush()
	if seq == nil {
		return nil, false
	}
	out, err := json.Marshal(seq)
	if err != nil {
		return nil, false
	}
	return out, true
}

// hostConfigFields turns the lifecycle payload into a JSON object holding the
// fields this plugin understands, with the same names as the settings file.
func hostConfigFields(raw json.RawMessage) []byte {
	blob := getBytes(decodeMap(raw), "config_yaml", "ConfigYAML", "config")
	if len(blob) == 0 {
		return nil
	}
	node := map[string]json.RawMessage{}
	for _, key := range []string{"data_dir", "base_url", "timeout_seconds", "api_keys", "models"} {
		if value, ok := parseConfigNodeValue(blob, key); ok {
			node[key] = value
		}
	}
	if len(node) == 0 {
		return nil
	}
	out, err := json.Marshal(node)
	if err != nil {
		return nil
	}
	return out
}

// configure builds the effective settings. Lowest to highest precedence:
// defaults, then settings.json (the durable mirror), then the host config node
// (what the management panel edits). The merged result is written back.
func configure(raw []byte) error {
	s := defaults()

	// data_dir can itself come from the config node, so resolve it first.
	var probe Settings
	if node := hostConfigFields(raw); len(node) > 0 {
		_ = json.Unmarshal(node, &probe)
	}
	if strings.TrimSpace(probe.DataDir) != "" {
		s.DataDir = strings.TrimSpace(probe.DataDir)
	}

	if b, err := os.ReadFile(filepath.Join(s.DataDir, "settings.json")); err == nil {
		mergeSettings(&s, b)
	}
	applyConfigNode(&s, hostConfigFields(raw))

	s.APIKeys = normalizeKeys(s.APIKeys)
	s.Models = normalizeModels(s.Models)
	if s.TimeoutSeconds < 10 || s.TimeoutSeconds > 1800 {
		s.TimeoutSeconds = defaultTimeout
	}
	persistSettings(s)

	mu.Lock()
	current = s
	loaded = true
	mu.Unlock()
	return nil
}

func cfg() Settings {
	mu.RLock()
	defer mu.RUnlock()
	return current
}

func timeout() time.Duration {
	return time.Duration(cfg().TimeoutSeconds) * time.Second
}

func credID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return pluginID + "-" + hex.EncodeToString(sum[:])[:16]
}

func modelRevision() string {
	b, _ := json.Marshal(cfg().Models)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// Host bridge
// ---------------------------------------------------------------------------

func callHost(method string, payload any, out any) (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("host callback %s panicked", method)
		}
	}()
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode host callback %s: %w", method, err)
	}
	if len(raw) > math.MaxInt32 {
		return fmt.Errorf("host callback %s request is too large", method)
	}
	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))
	cPayload := C.CBytes(raw)
	defer C.free(cPayload)
	rawResponse, code, err := invokeHost(cMethod, (*C.uint8_t)(cPayload), C.size_t(len(raw)))
	if err != nil {
		return fmt.Errorf("host callback %s: %w", method, err)
	}
	var env envelope
	if err := json.Unmarshal(rawResponse, &env); err != nil {
		return fmt.Errorf("decode host callback %s: %w", method, err)
	}
	if !env.OK {
		if env.Error != nil {
			return env.Error
		}
		return fmt.Errorf("host callback %s failed", method)
	}
	if code != 0 {
		return fmt.Errorf("host callback %s returned code=%d", method, int(code))
	}
	if out != nil && len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return fmt.Errorf("decode host callback %s result: %w", method, err)
		}
	}
	return nil
}

func invokeHost(method *C.char, request *C.uint8_t, requestLen C.size_t) ([]byte, C.int, error) {
	var response C.cliproxy_buffer
	callCode := C.call_host_api(method, request, requestLen, &response)
	if response.ptr == nil || response.len > C.size_t(math.MaxInt32) {
		if response.ptr != nil {
			C.free_host_buffer(response.ptr, response.len)
		}
		return nil, callCode, fmt.Errorf("invalid response buffer, code=%d", int(callCode))
	}
	raw := C.GoBytes(response.ptr, C.int(response.len))
	C.free_host_buffer(response.ptr, response.len)
	return raw, callCode, nil
}

// ---------------------------------------------------------------------------
// Loose JSON access (the host's key spelling is not fully documented, so every
// lookup ignores case, underscores and dashes)
// ---------------------------------------------------------------------------

func decodeMap(raw []byte) map[string]json.RawMessage {
	m := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(raw)) > 0 {
		_ = json.Unmarshal(raw, &m)
	}
	return m
}

func normKey(s string) string {
	return strings.NewReplacer("_", "", "-", "", " ", "", "\t", "").Replace(strings.ToLower(s))
}

func lookup(m map[string]json.RawMessage, names ...string) json.RawMessage {
	for _, name := range names {
		want := normKey(name)
		for k, v := range m {
			if normKey(k) == want {
				return v
			}
		}
	}
	return nil
}

func getString(m map[string]json.RawMessage, names ...string) string {
	raw := lookup(m, names...)
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}

func getBytes(m map[string]json.RawMessage, names ...string) []byte {
	raw := lookup(m, names...)
	if len(raw) == 0 {
		return nil
	}
	var b []byte
	if json.Unmarshal(raw, &b) == nil {
		return b
	}
	// The host may hand over an already-decoded JSON object.
	if raw[0] == '{' {
		return append([]byte(nil), raw...)
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []byte(s)
	}
	return nil
}

func getBool(m map[string]json.RawMessage, names ...string) bool {
	raw := lookup(m, names...)
	if len(raw) == 0 {
		return false
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b
	}
	return false
}

func getInt(m map[string]json.RawMessage, names ...string) int {
	raw := lookup(m, names...)
	if len(raw) == 0 {
		return 0
	}
	var n int
	if json.Unmarshal(raw, &n) == nil {
		return n
	}
	return 0
}

// ---------------------------------------------------------------------------
// Registration / credentials / models
// ---------------------------------------------------------------------------

func registration() map[string]any {
	return map[string]any{
		"schema_version": 6,
		"metadata": map[string]any{
			"Name":             "ClineFreeBridge",
			"Version":          pluginVersion,
			"Author":           "fomaper",
			"Description":      "Cline free-tier provider (cline-free/*) for CLIProxyAPI: product-surface headers, SSE aggregation, per-credential quota windows and a plugin-hosted key console",
			"GitHubRepository": "https://github.com/fomaper/clinefree-plugin",
			"ConfigFields": []map[string]any{
				{"Name": "data_dir", "Type": "string", "Description": "Persistent plugin state directory"},
			},
		},
		"capabilities": map[string]any{
			"auth_provider":            true,
			"model_provider":           true,
			"executor":                 true,
			"management_api":           true,
			"executor_model_scope":     "both",
			"executor_input_formats":   []string{"chat-completions"},
			"executor_output_formats":  []string{"chat-completions"},
		},
	}
}

func modelRegistration() map[string]any {
	models := []map[string]any{}
	for _, m := range cfg().Models {
		if strings.TrimSpace(m.ID) == "" {
			continue
		}
		models = append(models, map[string]any{
			"ID":                        m.ID,
			"Name":                      m.UpstreamID,
			"Object":                    "model",
			"OwnedBy":                   pluginID,
			"DisplayName":               m.ID,
			"SupportedGenerationMethods": []string{"chat"},
			"UserDefined":               true,
		})
	}
	return map[string]any{"Provider": pluginID, "Models": models}
}

func authData(c Credential, filename string) map[string]any {
	raw, _ := json.Marshal(c)
	return map[string]any{
		"Provider":    pluginID,
		"ID":          c.ID,
		"FileName":    filename,
		"Label":       c.Label,
		"Disabled":    c.Disabled,
		"ProxyURL":    "",
		"StorageJSON": json.RawMessage(raw),
		"Metadata":    map[string]any{"type": pluginID},
		"Attributes":  map[string]string{"auth_kind": "api_key"},
	}
}

// syncAuths publishes every configured key into CPA's auth store so the normal
// credential machinery (listing, disabling, scheduling) applies to them.
func syncAuths() error {
	rev := modelRevision()
	keys := normalizeKeys(cfg().APIKeys)
	saved := map[string]string{}
	authDir := ""
	for i, key := range keys {
		c := Credential{Type: pluginID, ID: credID(key), Label: fmt.Sprintf("%s-%d", pluginID, i+1), APIKey: key, ModelRevision: rev}
		blob, _ := json.Marshal(c)
		var out struct {
			Path string `json:"path"`
		}
		if err := callHost("host.auth.save", map[string]any{"name": c.ID + ".json", "json": json.RawMessage(blob)}, &out); err != nil {
			return fmt.Errorf("save credential %s: %w", c.ID, err)
		}
		saved[c.ID] = c.ID + ".json"
		if authDir == "" && strings.TrimSpace(out.Path) != "" {
			authDir = filepath.Dir(strings.TrimSpace(out.Path))
		}
	}
	mu.Lock()
	authFile = saved
	loaded = true
	mu.Unlock()
	pruneAuths(authDir, saved)
	return nil
}

// pruneAuths removes credentials this plugin published earlier but that are no
// longer configured, so deleting a key in the panel actually takes effect.
// Only files that are unambiguously ours are touched: the name must carry our
// prefix and the stored credential must say it is ours.
func pruneAuths(dir string, keep map[string]string) {
	if strings.TrimSpace(dir) == "" {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		if !strings.HasPrefix(id, pluginID+"-") {
			continue
		}
		if _, ok := keep[id]; ok {
			continue
		}
		full := filepath.Join(dir, name)
		b, err := os.ReadFile(full)
		if err != nil {
			continue
		}
		var c Credential
		if json.Unmarshal(b, &c) != nil || c.Type != pluginID {
			continue
		}
		_ = os.Remove(full)
	}
}

func parseAuth(raw json.RawMessage) (any, error) {
	m := decodeMap(raw)
	var c Credential
	if blob := getBytes(m, "StorageJSON", "storage_json", "json"); len(blob) > 0 {
		if err := json.Unmarshal(blob, &c); err != nil {
			return nil, fail(400, "invalid_credential", "credential JSON cannot be parsed")
		}
	}
	if strings.TrimSpace(c.APIKey) == "" {
		return nil, fail(401, "invalid_credential", "credential has no api_key")
	}
	if strings.TrimSpace(c.ID) == "" {
		c.ID = credID(c.APIKey)
	}
	if c.Type == "" {
		c.Type = pluginID
	}
	if c.Label == "" {
		c.Label = pluginID
	}
	filename := c.ID + ".json"
	if name := getString(m, "FileName", "file_name"); strings.TrimSpace(name) != "" {
		filename = filepath.Base(name)
	}
	mu.Lock()
	authFile[c.ID] = filename
	mu.Unlock()
	return authData(c, filename), nil
}

// ---------------------------------------------------------------------------
// Upstream transport (through the host so proxy/TLS/logging stay in CPA)
// ---------------------------------------------------------------------------

type upstreamStream struct {
	StatusCode int         `json:"status_code"`
	Headers    http.Header `json:"headers"`
	StreamID   string      `json:"stream_id"`
}

type streamChunk struct {
	Payload []byte `json:"payload"`
	Error   string `json:"error"`
	Done    bool   `json:"done"`
}

func gateHeaders(h http.Header) http.Header {
	h.Set("HTTP-Referer", "https://cline.bot")
	h.Set("X-Title", "Cline")
	h.Set("X-CLIENT-TYPE", "cline-sdk")
	return h
}

func openUpstream(hostCallbackID, apiKey string, body []byte) (upstreamStream, error) {
	headers := gateHeaders(http.Header{})
	headers.Set("Authorization", "Bearer "+apiKey)
	headers.Set("Content-Type", jsonContentType)
	headers.Set("Accept", sseContentType)

	payload := map[string]any{
		"host_callback_id": hostCallbackID,
		"method":           "POST",
		"url":              cfg().BaseURL + "/chat/completions",
		"headers":          headers,
		"body":             body,
	}
	type result struct {
		up  upstreamStream
		err error
	}
	done := make(chan result, 1)
	go func() {
		var up upstreamStream
		err := callHost("host.http.do_stream", payload, &up)
		done <- result{up, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			return r.up, fail(502, "upstream_unreachable", "upstream transport failed: "+r.err.Error())
		}
		if strings.TrimSpace(r.up.StreamID) == "" {
			return r.up, fail(502, "upstream_unreachable", "host returned no upstream stream")
		}
		return r.up, nil
	case <-time.After(timeout()):
		return upstreamStream{}, fail(504, "upstream_timeout", "Cline upstream request timed out")
	}
}

func closeUpstream(streamID string) {
	if streamID != "" {
		_ = callHost("host.http.stream_close", map[string]any{"stream_id": streamID}, nil)
	}
}

func streamRead(streamID string) ([]byte, bool, error) {
	var chunk streamChunk
	if err := callHost("host.http.stream_read", map[string]any{"stream_id": streamID}, &chunk); err != nil {
		return nil, true, err
	}
	if strings.TrimSpace(chunk.Error) != "" {
		return chunk.Payload, true, errors.New(chunk.Error)
	}
	return chunk.Payload, chunk.Done, nil
}

// ---------------------------------------------------------------------------
// Error classification - explicit http_status keeps CPA from turning
// permission and rate-limit failures into 500s.
// ---------------------------------------------------------------------------

// upstreamFailure carries the mapped error plus the retry window the upstream
// announced, so the caller can park exactly one credential for exactly that
// long instead of guessing.
type upstreamFailure struct {
	err     error
	retryIn time.Duration
	limited bool
}

var (
	// Cline spells its free-tier cap out in prose: "Try again in 6h 41m".
	retryHintPattern = regexp.MustCompile(`(?i)try again in\s*(?:(\d+)\s*h(?:ours?)?)?\s*(?:(\d+)\s*m(?:in(?:utes?)?)?)?`)
	// Some upstreams answer with the shorter form instead.
	retrySecondsPattern = regexp.MustCompile(`(?i)retry after\s+(\d+(?:\.\d+)?)\s*s\b`)
)

// failureOf extracts upstream error text from any of the shapes Cline uses.
// The object form {"error":{"code":"...","message":"..."}} is the common one,
// and it used to fall through to a generic "empty response" because only the
// string form was handled.
func failureOf(obj map[string]any) string {
	switch v := obj["error"].(type) {
	case string:
		return v
	case map[string]any:
		if len(v) > 0 {
			if b, err := json.Marshal(v); err == nil {
				return string(b)
			}
		}
	}
	if m, ok := obj["message"].(string); ok && m != "" {
		return m
	}
	return ""
}

// frameFailure reports an error carried inside an otherwise successful SSE
// frame. Only an explicit error field counts, so ordinary content is untouched.
func frameFailure(j map[string]any) string {
	raw, ok := j["error"]
	if !ok || raw == nil {
		return ""
	}
	switch v := raw.(type) {
	case string:
		return v
	case map[string]any:
		if b, err := json.Marshal(v); err == nil {
			return string(b)
		}
	}
	return ""
}

// parseRetryHint reads the wait the upstream already told us about.
func parseRetryHint(body []byte) time.Duration {
	text := string(body)
	if m := retryHintPattern.FindStringSubmatch(text); len(m) == 3 {
		hours, minutes := 0, 0
		if m[1] != "" {
			hours, _ = strconv.Atoi(m[1])
		}
		if m[2] != "" {
			minutes, _ = strconv.Atoi(m[2])
		}
		if d := time.Duration(hours)*time.Hour + time.Duration(minutes)*time.Minute; d > 0 {
			return d
		}
	}
	if m := retrySecondsPattern.FindStringSubmatch(text); len(m) == 2 {
		if secs, err := strconv.ParseFloat(m[1], 64); err == nil && secs > 0 && secs <= 86400 {
			return time.Duration(secs * float64(time.Second))
		}
	}
	return 0
}

// retryFromHeader reads an integer-seconds Retry-After, if one was sent.
func retryFromHeader(h http.Header) time.Duration {
	if h == nil {
		return 0
	}
	raw := strings.TrimSpace(h.Get("Retry-After"))
	if raw == "" {
		return 0
	}
	secs, err := strconv.ParseFloat(raw, 64)
	if err != nil || secs <= 0 || secs > 86400 {
		return 0
	}
	return time.Duration(secs * float64(time.Second))
}

// quotaMarkers identify the free-tier cap regardless of the HTTP status it
// arrived with. Cline sometimes delivers it inside a 200 body.
var quotaMarkers = []string{
	"inference_cap_error",
	"daily free limit",
	"quota_exceeded",
	"insufficient_quota",
	"usage limit has been reached",
	"insufficient credits",
	"insufficient balance",
}

func looksLikeQuota(text string) bool {
	lower := strings.ToLower(text)
	for _, marker := range quotaMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// classifyFailure maps an upstream answer onto CPA's error vocabulary. A
// permission or rate-limit failure must keep its own status: without an
// explicit http_status CPA degrades everything to 500 and the client backs off
// as if the gateway were broken.
func classifyFailure(status int, body []byte) upstreamFailure {
	text := string(body)
	retryIn := parseRetryHint(body)
	quota := looksLikeQuota(text)

	switch {
	// An explicit 429, or a 2xx body that carries the free-tier cap.
	case status == 429 || (quota && status < 400):
		e := fail(429, "rate_limit_exceeded", "Cline rate limited the request: "+clip(text, 300))
		e.Retryable = true
		if retryIn <= 0 {
			retryIn = 0
		}
		return upstreamFailure{err: e, retryIn: retryIn, limited: true}
	case status == 401:
		return upstreamFailure{err: fail(401, "invalid_api_key", "Cline rejected the credential")}
	case status == 403:
		return upstreamFailure{err: fail(403, "insufficient_quota", "Cline refused the model: "+clip(text, 300))}
	case status == 404:
		return upstreamFailure{err: fail(404, "model_not_found", "Cline does not expose this model: "+clip(text, 300))}
	case status >= 500:
		return upstreamFailure{err: fail(502, "upstream_error", "Cline upstream error: "+clip(text, 300))}
	case status >= 400:
		return upstreamFailure{err: fail(400, "invalid_request", "Cline rejected the request: "+clip(text, 300))}
	}
	return upstreamFailure{}
}

// ---------------------------------------------------------------------------
// Per-credential rate-limit gate
//
// Cline's cap is per account, and each of the configured keys is its own
// account with its own reset clock. Parking one credential for the announced
// window keeps the other keys serving instead of letting the scheduler keep
// handing work to an account that is already empty.
// ---------------------------------------------------------------------------

type rateWindow struct {
	until   time.Time
	probing bool
	epoch   uint64
}

type rateGate struct {
	mu      sync.Mutex
	windows map[string]*rateWindow
}

var gate = &rateGate{windows: map[string]*rateWindow{}}

// admit reports whether this credential may go upstream. When the window has
// expired exactly one recovery probe is let through.
func (g *rateGate) admit(id string) (uint64, time.Duration, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	// Drop idle windows so credential rotation cannot grow the map forever.
	for key, w := range g.windows {
		if !w.probing && time.Since(w.until) > 10*time.Minute {
			delete(g.windows, key)
		}
	}
	w := g.windows[id]
	if w == nil {
		return 0, 0, true
	}
	now := time.Now()
	if now.Before(w.until) {
		return w.epoch, w.until.Sub(now), false
	}
	if w.probing {
		// A probe is already in flight; do not stampede the upstream.
		return w.epoch, 0, false
	}
	w.probing = true
	return w.epoch, 0, true
}

// settle records the outcome of a request that passed admit.
func (g *rateGate) settle(id string, epoch uint64, f upstreamFailure) {
	g.mu.Lock()
	defer g.mu.Unlock()
	w := g.windows[id]
	if f.limited {
		retryIn := f.retryIn
		if retryIn <= 0 {
			retryIn = time.Minute
		}
		if w == nil {
			w = &rateWindow{}
			g.windows[id] = w
		}
		if until := time.Now().Add(retryIn); until.After(w.until) {
			w.until = until
		}
		w.probing = false
		w.epoch++
		return
	}
	if w == nil {
		return
	}
	w.probing = false
	// A success only clears the window it started from: an older in-flight
	// call must not erase a newer limit.
	if f.err == nil && w.epoch == epoch {
		delete(g.windows, id)
	}
}

// blockedError renders the local short-circuit for a parked credential.
func blockedError(id string, remaining time.Duration) *rpcError {
	secs := int64(remaining.Seconds())
	if secs < 1 {
		secs = 1
	}
	e := fail(429, "rate_limit_exceeded", fmt.Sprintf(
		"Cline account %s is out of quota; retry in %ds (another key is serving in the meantime)", id, secs))
	e.Retryable = true
	return e
}


func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ---------------------------------------------------------------------------
// SSE handling
// ---------------------------------------------------------------------------

type frameScanner struct {
	buf []byte
}

// next returns the payload of the next complete "data:" line, if any.
func (s *frameScanner) next() (string, bool) {
	for {
		i := bytes.IndexByte(s.buf, '\n')
		if i < 0 {
			return "", false
		}
		line := strings.TrimRight(string(s.buf[:i]), "\r")
		s.buf = s.buf[i+1:]
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		return strings.TrimSpace(strings.TrimPrefix(line, "data:")), true
	}
}

// aggregate folds an upstream SSE stream into one chat.completion body. Cline's
// native non-streaming path answers with an envelope and can come back empty,
// so the executor always asks upstream for SSE and rebuilds the JSON itself.
func aggregate(model string, raw []byte) ([]byte, upstreamFailure) {
	sc := &frameScanner{buf: raw}
	type toolState struct {
		id   string
		typ  string
		name string
		args strings.Builder
	}
	type choiceState struct {
		content   strings.Builder
		reasoning strings.Builder
		finish    string
		tools     map[int]*toolState
		toolOrder []int
	}
	states := map[int]*choiceState{}
	order := []int{}
	var usage json.RawMessage
	var id string
	created := time.Now().Unix()
	sawFrame := false

	for {
		payload, ok := sc.next()
		if !ok {
			break
		}
		if payload == "" || payload == "[DONE]" {
			continue
		}
		var j map[string]any
		if err := json.Unmarshal([]byte(payload), &j); err != nil {
			continue
		}
		sawFrame = true
		if s, ok := j["id"].(string); ok && s != "" {
			id = s
		}
		if n, ok := j["created"].(float64); ok && n > 0 {
			created = int64(n)
		}
		if u, ok := j["usage"]; ok && u != nil {
			if b, err := json.Marshal(u); err == nil {
				usage = b
			}
		}
		choices, _ := j["choices"].([]any)
		for _, cv := range choices {
			ch, _ := cv.(map[string]any)
			idx := 0
			if f, ok := ch["index"].(float64); ok {
				idx = int(f)
			}
			st, seen := states[idx]
			if !seen {
				st = &choiceState{tools: map[int]*toolState{}}
				states[idx] = st
				order = append(order, idx)
			}
			if d, ok := ch["delta"].(map[string]any); ok {
				// content and reasoning are independent channels: a frame may
				// carry either, and treating them as alternatives dropped one.
				if s := stringOf(d["content"]); s != "" {
					st.content.WriteString(s)
				}
				if s := stringOf(d["reasoning"]); s != "" {
					st.reasoning.WriteString(s)
				}
				if s := stringOf(d["reasoning_content"]); s != "" {
					st.reasoning.WriteString(s)
				}
				// Tool calls arrive as fragments keyed by index: the first one
				// carries id/name, the rest only extend the arguments string.
				if rawCalls, ok := d["tool_calls"].([]any); ok {
					for _, cv := range rawCalls {
						call, _ := cv.(map[string]any)
						if call == nil {
							continue
						}
						ti := 0
						if f, ok := call["index"].(float64); ok {
							ti = int(f)
						}
						t, seen := st.tools[ti]
						if !seen {
							t = &toolState{}
							st.tools[ti] = t
							st.toolOrder = append(st.toolOrder, ti)
						}
						if s := stringOf(call["id"]); s != "" {
							t.id = s
						}
						if s := stringOf(call["type"]); s != "" {
							t.typ = s
						}
						if fn, ok := call["function"].(map[string]any); ok {
							if s := stringOf(fn["name"]); s != "" {
								t.name = s
							}
							if s := stringOf(fn["arguments"]); s != "" {
								t.args.WriteString(s)
							}
						}
					}
				}
			}
			if s := stringOf(ch["finish_reason"]); s != "" {
				st.finish = s
			}
		}
	}

	if !sawFrame {
		// Not an SSE body: either a plain completion or Cline's envelope.
		var obj map[string]any
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil, upstreamFailure{err: fail(502, "upstream_error", "upstream returned an unrecognised body: "+clip(string(raw), 300))}
		}
		if inner, ok := obj["data"].(map[string]any); ok && inner["choices"] != nil {
			out, err := json.Marshal(inner)
			return out, upstreamFailure{err: err}
		}
		if obj["choices"] != nil {
			out, err := json.Marshal(obj)
			return out, upstreamFailure{err: err}
		}
		if txt := failureOf(obj); txt != "" {
			if f := classifyFailure(200, []byte(txt)); f.err != nil {
				return nil, f
			}
			return nil, upstreamFailure{err: fail(502, "upstream_error", clip(txt, 300))}
		}
		return nil, upstreamFailure{err: fail(502, "upstream_error", "upstream returned an empty response")}
	}

	if len(order) == 0 {
		return nil, upstreamFailure{err: fail(502, "upstream_error", "upstream stream carried no choices")}
	}
	sortInts(order)
	out := map[string]any{
		"id":      firstNonEmpty(id, "chatcmpl-"+strconv.FormatInt(time.Now().UnixNano(), 36)),
		"object":  "chat.completion",
		"created": created,
		"model":   model,
	}
	list := make([]map[string]any, 0, len(order))
	for _, idx := range order {
		st := states[idx]
		msg := map[string]any{"role": "assistant", "content": st.content.String()}
		if st.reasoning.Len() > 0 {
			msg["reasoning"] = st.reasoning.String()
		}
		if len(st.tools) > 0 {
			sortInts(st.toolOrder)
			calls := make([]map[string]any, 0, len(st.tools))
			for _, ti := range st.toolOrder {
				t := st.tools[ti]
				calls = append(calls, map[string]any{
					"id":   firstNonEmpty(t.id, "call_"+strconv.Itoa(ti)),
					"type": firstNonEmpty(t.typ, "function"),
					"function": map[string]any{
						"name":      t.name,
						"arguments": firstNonEmpty(t.args.String(), "{}"),
					},
				})
			}
			msg["tool_calls"] = calls
		}
		list = append(list, map[string]any{
			"index":         idx,
			"message":       msg,
			"finish_reason": firstNonEmpty(st.finish, "stop"),
		})
	}
	out["choices"] = list
	if len(usage) > 0 {
		var u any
		if json.Unmarshal(usage, &u) == nil {
			out["usage"] = u
		}
	}
	body, err := json.Marshal(out)
	return body, upstreamFailure{err: err}
}

func sortInts(v []int) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j-1] > v[j]; j-- {
			v[j-1], v[j] = v[j], v[j-1]
		}
	}
}

func stringOf(v any) string {
	s, _ := v.(string)
	return s
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

type execRequest struct {
	AuthID         string
	Model          string
	Stream         bool
	Payload        []byte
	StreamID       string
	HostCallbackID string
}

func parseExecRequest(raw json.RawMessage) execRequest {
	m := decodeMap(raw)
	return execRequest{
		AuthID:         getString(m, "AuthID", "auth_id"),
		Model:          getString(m, "Model", "model"),
		Stream:         getBool(m, "Stream", "stream"),
		Payload:        getBytes(m, "Payload", "payload", "OriginalRequest", "original_request"),
		StreamID:       getString(m, "StreamID", "stream_id"),
		HostCallbackID: getString(m, "HostCallbackID", "host_callback_id"),
	}
}

func upstreamModel(model string) (string, error) {
	for _, m := range cfg().Models {
		if m.ID == model {
			return m.UpstreamID, nil
		}
	}
	return "", fail(404, "model_not_found", "model is not enabled in clinefree: "+model)
}

func selectKey(authID string) (string, error) {
	keys := cfg().APIKeys
	if len(keys) == 0 {
		return "", fail(401, "invalid_api_key", "clinefree has no api key configured")
	}
	if strings.TrimSpace(authID) != "" {
		for _, k := range keys {
			if credID(strings.TrimSpace(k)) == authID {
				return strings.TrimSpace(k), nil
			}
		}
	}
	return strings.TrimSpace(keys[0]), nil
}

func buildRequest(r execRequest, upstream string, stream bool) ([]byte, error) {
	var body map[string]any
	if len(r.Payload) > 0 {
		if err := json.Unmarshal(r.Payload, &body); err != nil {
			return nil, fail(400, "invalid_request", "request payload is not JSON")
		}
	} else {
		body = map[string]any{}
	}
	body["model"] = upstream
	body["stream"] = stream
	delete(body, "providerOptions")
	return json.Marshal(body)
}

func readAll(streamID string) ([]byte, error) {
	var out []byte
	deadline := time.Now().Add(timeout())
	for {
		chunk, done, err := streamRead(streamID)
		out = append(out, chunk...)
		if err != nil {
			return out, err
		}
		if done {
			return out, nil
		}
		if time.Now().After(deadline) {
			return out, fail(504, "upstream_timeout", "upstream stream exceeded the request timeout")
		}
	}
}

func execute(r execRequest) (any, error) {
	upstream, err := upstreamModel(r.Model)
	if err != nil {
		return nil, err
	}
	key, err := selectKey(r.AuthID)
	if err != nil {
		return nil, err
	}
	id := credID(key)
	epoch, remaining, allowed := gate.admit(id)
	if !allowed {
		return nil, blockedError(id, remaining)
	}
	body, err := buildRequest(r, upstream, true)
	if err != nil {
		gate.settle(id, epoch, upstreamFailure{err: err})
		return nil, err
	}
	up, err := openUpstream(r.HostCallbackID, key, body)
	if err != nil {
		gate.settle(id, epoch, upstreamFailure{err: err})
		return nil, err
	}
	raw, readErr := readAll(up.StreamID)
	closeUpstream(up.StreamID)
	f := classifyFailure(up.StatusCode, raw)
	if f.retryIn <= 0 {
		f.retryIn = retryFromHeader(up.Headers)
	}
	if f.err != nil {
		gate.settle(id, epoch, f)
		return nil, f.err
	}
	if readErr != nil {
		gate.settle(id, epoch, upstreamFailure{err: readErr})
		return nil, fail(502, "upstream_incomplete_stream", readErr.Error())
	}
	out, aggFailure := aggregate(r.Model, raw)
	gate.settle(id, epoch, aggFailure)
	if aggFailure.err != nil {
		return nil, aggFailure.err
	}
	return map[string]any{
		"Payload": out,
		"Headers": http.Header{"Content-Type": []string{jsonContentType}},
	}, nil
}

func executeStream(r execRequest) (any, error) {
	upstream, err := upstreamModel(r.Model)
	if err != nil {
		return nil, err
	}
	key, err := selectKey(r.AuthID)
	if err != nil {
		return nil, err
	}
	id := credID(key)
	epoch, remaining, allowed := gate.admit(id)
	if !allowed {
		return nil, blockedError(id, remaining)
	}
	body, err := buildRequest(r, upstream, true)
	if err != nil {
		gate.settle(id, epoch, upstreamFailure{err: err})
		return nil, err
	}
	up, err := openUpstream(r.HostCallbackID, key, body)
	if err != nil {
		gate.settle(id, epoch, upstreamFailure{err: err})
		return nil, err
	}

	// A non-2xx upstream answer is only readable as a body, and it must travel
	// back through the structured envelope so CPA keeps the real status code.
	if up.StatusCode >= 400 {
		raw, _ := readAll(up.StreamID)
		closeUpstream(up.StreamID)
		f := classifyFailure(up.StatusCode, raw)
		if f.retryIn <= 0 {
			f.retryIn = retryFromHeader(up.Headers)
		}
		gate.settle(id, epoch, f)
		if f.err != nil {
			return nil, f.err
		}
		return nil, fail(502, "upstream_error", "upstream returned status "+strconv.Itoa(up.StatusCode))
	}
	if strings.TrimSpace(r.StreamID) == "" {
		closeUpstream(up.StreamID)
		return nil, fail(500, "no_output_stream", "host provided no output stream identifier")
	}

	// CPA only starts forwarding the client response after this RPC returns, so
	// the upstream read loop runs in the background. It unblocks as soon as real
	// model output arrives; anything that fails before that point still travels
	// through the structured envelope and keeps its HTTP status.
	ready := make(chan error, 1)
	go func() {
		var runErr error
		var settle upstreamFailure
		started := false
		pending := [][]byte{}
		pendingBytes := 0
		sc := &frameScanner{}
		defer func() {
			if recover() != nil {
				runErr = fail(500, "stream_failed", "stream processing failed")
			}
			if settle.err == nil && runErr != nil {
				settle.err = runErr
			}
			closeUpstream(up.StreamID)
			gate.settle(id, epoch, settle)
			_ = callHost("host.stream.close", map[string]any{"stream_id": r.StreamID, "error": errorText(runErr)}, nil)
			if !started {
				ready <- firstErr(runErr, fail(502, "upstream_incomplete_stream", "upstream ended before any completion frame"))
			}
		}()
		deadline := time.Now().Add(timeout())
		for {
			chunk, done, readErr := streamRead(up.StreamID)
			if len(chunk) > 0 {
				sc.buf = append(sc.buf, chunk...)
				for {
					payload, ok := sc.next()
					if !ok {
						break
					}
					if payload == "" || payload == "[DONE]" {
						// CPA adds the stream terminator itself.
						continue
					}
					var j map[string]any
					if json.Unmarshal([]byte(payload), &j) != nil {
						continue
					}
					// Cline can open a 200 stream and only then report the
					// failure inside a frame. Detect it before it reaches the
					// client as if it were content.
					if txt := frameFailure(j); txt != "" {
						f := classifyFailure(200, []byte(txt))
						if f.err == nil {
							f = upstreamFailure{err: fail(502, "upstream_error", clip(txt, 300))}
						}
						if f.retryIn <= 0 {
							f.retryIn = retryFromHeader(up.Headers)
						}
						settle = f
						runErr = f.err
						return
					}
					j["model"] = r.Model
					frame, errMarshal := json.Marshal(j)
					if errMarshal != nil {
						continue
					}
					if !started {
						if !startsCompletion(j) {
							pendingBytes += len(frame)
							if pendingBytes > 64<<10 {
								runErr = fail(502, "upstream_incomplete_stream", "upstream prelude exceeds 64 KiB")
								return
							}
							pending = append(pending, frame)
							continue
						}
						started = true
						ready <- nil
						for _, buffered := range pending {
							if e := emitFrame(r.StreamID, buffered); e != nil {
								runErr = e
								return
							}
						}
						pending = nil
					}
					if e := emitFrame(r.StreamID, frame); e != nil {
						runErr = e
						return
					}
				}
			}
			if readErr != nil {
				runErr = fail(502, "upstream_incomplete_stream", readErr.Error())
				return
			}
			if done {
				return
			}
			if time.Now().After(deadline) {
				runErr = fail(504, "upstream_timeout", "upstream stream exceeded the request timeout")
				return
			}
		}
	}()

	if err := <-ready; err != nil {
		return nil, err
	}
	return map[string]any{"headers": http.Header{"Content-Type": []string{sseContentType}}}, nil
}

func emitFrame(streamID string, payload []byte) error {
	if err := callHost("host.stream.emit", map[string]any{"stream_id": streamID, "payload": payload}, nil); err != nil {
		return fail(499, "client_disconnected", "client disconnected: "+err.Error())
	}
	return nil
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func firstErr(primary error, fallback error) error {
	if primary != nil {
		return primary
	}
	return fallback
}

// startsCompletion reports whether a frame is real model output rather than the
// role/metadata prelude, so early failures can still be reported structurally.
func startsCompletion(j map[string]any) bool {
	choices, _ := j["choices"].([]any)
	for _, cv := range choices {
		ch, _ := cv.(map[string]any)
		if ch == nil {
			continue
		}
		if stringOf(ch["finish_reason"]) != "" {
			return true
		}
		d, _ := ch["delta"].(map[string]any)
		if d == nil {
			continue
		}
		if stringOf(d["content"]) != "" || stringOf(d["reasoning"]) != "" || stringOf(d["reasoning_content"]) != "" {
			return true
		}
		if list, ok := d["tool_calls"].([]any); ok && len(list) > 0 {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Plugin-hosted console
//
// The host auto-generates an OAuth entry for every plugin that declares
// auth_provider, and that entry can never work here (this plugin authenticates
// with API keys, not OAuth). The host offers no way to suppress it, so the
// usable interface lives in the plugin itself: a management route set plus a
// browser page at /v0/resource/plugins/clinefree/console.
//
// Resource routes are not management-authenticated, so the page asks for the
// CPA management key once and keeps it in sessionStorage for its API calls.
// ---------------------------------------------------------------------------

const consoleAPIPath = "/v0/management/" + pluginID
const consolePagePath = "/v0/resource/plugins/" + pluginID + "/console"

type managementResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

func jsonResponse(code int, payload any) managementResponse {
	body, err := json.Marshal(payload)
	if err != nil {
		code, body = 500, []byte(`{"error":"response cannot be encoded"}`)
	}
	return managementResponse{
		StatusCode: code,
		Headers:    http.Header{"Content-Type": []string{"application/json; charset=utf-8"}, "Cache-Control": []string{"no-store"}},
		Body:       body,
	}
}

func htmlResponse(body string) managementResponse {
	return managementResponse{
		StatusCode: 200,
		Headers:    http.Header{"Content-Type": []string{"text/html; charset=utf-8"}, "Cache-Control": []string{"no-store"}},
		Body:       []byte(body),
	}
}

func managementRegister() map[string]any {
	routes := []map[string]string{
		{"Method": "GET", "Path": consoleAPIPath + "/keys"},
		{"Method": "POST", "Path": consoleAPIPath + "/keys"},
		{"Method": "DELETE", "Path": consoleAPIPath + "/keys"},
	}
	resources := []map[string]string{{
		"Path":        "/console",
		"Menu":        "ClineFreeBridge",
		"Description": "管理 Cline API key：查看、添加、删除；每把 key 对应一个 Cline 账号",
	}}
	return map[string]any{"routes": routes, "resources": resources}
}

func maskKey(key string) string {
	if len(key) <= 14 {
		return strings.Repeat("*", 8)
	}
	return key[:8] + "…" + key[len(key)-6:]
}

func keysSnapshot() map[string]any {
	keys := cfg().APIKeys
	items := make([]map[string]any, 0, len(keys))
	for i, key := range keys {
		items = append(items, map[string]any{
			"id":     credID(key),
			"masked": maskKey(key),
			"label":  fmt.Sprintf("#%d", i+1),
		})
	}
	return map[string]any{"count": len(keys), "keys": items, "models": cfg().Models}
}

// applyKeys swaps the key list, mirrors it to disk and republishes credentials.
// syncAuths also prunes credentials that are no longer configured.
func applyKeys(keys []string) error {
	mu.Lock()
	current.APIKeys = normalizeKeys(keys)
	snapshot := current
	mu.Unlock()
	persistSettings(snapshot)
	return syncAuths()
}

// mergeKeys appends only keys that are not already present.
func mergeKeys(existing, incoming []string) ([]string, int) {
	out := normalizeKeys(existing)
	seen := map[string]bool{}
	for _, key := range out {
		seen[key] = true
	}
	added := 0
	for _, key := range normalizeKeys(incoming) {
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
		added++
	}
	return out, added
}

// dropKey removes the credential identified by its derived id.
func dropKey(keys []string, id string) ([]string, int) {
	out := make([]string, 0, len(keys))
	removed := 0
	for _, key := range normalizeKeys(keys) {
		if credID(key) == id {
			removed++
			continue
		}
		out = append(out, key)
	}
	return out, removed
}

// firstQueryValue reads a query parameter. url.Values encodes each key as a
// list, so both shapes are accepted.
func firstQueryValue(query map[string]json.RawMessage, names ...string) string {
	raw := lookup(query, names...)
	if len(raw) == 0 {
		return ""
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		for _, item := range list {
			if strings.TrimSpace(item) != "" {
				return strings.TrimSpace(item)
			}
		}
		return ""
	}
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return strings.TrimSpace(single)
	}
	return ""
}

func managementHandle(raw json.RawMessage) (any, error) {
	fields := decodeMap(raw)
	method := strings.ToUpper(strings.TrimSpace(getString(fields, "Method", "method")))
	path := strings.TrimSpace(getString(fields, "Path", "path"))
	body := getBytes(fields, "Body", "body")
	query := decodeMap(getBytes(fields, "Query", "query"))

	switch {
	case method == "GET" && path == consolePagePath:
		return htmlResponse(consoleHTML), nil

	case method == "GET" && path == consoleAPIPath+"/keys":
		return jsonResponse(200, keysSnapshot()), nil

	case method == "POST" && path == consoleAPIPath+"/keys":
		var in struct {
			Keys []string `json:"keys"`
			Key  string   `json:"key"`
		}
		if len(body) > 0 {
			_ = json.Unmarshal(body, &in)
		}
		if strings.TrimSpace(in.Key) != "" {
			in.Keys = append(in.Keys, in.Key)
		}
		incoming := normalizeKeys(in.Keys)
		if len(incoming) == 0 {
			return jsonResponse(400, map[string]any{"error": "no api key supplied"}), nil
		}
		next, added := mergeKeys(cfg().APIKeys, incoming)
		if added == 0 {
			out := keysSnapshot()
			out["added"] = 0
			out["message"] = "这些 key 已经存在"
			return jsonResponse(200, out), nil
		}
		if err := applyKeys(next); err != nil {
			return jsonResponse(500, map[string]any{"error": err.Error()}), nil
		}
		out := keysSnapshot()
		out["added"] = added
		out["message"] = fmt.Sprintf("已添加 %d 把 key", added)
		return jsonResponse(200, out), nil

	case method == "DELETE" && path == consoleAPIPath+"/keys":
		id := firstQueryValue(query, "id", "Id", "ID")
		if id == "" {
			return jsonResponse(400, map[string]any{"error": "id is required"}), nil
		}
		next, removed := dropKey(cfg().APIKeys, id)
		if removed == 0 {
			return jsonResponse(404, map[string]any{"error": "credential not found"}), nil
		}
		if err := applyKeys(next); err != nil {
			return jsonResponse(500, map[string]any{"error": err.Error()}), nil
		}
		out := keysSnapshot()
		out["removed"] = removed
		out["message"] = "已删除 1 把 key"
		return jsonResponse(200, out), nil
	}

	return jsonResponse(404, map[string]any{"error": "not found", "path": path, "method": method}), nil
}

const consoleHTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ClineFreeBridge</title>
<style>
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin:0; padding:24px; font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
       background:#f6f7f9; color:#1f2328; }
.wrap { max-width:820px; margin:0 auto; }
h1 { font-size:20px; margin:0 0 4px; }
h2 { font-size:15px; margin:0 0 10px; }
.sub { color:#6b7280; margin:0 0 20px; }
.card { background:#fff; border:1px solid #e5e7eb; border-radius:10px; padding:18px; margin-bottom:16px; }
.row { display:flex; gap:8px; align-items:center; }
input[type=password], textarea { width:100%; padding:9px 11px; border:1px solid #d1d5db; border-radius:8px;
       font:inherit; background:#fff; color:inherit; }
textarea { min-height:110px; resize:vertical; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
button { padding:9px 16px; border:0; border-radius:8px; background:#2563eb; color:#fff; font:inherit; cursor:pointer; white-space:nowrap; }
button.ghost { background:#eef2f7; color:#374151; }
button.danger { background:#fee2e2; color:#b91c1c; padding:5px 12px; font-size:13px; }
button:disabled { opacity:.5; cursor:default; }
ul { list-style:none; margin:0; padding:0; }
li { display:flex; align-items:center; justify-content:space-between; gap:12px; padding:9px 0; border-bottom:1px solid #f1f3f5; }
li:last-child { border-bottom:0; }
code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:13px; }
.muted { color:#6b7280; }
.msg { margin-top:12px; padding:9px 12px; border-radius:8px; display:none; }
.msg.ok { display:block; background:#ecfdf5; color:#065f46; }
.msg.err { display:block; background:#fef2f2; color:#991b1b; }
.hide { display:none; }
@media (prefers-color-scheme: dark) {
  body { background:#16181d; color:#e6e8eb; }
  .card { background:#1e2128; border-color:#2d3139; }
  input[type=password], textarea { background:#16181d; border-color:#3a3f48; color:#e6e8eb; }
  button.ghost { background:#2a2e36; color:#d1d5db; }
  li { border-bottom-color:#2a2e36; }
}
</style>
</head>
<body>
<div class="wrap">
  <h1>ClineFreeBridge</h1>
  <p class="sub">管理 Cline API key。每把 key 对应一个 Cline 账号，日额度各自独立，请求按轮询分发。</p>

  <div class="card" id="authCard">
    <h2>连接</h2>
    <div class="sub" style="margin:0 0 10px">填入 CPA 管理密钥，只保存在本标签页的 sessionStorage，关闭即失效。</div>
    <div class="row">
      <input id="mgmtKey" type="password" placeholder="CPA 管理密钥" autocomplete="off">
      <button id="connect">连接</button>
    </div>
  </div>

  <div id="panel" class="hide">
    <div class="card">
      <h2>已有 key <span class="muted" id="count"></span></h2>
      <ul id="list"></ul>
    </div>

    <div class="card">
      <h2>添加 key</h2>
      <div class="sub" style="margin:0 0 10px">每行一个，以 sk_ 开头。保存后会立即发布成凭据，无需重启。</div>
      <textarea id="newKeys" placeholder="sk_xxxxxxxxxxxxxxxx"></textarea>
      <div class="row" style="margin-top:10px">
        <button id="add">添加</button>
        <button id="reload" class="ghost">刷新</button>
      </div>
    </div>

    <div class="card">
      <h2>模型映射</h2>
      <ul id="models"></ul>
    </div>
  </div>

  <div class="msg" id="msg"></div>
</div>

<script>
(function () {
  var API = "` + consoleAPIPath + `";
  var STORE = "clinefree.mgmtKey";
  var keyInput = document.getElementById("mgmtKey");
  var panel = document.getElementById("panel");
  var listEl = document.getElementById("list");
  var modelsEl = document.getElementById("models");
  var countEl = document.getElementById("count");
  var msgEl = document.getElementById("msg");
  var ta = document.getElementById("newKeys");

  function token() { return keyInput.value.trim(); }

  function say(text, kind) {
    msgEl.textContent = text;
    msgEl.className = "msg " + (kind || "ok");
    if (!text) { msgEl.className = "msg"; }
  }

  function call(method, path, body) {
    var headers = { "Authorization": "Bearer " + token() };
    if (body !== undefined) { headers["Content-Type"] = "application/json"; }
    return fetch(path, { method: method, headers: headers, body: body === undefined ? undefined : JSON.stringify(body) })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (data) {
          if (!r.ok) { throw new Error((data && data.error) || ("HTTP " + r.status)); }
          return data;
        });
      });
  }

  function render(data) {
    countEl.textContent = "共 " + data.count + " 把";
    listEl.innerHTML = "";
    if (!data.keys || !data.keys.length) {
      var empty = document.createElement("li");
      empty.className = "muted";
      empty.textContent = "还没有 key，先在下面添加。";
      listEl.appendChild(empty);
    } else {
      data.keys.forEach(function (item) {
        var li = document.createElement("li");
        var left = document.createElement("span");
        var code = document.createElement("code");
        code.textContent = item.masked;
        var tag = document.createElement("span");
        tag.className = "muted";
        tag.textContent = "  " + item.label;
        left.appendChild(code);
        left.appendChild(tag);
        var del = document.createElement("button");
        del.className = "danger";
        del.textContent = "删除";
        del.onclick = function () {
          if (!confirm("删除 " + item.masked + " ？")) { return; }
          del.disabled = true;
          call("DELETE", API + "/keys?id=" + encodeURIComponent(item.id))
            .then(function (d) { say(d.message || "已删除", "ok"); render(d); })
            .catch(function (e) { say("删除失败：" + e.message, "err"); del.disabled = false; });
        };
        li.appendChild(left);
        li.appendChild(del);
        listEl.appendChild(li);
      });
    }
    modelsEl.innerHTML = "";
    (data.models || []).forEach(function (m) {
      var li = document.createElement("li");
      var left = document.createElement("span");
      var code = document.createElement("code");
      code.textContent = m.id;
      var arrow = document.createElement("span");
      arrow.className = "muted";
      arrow.textContent = "  →  " + m.upstream_id;
      left.appendChild(code);
      left.appendChild(arrow);
      li.appendChild(left);
      modelsEl.appendChild(li);
    });
  }

  function load() {
    return call("GET", API + "/keys").then(render);
  }

  function connect() {
    if (!token()) { say("先填管理密钥", "err"); return; }
    sessionStorage.setItem(STORE, token());
    load().then(function () {
      panel.classList.remove("hide");
      say("已连接", "ok");
    }).catch(function (e) {
      panel.classList.add("hide");
      say("连接失败：" + e.message, "err");
    });
  }

  document.getElementById("connect").onclick = connect;
  document.getElementById("reload").onclick = function () {
    load().then(function () { say("已刷新", "ok"); }).catch(function (e) { say("刷新失败：" + e.message, "err"); });
  };
  document.getElementById("add").onclick = function () {
    var keys = ta.value.split(/[\r\n,;]+/).map(function (s) { return s.trim(); }).filter(Boolean);
    if (!keys.length) { say("先粘贴至少一把 key", "err"); return; }
    var btn = this;
    btn.disabled = true;
    call("POST", API + "/keys", { keys: keys })
      .then(function (d) { ta.value = ""; say(d.message || "已添加", "ok"); render(d); })
      .catch(function (e) { say("添加失败：" + e.message, "err"); })
      .finally(function () { btn.disabled = false; });
  };

  var saved = sessionStorage.getItem(STORE);
  if (saved) { keyInput.value = saved; connect(); }
})();
</script>
</body>
</html>
`



func handle(method string, raw json.RawMessage) (any, error) {
	switch method {
	case "plugin.register", "plugin.reconfigure":
		if err := configure(raw); err != nil {
			return nil, err
		}
		if err := syncAuths(); err != nil {
			return nil, fail(500, "credential_persistence_failed", err.Error())
		}
		return registration(), nil
	case "executor.identifier", "auth.identifier":
		return map[string]any{"identifier": pluginID}, nil
	case "model.static", "model.for_auth":
		return modelRegistration(), nil
	case "auth.parse":
		return parseAuth(raw)
	case "auth.login.start":
		return nil, fail(400, "unsupported", "clinefree 使用 API key 认证，请在插件页面（/v0/resource/plugins/clinefree/console）添加")
	case "auth.login.poll":
		return map[string]any{"Status": "error", "Message": "clinefree 使用 API key 认证"}, nil
	case "auth.refresh":
		parsed, err := parseAuth(raw)
		if err != nil {
			return nil, err
		}
		return map[string]any{"Auth": parsed, "NextRefreshAfter": time.Now().Add(365 * 24 * time.Hour)}, nil
	case "management.register":
		return managementRegister(), nil
	case "management.handle":
		return managementHandle(raw)
	case "executor.execute":
		return execute(parseExecRequest(raw))
	case "executor.execute_stream":
		return executeStream(parseExecRequest(raw))
	case "executor.count_tokens":
		return nil, fail(501, "unsupported", "clinefree does not expose token counting")
	case "executor.http_request":
		return nil, fail(400, "unsupported", "clinefree does not proxy arbitrary HTTP")
	case "plugin.shutdown":
		return map[string]any{}, nil
	default:
		return nil, fail(400, "unsupported_method", "unsupported plugin method: "+method)
	}
}

// ---------------------------------------------------------------------------
// C ABI surface
// ---------------------------------------------------------------------------

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) (rc C.int) {
	defer func() {
		if recover() != nil {
			rc = 1
		}
	}()
	if host == nil || host.abi_version != C.uint32_t(abiVersion) || host.call == nil || host.free_buffer == nil || plugin == nil {
		return 1
	}
	C.store_host_api(host)
	plugin.abi_version = C.uint32_t(abiVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) (rc C.int) {
	if response == nil {
		return 1
	}
	response.ptr = nil
	response.len = 0
	defer func() {
		if recover() != nil {
			writeResponse(response, failure(fail(500, "plugin_panic", "plugin callback panicked")))
			rc = 1
		}
	}()
	if method == nil || strings.TrimSpace(C.GoString(method)) == "" {
		writeResponse(response, failure(fail(400, "invalid_method", "method is required")))
		return 1
	}
	if requestLen > C.size_t(math.MaxInt32) || (requestLen > 0 && request == nil) {
		writeResponse(response, failure(fail(400, "invalid_request", "request buffer is invalid")))
		return 1
	}
	var raw json.RawMessage
	if requestLen > 0 {
		raw = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
		if !json.Valid(raw) {
			writeResponse(response, failure(fail(400, "invalid_request", "request JSON is invalid")))
			return 1
		}
	}
	result, err := handle(C.GoString(method), raw)
	if err != nil {
		writeResponse(response, failure(errorDetails(err)))
		return 1
	}
	encoded, encErr := success(result)
	if encErr != nil {
		writeResponse(response, failure(fail(500, "serialization_error", "plugin response cannot be encoded")))
		return 1
	}
	writeResponse(response, encoded)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, _ C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {
	defer func() { _ = recover() }()
	C.store_host_api(nil)
	_, _ = handle("plugin.shutdown", nil)
}

func success(result any) ([]byte, error) {
	if result == nil {
		result = struct{}{}
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{OK: true, Result: raw})
}

func failure(details *rpcError) []byte {
	raw, err := json.Marshal(envelope{OK: false, Error: details})
	if err != nil {
		return []byte(`{"ok":false,"error":{"code":"serialization_error","message":"plugin error cannot be encoded","http_status":500}}`)
	}
	return raw
}

func errorDetails(err error) *rpcError {
	details := fail(500, "plugin_error", err.Error())
	var status interface{ StatusCode() int }
	if errors.As(err, &status) && status.StatusCode() >= 400 && status.StatusCode() <= 599 {
		details.HTTPStatus = status.StatusCode()
	}
	var code interface{ Code() string }
	if errors.As(err, &code) && strings.TrimSpace(code.Code()) != "" {
		details.ErrorCode = code.Code()
	}
	return details
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	response.ptr = C.CBytes(raw)
	response.len = C.size_t(len(raw))
}

func main() {}
