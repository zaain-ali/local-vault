package vault

// This is the core of LocalVault
// Handles: storing secrets, reading secrets, encrypting vault file
// Think of this like your database layer

import (
	"bytes"
	"crypto/rand"
	"encoding/json" // like JSON.parse / JSON.stringify in JS
	"errors"
	"fmt"
	"os"            // file system operations
	"path/filepath" // cross-platform file paths (handles Windows \ vs Unix /)
	"strings"
	"time"

	"github.com/zain-23/local-vault/apps/cli/internal/crypto"
	"github.com/zain-23/local-vault/apps/cli/internal/identity"
)

// ===== DATA STRUCTURES =====
// In Go, structs are like JS objects with fixed shape (like TypeScript interfaces)

// Secret represents one environment variable
// The `json:"..."` tags tell Go how to name fields when converting to/from JSON
// Same as: type Secret = { key: string, value: string, env: string }
type Secret struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	Env       string    `json:"env"`        // "development", "staging", "production"
	UpdatedAt time.Time `json:"updated_at"` // when was this last changed
	UpdatedBy string    `json:"updated_by"` // which device changed it (for sync)
}

// Peer represents a trusted teammate's device
// Stored after successful lv join
type Peer struct {
	DeviceID        string    `json:"device_id"`
	DeviceName      string    `json:"device_name"`
	PublicKey       []byte    `json:"public_key"`        // Ed25519 public key
	X25519PublicKey []byte    `json:"x25519_public_key"` // X25519 public key for encryption
	AddedAt         time.Time `json:"added_at"`
}

type SecretEntry struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	Env       string    `json:"env"`
	UpdatedAt time.Time `json:"updated_at"`
}

// VaultFile is what gets written to disk (encrypted)
// Contains all secrets + metadata
type VaultFile struct {
	Version   string       `json:"version"`   // vault format version
	Salt      []byte       `json:"salt"`      // salt for key derivation
	PassHash  string       `json:"pass_hash"` // hashed passphrase for validation
	Secrets   []Secret     `json:"secrets"`   // all the secrets
	Peers     []Peer       `json:"peers"`     // trusted devices for sync
	DataKey   []byte       `json:"data_key,omitempty"` // shared vault key for snapshot encryption
	AuditLog  []AuditEntry `json:"audit_log"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
}

// AuditEntry records a change made to the vault
// Stored locally — full history of who changed what
type AuditEntry struct {
	Action    string    `json:"action"`    // add, update, remove, rotate
	Key       string    `json:"key"`       // which secret changed
	Env       string    `json:"env"`       // which environment
	DeviceID  string    `json:"device_id"` // who made the change
	Timestamp time.Time `json:"timestamp"`
}

// Vault is the in-memory representation
// After we decrypt + parse VaultFile, we work with this struct
// It holds both the data and the paths/keys needed to save it back
type Vault struct {
	file       VaultFile
	passphrase string // used when loaded with passphrase
	key        []byte // used when loaded with session key
	dir        string
}

// ===== CONSTANTS =====

const (
	lvDir     = ".lv"            // hidden folder name
	vaultFile = "vault.json.enc" // encrypted vault filename
	version   = "1.0.0"
)

// ===== PUBLIC FUNCTIONS =====

// Init creates a new vault in the given directory
// Called by: lv init
// JS equivalent: async function initVault(dir, passphrase)
func Init(dir string, passphrase string) error {
	// Build path to .lv folder
	// filepath.Join handles slashes correctly on all OS
	lvPath := filepath.Join(dir, lvDir)

	// Check if vault already exists
	// os.Stat returns file info or error if not found
	if _, err := os.Stat(lvPath); err == nil {
		return errors.New("vault already exists in this directory")
	}

	// Create .lv directory
	// 0700 = only owner can read/write/execute (Unix permissions)
	// Like: chmod 700 .lv
	if err := os.MkdirAll(lvPath, 0700); err != nil {
		return fmt.Errorf("failed to create vault directory: %w", err)
	}

	// Generate random salt for key derivation
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Generate the shared vault Data Encryption Key (DEK).
	// This single key encrypts the snapshot so a solo owner can push
	// and any future joiner can decrypt — see the design spec.
	dataKey, err := newDataKey()
	if err != nil {
		return err
	}

	// Create empty vault file structure
	vf := VaultFile{
		Version:   version,
		Salt:      salt,
		PassHash:  crypto.HashPassphrase(passphrase),
		Secrets:   []Secret{}, // empty slice (like [] in JS)
		DataKey:   dataKey,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Create vault instance
	v := &Vault{ // & means we're creating a pointer to Vault
		file:       vf,
		passphrase: passphrase,
		dir:        lvPath,
	}

	// Save encrypted vault to disk
	if err := v.save(); err != nil {
		return fmt.Errorf("failed to save vault: %w", err)
	}

	// Generate device identity (keypair)
	// Every machine gets unique ID and Ed25519 keypair
	// This is what makes sync secure between peers
	if _, err := identity.Generate(lvPath); err != nil {
		return fmt.Errorf("failed to generate identity: %w", err)
	}

	// Add .gitignore rules to prevent secrets from being committed
	if err := addGitignoreRules(dir); err != nil {
		// Non-fatal — vault still works, just warn user
		fmt.Println("⚠️  Could not update .gitignore:", err)
	}

	return nil
}

// Load reads and decrypts an existing vault from disk
// Called before every command that needs to read/write secrets
// JS equivalent: async function loadVault(dir, passphrase)
func Load(dir string, passphrase string) (*Vault, error) {
	lvPath := filepath.Join(dir, lvDir)
	vaultPath := filepath.Join(lvPath, vaultFile)

	// Read encrypted file from disk
	encryptedData, err := os.ReadFile(vaultPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("no vault found. run 'lv init' first")
		}
		return nil, fmt.Errorf("failed to read vault: %w", err)
	}

	// Derive encryption key from passphrase
	// We need the salt first — it's stored unencrypted at start of file
	// First 16 bytes are salt (we'll improve this later with a header)
	// For now, decrypt with a temporary approach:
	// Actually we store salt in the JSON so we need to do this in 2 steps

	// Step 1: Try to decrypt with provided passphrase
	// We need the salt — temporarily store it unencrypted as first 16 bytes
	if len(encryptedData) < 16 {
		return nil, errors.New("vault file is corrupted")
	}

	salt := encryptedData[:16]
	actualEncrypted := encryptedData[16:]

	// Derive the key using the stored salt
	key := crypto.DeriveKey(passphrase, salt)

	// Decrypt the vault data
	decryptedData, err := crypto.Decrypt(actualEncrypted, key)
	if err != nil {
		return nil, errors.New("wrong passphrase or corrupted vault")
	}

	// Parse JSON into our VaultFile struct
	// Like: const vaultFile = JSON.parse(decryptedData)
	var vf VaultFile
	if err := json.Unmarshal(decryptedData, &vf); err != nil {
		return nil, fmt.Errorf("failed to parse vault: %w", err)
	}

	// Verify passphrase matches stored hash
	if crypto.HashPassphrase(passphrase) != vf.PassHash {
		return nil, errors.New("wrong passphrase")
	}

	return &Vault{
		file:       vf,
		passphrase: passphrase,
		dir:        lvPath,
	}, nil
}

// LoadWithKey loads vault using raw key bytes
// Used when key is retrieved from session cache
// No passphrase needed — key already derived
func LoadWithKey(dir string, key []byte) (*Vault, error) {
	lvPath := filepath.Join(dir, lvDir)
	vaultPath := filepath.Join(lvPath, vaultFile)

	// Read encrypted file
	encryptedData, err := os.ReadFile(vaultPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("no vault found — run: lv init")
		}
		return nil, fmt.Errorf("failed to read vault: %w", err)
	}

	if len(encryptedData) < 16 {
		return nil, errors.New("vault file corrupted")
	}

	// Extract salt and encrypted data
	salt := encryptedData[:16]
	actualEncrypted := encryptedData[16:]

	// Decrypt using provided key
	decryptedData, err := crypto.Decrypt(actualEncrypted, key)
	if err != nil {
		return nil, errors.New("failed to decrypt vault — session may be invalid")
	}

	// Parse vault file
	var vf VaultFile
	if err := json.Unmarshal(decryptedData, &vf); err != nil {
		return nil, fmt.Errorf("failed to parse vault: %w", err)
	}

	// We need salt for future saves
	// Store it back so save() works correctly
	vf.Salt = salt

	return &Vault{
		file: vf,
		key:  key, // store key directly instead of passphrase
		dir:  lvPath,
	}, nil
}

// Add stores a new secret in the vault
// Called by: lv add KEY=value
func (v *Vault) Add(key, value, env string) error {
	// Check if key already exists — update it if so
	for i, s := range v.file.Secrets {
		if s.Key == key && s.Env == env {
			v.file.Secrets[i].Value = value
			v.file.Secrets[i].UpdatedAt = time.Now()
			v.LogAction("update", key, env, "local") // ← add this
			return v.save()
		}
	}

	// Add new secret
	v.file.Secrets = append(v.file.Secrets, Secret{
		Key:       key,
		Value:     value,
		Env:       env,
		UpdatedAt: time.Now(),
	})
	v.LogAction("add", key, env, "local") // ← add this
	v.file.UpdatedAt = time.Now()
	return v.save()
}

// Get retrieves a single secret by key
// Called by: lv get KEY
func (v *Vault) Get(key, env string) (string, error) {
	for _, s := range v.file.Secrets {
		if s.Key == key && (s.Env == env || env == "") {
			return s.Value, nil
		}
	}
	return "", fmt.Errorf("secret '%s' not found", key)
}

// List returns all secrets for a given environment
// Called by: lv list
func (v *Vault) List(env string) []Secret {
	if env == "" {
		return v.file.Secrets // return all
	}

	// Filter by environment
	// In JS: secrets.filter(s => s.env === env)
	var filtered []Secret
	for _, s := range v.file.Secrets {
		if s.Env == env {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

// Remove deletes a secret from the vault
// Called by: lv remove KEY
func (v *Vault) Remove(key, env string) error {
	found := false
	var remaining []Secret
	for _, s := range v.file.Secrets {
		if s.Key == key && (s.Env == env || env == "") {
			found = true
			continue
		}
		remaining = append(remaining, s)
	}

	if !found {
		return fmt.Errorf("secret '%s' not found", key)
	}

	v.LogAction("remove", key, env, "local") // ← add this
	v.file.Secrets = remaining
	v.file.UpdatedAt = time.Now()
	return v.save()
}

// InjectMap returns secrets as a simple key→value map
// Used by lv inject to export to shell or child process
func (v *Vault) InjectMap(env string) map[string]string {
	result := make(map[string]string) // like {} in JS
	for _, s := range v.file.Secrets {
		if s.Env == env || s.Env == "" || env == "" {
			result[s.Key] = s.Value
		}
	}
	return result
}

// ImportEnvFile reads a .env file and adds all its secrets to vault
// Called by: lv import .env.local
func (v *Vault) ImportEnvFile(path, env string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("failed to read file: %w", err)
	}

	count := 0
	lines := splitLines(string(data))

	for _, line := range lines {
		// Skip comments and empty lines
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		// Parse KEY=VALUE format
		key, value, found := parseEnvLine(line)
		if !found {
			continue
		}

		if err := v.Add(key, value, env); err != nil {
			return count, err
		}
		count++
	}

	return count, nil
}

// ===== PRIVATE FUNCTIONS =====
// In Go, lowercase function names are private to the package
// Like unexported functions in a JS module

// save encrypts and writes vault to disk
func (v *Vault) save() error {
	jsonData, err := json.Marshal(v.file)
	if err != nil {
		return fmt.Errorf("failed to serialize vault: %w", err)
	}

	// Use key directly if available (session mode)
	// Otherwise derive from passphrase (first unlock)
	var key []byte
	if v.key != nil {
		key = v.key
	} else {
		key = crypto.DeriveKey(v.passphrase, v.file.Salt)
	}

	encrypted, err := crypto.Encrypt(jsonData, key)
	if err != nil {
		return fmt.Errorf("failed to encrypt vault: %w", err)
	}

	finalData := append(v.file.Salt, encrypted...)
	vaultPath := filepath.Join(v.dir, vaultFile)
	return os.WriteFile(vaultPath, finalData, 0600)
}

// addGitignoreRules ignores the entire .lv/ directory (like .git).
func addGitignoreRules(dir string) error {
	gitignorePath := filepath.Join(dir, ".gitignore")

	if data, err := os.ReadFile(gitignorePath); err == nil {
		for _, line := range splitLines(string(data)) {
			trimmed := strings.TrimSpace(line)
			if trimmed == ".lv" || trimmed == ".lv/" {
				return nil
			}
		}
	}

	rules := "\n# LocalVault\n.lv/\n"

	f, err := os.OpenFile(gitignorePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(rules)
	return err
}

// splitLines splits text into lines (handles \r\n on Windows)
func splitLines(text string) []string {
	var lines []string
	start := 0
	for i, c := range text {
		if c == '\n' {
			line := text[start:i]
			// Trim \r for Windows line endings
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			lines = append(lines, line)
			start = i + 1
		}
	}
	if start < len(text) {
		lines = append(lines, text[start:])
	}
	return lines
}

// parseEnvLine parses "KEY=VALUE" into separate key and value
// Returns false if line doesn't match expected format
func parseEnvLine(line string) (string, string, bool) {
	for i, c := range line {
		if c == '=' {
			key := line[:i]
			value := line[i+1:]
			// Strip surrounding quotes from value if present
			// Handles: KEY="value" or KEY='value'
			if len(value) >= 2 {
				if (value[0] == '"' && value[len(value)-1] == '"') ||
					(value[0] == '\'' && value[len(value)-1] == '\'') {
					value = value[1 : len(value)-1]
				}
			}
			return key, value, true
		}
	}
	return "", "", false
}

// ErrPeerKeyChanged is returned when an update would replace a known peer's keys
var ErrPeerKeyChanged = errors.New("peer keys changed — refusing to update a trusted peer")

// keyChanged reports whether a stored key would be replaced by a different one
func keyChanged(stored, incoming []byte) bool {
	return len(stored) > 0 && len(incoming) > 0 && !bytes.Equal(stored, incoming)
}

// AddPeer saves a trusted peer to the vault
// Called after successful lv join
func (v *Vault) AddPeer(peer Peer) error {
	// Check if peer already exists
	for i, p := range v.file.Peers {
		if p.DeviceID == peer.DeviceID {
			// Keys of a known peer are pinned — a change must never be applied silently
			if keyChanged(p.PublicKey, peer.PublicKey) || keyChanged(p.X25519PublicKey, peer.X25519PublicKey) {
				return ErrPeerKeyChanged
			}
			v.file.Peers[i].DeviceName = peer.DeviceName
			if len(p.PublicKey) == 0 {
				v.file.Peers[i].PublicKey = peer.PublicKey
			}
			if len(p.X25519PublicKey) == 0 {
				v.file.Peers[i].X25519PublicKey = peer.X25519PublicKey
			}
			return v.save()
		}
	}

	// Add new peer
	v.file.Peers = append(v.file.Peers, peer)
	return v.save()
}

// GetPeers returns all trusted peers
func (v *Vault) GetPeers() []Peer {
	return v.file.Peers
}

// GetSecretEntries returns secrets in sync-friendly format
// Used when sending vault to a new peer
// GetSecretEntries returns all secrets in transfer format
// Called by lv push to prepare secrets for sending to peers
func (v *Vault) GetSecretEntries() []SecretEntry {
	entries := make([]SecretEntry, len(v.file.Secrets))
	for i, s := range v.file.Secrets {
		entries[i] = SecretEntry{
			Key:       s.Key,
			Value:     s.Value,
			Env:       s.Env,
			UpdatedAt: s.UpdatedAt,
		}
	}
	return entries
}

// MergeSecrets adds secrets received from peer
// Newer timestamp wins on conflict
// MergeSecrets merges secrets received from peer into vault
// Newer timestamp wins on conflict
// Takes []SecretEntry not []sync.SecretEntry to avoid circular imports
func (v *Vault) MergeSecrets(entries []SecretEntry) (int, error) {
	updated := 0

	for _, entry := range entries {
		found := false
		for i, existing := range v.file.Secrets {
			if existing.Key == entry.Key && existing.Env == entry.Env {
				found = true
				if entry.UpdatedAt.After(existing.UpdatedAt) {
					v.file.Secrets[i].Value = entry.Value
					v.file.Secrets[i].UpdatedAt = entry.UpdatedAt
					updated++
				}
				break
			}
		}
		if !found {
			v.file.Secrets = append(v.file.Secrets, Secret{
				Key:       entry.Key,
				Value:     entry.Value,
				Env:       entry.Env,
				UpdatedAt: entry.UpdatedAt,
			})
			updated++
		}
	}

	if updated > 0 {
		v.file.UpdatedAt = time.Now()
		return updated, v.save()
	}

	return 0, nil
}

func (v *Vault) GetPeer(deviceID string) (Peer, bool) {
	for _, p := range v.file.Peers {
		if p.DeviceID == deviceID {
			return p, true
		}
	}
	return Peer{}, false
}

// LogAction records an action in the audit log
// Called internally by Add, Remove, rotate
func (v *Vault) LogAction(action, key, env, deviceID string) {
	entry := AuditEntry{
		Action:    action,
		Key:       key,
		Env:       env,
		DeviceID:  deviceID,
		Timestamp: time.Now(),
	}
	// Keep last 100 entries only
	// Prevents log from growing forever
	v.file.AuditLog = append(v.file.AuditLog, entry)
	if len(v.file.AuditLog) > 100 {
		v.file.AuditLog = v.file.AuditLog[len(v.file.AuditLog)-100:]
	}
}

// GetAuditLog returns audit log entries
// Newest first
func (v *Vault) GetAuditLog() []AuditEntry {
	log := make([]AuditEntry, len(v.file.AuditLog))
	copy(log, v.file.AuditLog)

	// Reverse so newest is first
	// Like: log.reverse() in JS
	for i, j := 0, len(log)-1; i < j; i, j = i+1, j-1 {
		log[i], log[j] = log[j], log[i]
	}
	return log
}

// GetKey returns the derived encryption key
// Called after Load() to save key to session cache
func (v *Vault) GetKey() []byte {
	if v.key != nil {
		return v.key
	}
	// Derive from passphrase if key not set
	return crypto.DeriveKey(v.passphrase, v.file.Salt)
}

// newDataKey returns 32 fresh random bytes for the vault DEK.
func newDataKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate vault data key: %w", err)
	}
	return key, nil
}

// GetDataKey returns the shared vault Data Encryption Key.
// May be empty for vaults created before this key existed — callers
// that need it should use EnsureDataKey instead.
func (v *Vault) GetDataKey() []byte {
	return v.file.DataKey
}

// SetDataKey stores a DEK (e.g. one unwrapped from a join token) and
// persists it inside the passphrase-encrypted vault file.
func (v *Vault) SetDataKey(key []byte) error {
	v.file.DataKey = key
	return v.save()
}

// EnsureDataKey returns the vault DEK, generating and persisting one if
// the vault predates the shared-key feature (transparent migration).
func (v *Vault) EnsureDataKey() ([]byte, error) {
	if len(v.file.DataKey) > 0 {
		return v.file.DataKey, nil
	}
	key, err := newDataKey()
	if err != nil {
		return nil, err
	}
	if err := v.SetDataKey(key); err != nil {
		return nil, err
	}
	return key, nil
}

// RemovePeer removes a trusted peer from the vault
func (v *Vault) RemovePeer(deviceID string) error {
	found := false
	var remaining []Peer

	for _, p := range v.file.Peers {
		if p.DeviceID == deviceID {
			found = true
			continue
		}
		remaining = append(remaining, p)
	}

	if !found {
		return fmt.Errorf("peer not found: %s", deviceID)
	}

	v.file.Peers = remaining
	v.file.UpdatedAt = time.Now()
	v.LogAction("revoke", deviceID, "", "local")
	return v.save()
}
