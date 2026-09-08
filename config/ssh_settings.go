package config

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// LoadSSHSettings inspects only SSH-owned settings without requiring a configured
// project/platform or resolving unrelated provider credentials. Environment
// placeholders use the same resolver as the daemon configuration.
func LoadSSHSettings(path string) (string, SSHConfig, error) {
	var fields struct {
		DataDir string    `toml:"data_dir"`
		SSH     SSHConfig `toml:"ssh"`
	}
	invalid := func() (string, SSHConfig, error) {
		return "", SSHConfig{}, errors.New("ssh: cannot load configuration")
	}
	f, err := os.Open(path)
	if err != nil {
		return invalid()
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	if err != nil || len(data) > 4<<20 {
		return invalid()
	}
	meta, err := toml.Decode(string(data), &fields)
	if err != nil {
		return invalid()
	}
	for _, key := range meta.Undecoded() {
		if len(key) > 0 && key[0] == "ssh" {
			return "", SSHConfig{}, errors.New("ssh: unknown configuration field")
		}
	}
	cfg := &Config{DataDir: fields.DataDir, SSH: fields.SSH}
	resolveEnvInConfig(cfg)
	if cfg.DataDir == "" {
		cfg.DataDir = defaultDataDir()
	}
	if strings.HasPrefix(cfg.DataDir, "~/") || cfg.DataDir == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return invalid()
		}
		cfg.DataDir = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(cfg.DataDir, "~"), "/"))
	}
	return cfg.DataDir, cfg.SSH, nil
}
