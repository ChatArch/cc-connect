package config

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/chenhg5/cc-connect/core"
	"gopkg.in/yaml.v3"
)

// SSHConfig selects an explicit registry and optional inline targets. Neither
// the registry loader nor core implicitly imports Hermes or OpenSSH config.
type SSHConfig struct {
	Registry string           `toml:"registry"`
	Targets  []core.SSHTarget `toml:"targets"`
}

// LoadSSHTargets merges the registry with inline targets and returns validated,
// sorted, independent copies. Only a missing default registry is optional.
// Registry/validation failures never include private paths or input values.
func LoadSSHTargets(dataDir string, cfg SSHConfig) ([]core.SSHTarget, error) {
	path := cfg.Registry
	if path == "" {
		path = filepath.Join(dataDir, "ssh", "targets.yaml")
	} else if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, errors.New("ssh: cannot resolve registry home directory")
		}
		path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
		if cfg.Registry == "~" {
			path = home
		}
	}
	data, err := os.ReadFile(path)
	var targets []core.SSHTarget
	if err != nil {
		if cfg.Registry != "" || !os.IsNotExist(err) {
			return nil, errors.New("ssh: cannot read target registry")
		}
	} else {
		targets, err = parseSSHTargetRegistry(data)
		if err != nil {
			return nil, err
		}
	}
	targets = append(targets, cfg.Targets...)
	// The in-memory store is the canonical validator, duplicate detector and
	// copy/default/sort implementation. Empty path performs no state-file I/O.
	mode, err := core.NewSSHMode("", targets)
	if err != nil {
		return nil, err
	}
	return mode.Targets(), nil
}

var errSSHRegistry = errors.New("ssh: invalid target registry schema or values")

func parseSSHTargetRegistry(data []byte) ([]core.SSHTarget, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := dec.Decode(&document); err != nil || len(document.Content) != 1 {
		return nil, errSSHRegistry
	}
	if err := dec.Decode(new(yaml.Node)); err != io.EOF {
		return nil, errSSHRegistry
	}
	root, err := sshYAMLMapping(document.Content[0])
	if err != nil {
		return nil, err
	}
	node := root["targets"]
	if ssh := root["ssh"]; ssh != nil {
		nested, err := sshYAMLMapping(ssh)
		if err != nil {
			return nil, err
		}
		if nested["targets"] != nil {
			if node != nil {
				return nil, errSSHRegistry
			}
			node = nested["targets"]
		}
	}
	if node == nil {
		return nil, errSSHRegistry
	}
	var targets []core.SSHTarget
	switch node.Kind {
	case yaml.MappingNode:
		mapping, err := sshYAMLMapping(node)
		if err != nil {
			return nil, err
		}
		for alias, entry := range mapping {
			if alias == "" {
				return nil, errSSHRegistry
			}
			target, err := decodeSSHTarget(entry, alias)
			if err != nil {
				return nil, err
			}
			targets = append(targets, target)
		}
	case yaml.SequenceNode:
		if node.Tag != "!!seq" {
			return nil, errSSHRegistry
		}
		for _, entry := range node.Content {
			target, err := decodeSSHTarget(entry, "")
			if err != nil {
				return nil, err
			}
			targets = append(targets, target)
		}
	default:
		return nil, errSSHRegistry
	}
	return targets, nil
}

// Require string keys and reject duplicates before decoding: YAML decoding
// must never silently overwrite a target, alias, or security-related field.
func sshYAMLMapping(node *yaml.Node) (map[string]*yaml.Node, error) {
	if node.Kind != yaml.MappingNode || node.Tag != "!!map" {
		return nil, errSSHRegistry
	}
	fields := make(map[string]*yaml.Node, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return nil, errSSHRegistry
		}
		if _, duplicate := fields[key.Value]; duplicate {
			return nil, errSSHRegistry
		}
		fields[key.Value] = node.Content[i+1]
	}
	return fields, nil
}

func decodeSSHTarget(node *yaml.Node, alias string) (core.SSHTarget, error) {
	fields, err := sshYAMLMapping(node)
	if err != nil {
		return core.SSHTarget{}, err
	}
	for name, field := range fields {
		tag := "!!str"
		switch name {
		case "alias", "host", "user", "identity_file", "known_hosts", "host_key_policy", "cwd", "worker_command":
		case "port":
			tag = "!!int"
		case "identities_only":
			tag = "!!bool"
		case "agent_options":
			options, err := sshYAMLMapping(field)
			if err != nil {
				return core.SSHTarget{}, err
			}
			for _, value := range options {
				if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
					return core.SSHTarget{}, errSSHRegistry
				}
			}
			continue
		default:
			return core.SSHTarget{}, errSSHRegistry
		}
		if field.Kind != yaml.ScalarNode || field.Tag != tag {
			return core.SSHTarget{}, errSSHRegistry
		}
	}
	var target core.SSHTarget
	if err := node.Decode(&target); err != nil {
		return core.SSHTarget{}, errSSHRegistry
	}
	if alias != "" {
		if explicit := fields["alias"]; explicit != nil && target.Alias != alias {
			return core.SSHTarget{}, errSSHRegistry
		}
		target.Alias = alias
	}
	return target, nil
}
