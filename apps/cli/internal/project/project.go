package project

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type File struct {
	Workspace  string
	Vault      string
	DefaultEnv string
	Dir        string
}

func Find(start string) (*File, error) {
	dir := start
	for {
		p := filepath.Join(dir, ".lv.toml")
		if _, err := os.Stat(p); err == nil {
			return Load(p)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil, errors.New("no .lv.toml — run: lv init or lv link")
		}
		dir = parent
	}
}

func Load(path string) (*File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := &File{DefaultEnv: "development", Dir: filepath.Dir(path)}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"`)
		switch k {
		case "workspace":
			out.Workspace = v
		case "vault":
			out.Vault = v
		case "default_env":
			out.DefaultEnv = v
		}
	}
	if out.Vault == "" {
		return nil, errors.New(".lv.toml is missing vault")
	}
	return out, sc.Err()
}

func Write(dir, workspace, vault, defaultEnv string) error {
	if defaultEnv == "" {
		defaultEnv = "development"
	}
	body := "# LocalVault project link (safe to commit)\n" +
		"workspace = \"" + workspace + "\"\n" +
		"vault = \"" + vault + "\"\n" +
		"default_env = \"" + defaultEnv + "\"\n"
	return os.WriteFile(filepath.Join(dir, ".lv.toml"), []byte(body), 0644)
}

func EnvOr(flag string, f *File) string {
	if flag != "" {
		return flag
	}
	if v := os.Getenv("LV_ENV"); v != "" {
		return v
	}
	if f != nil && f.DefaultEnv != "" {
		return f.DefaultEnv
	}
	return "development"
}
