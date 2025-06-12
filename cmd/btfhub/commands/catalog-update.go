package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type btfCatalog struct {
	X64   btfArchCatalog `json:"x86_64"`
	Arm64 btfArchCatalog `json:"arm64"`
}

// keyed by distro name
type btfArchCatalog map[string]btfDistroCatalog

// keyed by release
type btfDistroCatalog map[string]btfReleaseCatalog

// keyed by kernel version
type btfReleaseCatalog map[string]btfEntry

type btfEntry struct {
	SHA256 string `json:"sha256"`
}

func CatalogUpdate(ctx context.Context) error {
	if hashDir == "" {
		return fmt.Errorf("--hash-dir must be set")
	}
	if catalogJSONPath == "" {
		return fmt.Errorf("--catalog-json must be set")
	}

	var catalog btfCatalog
	catalogData, err := os.ReadFile(catalogJSONPath)
	if err != nil {
		return fmt.Errorf("read catalog json: %s", err)
	}
	if err := json.Unmarshal(catalogData, &catalog); err != nil {
		return fmt.Errorf("unmarshal catalog json: %s", err)
	}

	// walk hash directory and collect hashes
	err = filepath.Walk(hashDir, func(walkPath string, info fs.FileInfo, walkErr error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if walkErr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "walk error: %s\n", walkErr)
			return nil
		}
		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(hashDir, walkPath)
		if err != nil {
			return fmt.Errorf("relative path: %s", err)
		}
		data, err := os.ReadFile(walkPath)
		if err != nil {
			return fmt.Errorf("read file %s: %w", walkPath, err)
		}

		return catalog.addHash(relPath, string(data))
	})
	if err != nil {
		return err
	}

	catalogData, err = json.Marshal(catalog)
	if err != nil {
		return fmt.Errorf("marshal catalog: %s", err)
	}
	if err := os.WriteFile(catalogJSONPath, catalogData, 0644); err != nil {
		return fmt.Errorf("write catalog json: %s", err)
	}
	return nil
}

func (catalog *btfCatalog) addHash(entryPath string, hash string) error {
	parts := strings.Split(entryPath, string(filepath.Separator))
	if len(parts) < 4 {
		return fmt.Errorf("invalid hash path: %s", entryPath)
	}

	// access entry in catalog, creating new maps as necessary
	arch, distro, release, version := parts[0], parts[1], parts[2], parts[3]
	var archCatalog btfArchCatalog
	switch arch {
	case "x86_64":
		archCatalog = catalog.X64
	case "arm64":
		archCatalog = catalog.Arm64
	}
	distroCatalog, ok := archCatalog[distro]
	if !ok {
		distroCatalog = btfDistroCatalog{}
		archCatalog[distro] = distroCatalog
	}
	releaseCatalog, ok := distroCatalog[release]
	if !ok {
		releaseCatalog = btfReleaseCatalog{}
		distroCatalog[release] = releaseCatalog
	}

	// add new entry, or compare hashes if entry already exists
	if v, ok := releaseCatalog[version]; ok {
		if v.SHA256 != hash {
			return fmt.Errorf("hash mismatch for %s (expected %s, got %s)", entryPath, hash, v.SHA256)
		}
	} else {
		releaseCatalog[version] = btfEntry{
			SHA256: hash,
		}
	}
	return nil
}
