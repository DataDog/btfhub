package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// BTFCatalog is the entire catalog
type BTFCatalog struct {
	X64   BTFArchCatalog `json:"x86_64"`
	Arm64 BTFArchCatalog `json:"arm64"`
}

// BTFArchCatalog is keyed by distro name
type BTFArchCatalog map[string]BTFDistroCatalog

// BTFDistroCatalog is keyed by release
type BTFDistroCatalog map[string]BTFReleaseCatalog

// BTFReleaseCatalog is keyed by kernel version
type BTFReleaseCatalog map[string]BTFEntry

// BTFEntry is a single entry in the catalog
type BTFEntry struct {
	SHA256 string `json:"sha256"`
}

// Read reads a BTFCatalog from the file
func Read(catalogPath string) (*BTFCatalog, error) {
	catalog := &BTFCatalog{}
	catalogData, err := os.ReadFile(catalogPath)
	if err != nil {
		return nil, fmt.Errorf("read catalog json: %s", err)
	}
	if err := json.Unmarshal(catalogData, catalog); err != nil {
		return nil, fmt.Errorf("unmarshal catalog json: %s", err)
	}
	return catalog, nil
}

func Update(ctx context.Context, hashDir string, catalogJSONPath string) error {
	if hashDir == "" {
		return fmt.Errorf("--hash-dir must be set")
	}
	if _, err := os.Stat(hashDir); err != nil && os.IsNotExist(err) {
		// fast return if there are no new hashes
		return nil
	}
	if catalogJSONPath == "" {
		return fmt.Errorf("--catalog-json must be set")
	}

	catalog, err := Read(catalogJSONPath)
	if err != nil {
		return err
	}

	err = updateCatalog(ctx, os.DirFS(hashDir), catalog)
	if err != nil {
		return fmt.Errorf("update catalog: %s", err)
	}

	catalogData, err := json.MarshalIndent(catalog, "", "    ")
	if err != nil {
		return fmt.Errorf("marshal catalog: %s", err)
	}
	if err := os.WriteFile(catalogJSONPath, catalogData, 0644); err != nil {
		return fmt.Errorf("write catalog json: %s", err)
	}
	return nil
}

const sha256HexLen = sha256.Size * 2

func updateCatalog(ctx context.Context, hashFS fs.FS, catalog *BTFCatalog) error {
	// walk hash directory and collect hashes
	return fs.WalkDir(hashFS, ".", func(walkPath string, info fs.DirEntry, walkErr error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}

		data, err := fs.ReadFile(hashFS, walkPath)
		if err != nil {
			return fmt.Errorf("read file %s: %w", walkPath, err)
		}
		if len(data) != sha256HexLen {
			// ignore files without valid SHA256 hashes
			return nil
		}
		return catalog.addHash(walkPath, string(data))
	})
}

func (catalog *BTFCatalog) GetHash(arch, distro, release, version string) string {
	releaseCatalog := catalog.getReleaseCatalog(arch, distro, release)
	if releaseCatalog == nil {
		return ""
	}
	return releaseCatalog[version].SHA256
}

func (catalog *BTFCatalog) addHash(entryPath string, hash string) error {
	parts := strings.Split(entryPath, string(filepath.Separator))
	if len(parts) != 4 {
		// ignore files that don't match the layout
		return nil
	}

	arch, distro, release, version := parts[0], parts[1], parts[2], parts[3]
	releaseCatalog := catalog.getReleaseCatalog(arch, distro, release)
	if releaseCatalog == nil {
		return nil
	}
	// add new entry, or compare hashes if entry already exists
	if v, ok := releaseCatalog[version]; ok {
		if v.SHA256 != hash {
			return fmt.Errorf("hash mismatch for %s (expected %s, got %s)", entryPath, hash, v.SHA256)
		}
	} else {
		releaseCatalog[version] = BTFEntry{
			SHA256: hash,
		}
	}
	return nil
}

func (catalog *BTFCatalog) getReleaseCatalog(arch, distro, release string) BTFReleaseCatalog {
	// access entry in catalog, creating new maps as necessary
	var archCatalog BTFArchCatalog
	switch arch {
	case "x86_64":
		if catalog.X64 == nil {
			catalog.X64 = BTFArchCatalog{}
		}
		archCatalog = catalog.X64
	case "arm64":
		if catalog.Arm64 == nil {
			catalog.Arm64 = BTFArchCatalog{}
		}
		archCatalog = catalog.Arm64
	default:
		// ignore files that don't match the layout
		return nil
	}
	distroCatalog, ok := archCatalog[distro]
	if !ok {
		distroCatalog = BTFDistroCatalog{}
		archCatalog[distro] = distroCatalog
	}
	releaseCatalog, ok := distroCatalog[release]
	if !ok {
		releaseCatalog = BTFReleaseCatalog{}
		distroCatalog[release] = releaseCatalog
	}

	return releaseCatalog
}
