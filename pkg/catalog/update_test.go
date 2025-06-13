package catalog

import (
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testHash1 = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff0000000011111111"
	testHash2 = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff1111111122222222"
)

func TestWalkNoHashes(t *testing.T) {
	catalog := &btfCatalog{}
	hashFS := fstest.MapFS{}
	err := updateCatalog(t.Context(), hashFS, catalog)
	require.NoError(t, err)
	assert.Empty(t, catalog.X64)
	assert.Empty(t, catalog.Arm64)
}

func TestWalkHashConflict(t *testing.T) {
	catalog := &btfCatalog{
		X64: map[string]btfDistroCatalog{"amzn": {"2": btfReleaseCatalog{"4.14.355-276.639.amzn2.x86_64": btfEntry{SHA256: testHash1}}}},
	}
	hashFS := fstest.MapFS{
		"x86_64/amzn/2/4.14.355-276.639.amzn2.x86_64": &fstest.MapFile{Data: []byte(testHash2)},
	}
	err := updateCatalog(t.Context(), hashFS, catalog)
	require.Error(t, err)
}

func TestWalkAddEntry(t *testing.T) {
	catalog := &btfCatalog{
		X64: map[string]btfDistroCatalog{"amzn": {"2": btfReleaseCatalog{"4.14.355-276.639.amzn2.x86_64": btfEntry{SHA256: testHash1}}}},
	}
	hashFS := fstest.MapFS{
		"x86_64/amzn/2/4.14.355-277.647.amzn2.x86_64": &fstest.MapFile{Data: []byte(testHash2)},
	}
	err := updateCatalog(t.Context(), hashFS, catalog)
	require.NoError(t, err)

	entry, ok := catalog.X64["amzn"]["2"]["4.14.355-277.647.amzn2.x86_64"]
	require.True(t, ok, "new entry should exist")
	assert.Equal(t, entry.SHA256, testHash2)

	entry, ok = catalog.X64["amzn"]["2"]["4.14.355-276.639.amzn2.x86_64"]
	require.True(t, ok, "old entry should exist")
	assert.Equal(t, entry.SHA256, testHash1)
}

func TestWalkNewDistro(t *testing.T) {
	catalog := &btfCatalog{
		X64: map[string]btfDistroCatalog{"amzn": {"2": btfReleaseCatalog{"4.14.355-276.639.amzn2.x86_64": btfEntry{SHA256: testHash1}}}},
	}
	hashFS := fstest.MapFS{
		"x86_64/ubuntu/20.04/5.4.0-1097-aws": &fstest.MapFile{Data: []byte(testHash2)},
	}
	err := updateCatalog(t.Context(), hashFS, catalog)
	require.NoError(t, err)

	entry, ok := catalog.X64["ubuntu"]["20.04"]["5.4.0-1097-aws"]
	require.True(t, ok, "new entry should exist")
	assert.Equal(t, entry.SHA256, testHash2)

	entry, ok = catalog.X64["amzn"]["2"]["4.14.355-276.639.amzn2.x86_64"]
	require.True(t, ok, "old entry should exist")
	assert.Equal(t, entry.SHA256, testHash1)
}

func TestWalkNewRelease(t *testing.T) {
	catalog := &btfCatalog{
		X64: map[string]btfDistroCatalog{"amzn": {"2": btfReleaseCatalog{"4.14.355-276.639.amzn2.x86_64": btfEntry{SHA256: testHash1}}}},
	}
	hashFS := fstest.MapFS{
		"x86_64/amzn/2018/4.14.355-196.647.amzn1.x86_64": &fstest.MapFile{Data: []byte(testHash2)},
	}
	err := updateCatalog(t.Context(), hashFS, catalog)
	require.NoError(t, err)

	entry, ok := catalog.X64["amzn"]["2018"]["4.14.355-196.647.amzn1.x86_64"]
	require.True(t, ok, "new entry should exist")
	assert.Equal(t, entry.SHA256, testHash2)

	entry, ok = catalog.X64["amzn"]["2"]["4.14.355-276.639.amzn2.x86_64"]
	require.True(t, ok, "old entry should exist")
	assert.Equal(t, entry.SHA256, testHash1)
}

func TestWalkNewArch(t *testing.T) {
	catalog := &btfCatalog{
		X64: map[string]btfDistroCatalog{"amzn": {"2": btfReleaseCatalog{"4.14.355-276.639.amzn2.x86_64": btfEntry{SHA256: testHash1}}}},
	}
	hashFS := fstest.MapFS{
		"arm64/amzn/2/4.14.355-277.647.amzn2.aarch64": &fstest.MapFile{Data: []byte(testHash2)},
	}
	err := updateCatalog(t.Context(), hashFS, catalog)
	require.NoError(t, err)

	entry, ok := catalog.Arm64["amzn"]["2"]["4.14.355-277.647.amzn2.aarch64"]
	require.True(t, ok, "new entry should exist")
	assert.Equal(t, entry.SHA256, testHash2)

	entry, ok = catalog.X64["amzn"]["2"]["4.14.355-276.639.amzn2.x86_64"]
	require.True(t, ok, "old entry should exist")
	assert.Equal(t, entry.SHA256, testHash1)
}

func TestWalkIgnoreFiles(t *testing.T) {
	catalog := &btfCatalog{
		X64: map[string]btfDistroCatalog{"amzn": {"2": btfReleaseCatalog{"4.14.355-276.639.amzn2.x86_64": btfEntry{SHA256: testHash1}}}},
	}
	hashFS := fstest.MapFS{
		"x86_64/amzn/2018/4.14.355-196.647.amzn1.x86_64": &fstest.MapFile{Data: []byte(testHash2)},
		".DS_Store":                  &fstest.MapFile{},
		"badarch/.gitignore":         &fstest.MapFile{},
		"x86_64/amzn/no_release_dir": &fstest.MapFile{},
		"x86_64/amzn/2018/badhash":   &fstest.MapFile{Data: []byte("asdf")},
	}
	err := updateCatalog(t.Context(), hashFS, catalog)
	require.NoError(t, err)

	entry, ok := catalog.X64["amzn"]["2018"]["4.14.355-196.647.amzn1.x86_64"]
	require.True(t, ok, "new entry should exist")
	assert.Equal(t, entry.SHA256, testHash2)

	entry, ok = catalog.X64["amzn"]["2"]["4.14.355-276.639.amzn2.x86_64"]
	require.True(t, ok, "old entry should exist")
	assert.Equal(t, entry.SHA256, testHash1)

	_, ok = catalog.X64["amzn"]["2018"]["badhash"]
	assert.False(t, ok, "badhash entry should not exist")
}

var testIndentContent = []byte(`{
    "x86_64": {
        "amzn": {
            "2": {
                "4.14.355-276.639.amzn2.x86_64": {
                    "sha256": "3d9ada50ed6b72ea53c52b7655d9ce4a0dba76a012f3430c416dfc51c5dff6bb"
                }
            }
        }
    },
    "arm64": {
        "amzn": {
            "2": {
                "4.14.355-276.639.amzn2.aarch64": {
                    "sha256": "539258e1f0a90c7376e860c0f1cdc28351bb44c5441b0e1df9d3533d689daa35"
                }
            }
        }
    }
}`)

func TestJSONIndent(t *testing.T) {
	catalogPath := filepath.Join(t.TempDir(), "catalog.json")
	err := os.WriteFile(catalogPath, testIndentContent, 0644)
	require.NoError(t, err)
	oldStat, err := os.Stat(catalogPath)
	require.NoError(t, err)

	err = Update(t.Context(), t.TempDir(), catalogPath)
	require.NoError(t, err)
	newStat, err := os.Stat(catalogPath)
	require.NoError(t, err)

	newCatalogData, err := os.ReadFile(catalogPath)
	require.Equal(t, testIndentContent, newCatalogData)
	require.NotEqual(t, oldStat.ModTime(), newStat.ModTime())
}
