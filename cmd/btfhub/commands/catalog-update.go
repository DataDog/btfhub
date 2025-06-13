package commands

import (
	"context"

	"github.com/DataDog/btfhub/pkg/catalog"
)

func CatalogUpdate(ctx context.Context) error {
	return catalog.Update(ctx, hashDir, catalogJSONPath)
}
