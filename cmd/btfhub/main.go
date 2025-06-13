package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"

	"github.com/DataDog/btfhub/cmd/btfhub/commands"
)

func main() {
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := run(ctx); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	if fa := flag.Args(); len(fa) > 0 {
		switch fa[0] {
		case "check":
			return commands.Check(ctx)
		case "upload":
			return commands.Upload(ctx)
		case "catalog-update":
			return commands.CatalogUpdate(ctx)
		default:
			log.Fatalf("unknown command %s", fa[0])
		}
	}
	return commands.Generate(ctx)
}
