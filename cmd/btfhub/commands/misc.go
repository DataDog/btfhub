package commands

import (
	"fmt"
	"os"
	"path"
	"slices"
	"strings"
)

func processArgs(defDistros []string, defReleases map[string][]string) (distros []string, releases map[string][]string, archs []string, err error) {
	releases = make(map[string][]string)
	var rels []string
	if releaseArg != "" {
		rels = strings.Split(releaseArg, " ")
	}
	if distroArg != "" {
		distros = strings.Split(distroArg, " ")
		for _, d := range distros {
			if _, ok := distroReleases[d]; !ok {
				err = fmt.Errorf("invalid distribution %s", d)
				return
			}

			for _, r := range rels {
				if slices.Contains(distroReleases[d], r) {
					releases[d] = append(releases[d], r)
				}
			}
			if len(rels) == 0 {
				releases[d] = defReleases[d]
			}
		}
	} else {
		distros = defDistros
		releaseArg = "" // no release if no distro is selected
	}

	// Architectures
	archs = possibleArchs
	if archArg != "" {
		archs = []string{archArg}
	}
	return
}

func archivePath() (string, error) {
	basedir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("pwd: %s", err)
	}
	archiveDir := path.Join(basedir, "archive")
	return archiveDir, nil
}
