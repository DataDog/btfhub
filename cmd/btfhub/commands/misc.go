package commands

import (
	"fmt"
	"os"
	"path"
	"strings"
)

func processArgs(defDistros []string, defReleases map[string][]string) (distros, releases, archs []string, err error) {
	if distroArg != "" {
		distros = strings.Split(distroArg, " ")
		for i, d := range distros {
			if _, ok := distroReleases[d]; !ok {
				err = fmt.Errorf("invalid distribution %s", d)
				return
			}
			if releaseArg != "" {
				releases = strings.Split(releaseArg, " ")
				found := false
				for _, r := range distroReleases[d] {
					found = r == releases[i]
					if found {
						break
					}
				}
				if !found {
					err = fmt.Errorf("invalid release %s for %s", releases[i], d)
					return
				}
			} else {
				releases = defReleases[d]
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
