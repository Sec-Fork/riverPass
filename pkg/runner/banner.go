package runner

import (
	"github.com/projectdiscovery/gologger"
	folderutil "github.com/projectdiscovery/utils/folder"
	"os"
	"path/filepath"
)

const (
	banner = `
         _                                            
   _____(_)   _____  _____      ____  ____ ___________
  / ___/ / | / / _ \/ ___/_____/ __ \/ __ / ___/ ___/
 / /  / /| |/ /  __/ /  /_____/ /_/ / /_/ (__  |__  )
/_/  /_/ |___/\___/_/        / .___/\__,_/____/____/
/_/
`
	Version  = "1.0.2"
	repoName = "riverPass"
	user     = "wjlin0"
)

var (
	DefaultRiverPassDir = filepath.Join(folderutil.HomeDirOrDefault("."), ".config", "riverPass")
	DefaultConfig       = filepath.Join(DefaultRiverPassDir, "config.yaml")
)

func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\t\twjlin0.com\n\n")
	gologger.Print().Msgf("慎用。你要为自己的行为负责\n")
	gologger.Print().Msgf("开发者不承担任何责任，也不对任何误用或损坏负责.\n")
}
func getVersionFromCallback() func() {
	return func() {
		showBanner()
		gologger.Info().Msgf("RiverPass Engine Version: v%s", Version)
		gologger.Info().Msgf("RiverPass Config Directory: %s", DefaultConfig)
		os.Exit(0)
	}
}
