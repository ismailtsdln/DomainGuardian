package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "domainguardian",
	Short: "DomainGuardian is a high-accuracy subdomain takeover detection tool",
	Long: `DomainGuardian is a next-generation subdomain takeover detection platform 
designed to be fast, accurate, modular, and low-false-positive.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// Root flags if any
}
