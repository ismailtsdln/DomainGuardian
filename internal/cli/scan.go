package cli

import (
	"bufio"
	"fmt"
	"os"
	"time"

	"github.com/ismailtsdln/DomainGuardian/internal/engine"
	"github.com/ismailtsdln/DomainGuardian/internal/fingerprints"
	"github.com/ismailtsdln/DomainGuardian/internal/models"
	"github.com/ismailtsdln/DomainGuardian/internal/output"
	"github.com/ismailtsdln/DomainGuardian/internal/validation"
	"github.com/spf13/cobra"
)

var (
	inputFile string
	domain    string
	threads   int
	timeout   int
	format    string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan subdomains for takeover vulnerabilities",
	Run: func(cmd *cobra.Command, args []string) {
		var subdomains []string

		if domain != "" {
			subdomains = append(subdomains, domain)
		} else if inputFile != "" {
			file, err := os.Open(inputFile)
			if err != nil {
				fmt.Printf("Error opening file: %v\n", err)
				return
			}
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				subdomains = append(subdomains, scanner.Text())
			}
		} else {
			fmt.Println("Error: either -d or -i must be specified")
			return
		}

		// Initialize components
		fe := fingerprints.NewEngine()
		// In a real scenario, this would be a path to a config file
		err := fe.LoadFromYAML("internal/fingerprints/data/fingerprints.yaml")
		if err != nil {
			fmt.Printf("Error loading fingerprints: %v\n", err)
			return
		}

		v := validation.NewValidator(fe)
		s := engine.NewScanner(threads, time.Duration(timeout)*time.Second, v)

		fmt.Printf("[*] Starting scan on %d subdomains...\n", len(subdomains))

		resultsChan := s.Scan(subdomains)
		var results []models.Result
		for res := range resultsChan {
			results = append(results, res)
		}

		// Format output
		var formatter output.Formatter
		switch format {
		case "json":
			formatter = &output.JSONFormatter{}
		case "md":
			formatter = &output.MarkdownFormatter{}
		default:
			formatter = &output.TableFormatter{}
		}

		err = formatter.Format(results)
		if err != nil {
			fmt.Printf("Error formatting output: %v\n", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input file containing subdomains")
	scanCmd.Flags().StringVarP(&domain, "domain", "d", "", "Single domain to scan")
	scanCmd.Flags().IntVarP(&threads, "threads", "t", 10, "Number of concurrent threads")
	scanCmd.Flags().IntVarP(&timeout, "timeout", "", 10, "Timeout in seconds")
	scanCmd.Flags().StringVarP(&format, "format", "f", "table", "Output format (table, json, md)")
}
