package output

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ismailtsdln/DomainGuardian/internal/models"
	"github.com/olekukonko/tablewriter"
)

// Formatter defines the interface for output formatters
type Formatter interface {
	Format(results []models.Result) error
}

// TableFormatter prints results in a table format
type TableFormatter struct{}

func (f *TableFormatter) Format(results []models.Result) error {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Subdomain", "Provider", "Confidence", "Takeover"})
	table.SetBorder(false)
	table.SetAutoWrapText(false)

	for _, r := range results {
		takeover := "No"
		if r.TakeoverPossible {
			takeover = "YES"
		}
		table.Append([]string{
			r.Subdomain,
			r.Provider,
			string(r.Confidence),
			takeover,
		})
	}
	table.Render()
	return nil
}

// JSONFormatter prints results in JSON format
type JSONFormatter struct{}

func (f *JSONFormatter) Format(results []models.Result) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

// MarkdownFormatter prints results in Markdown table format
type MarkdownFormatter struct{}

func (f *MarkdownFormatter) Format(results []models.Result) error {
	fmt.Println("| Subdomain | Provider | Confidence | Takeover Possible |")
	fmt.Println("|-----------|----------|------------|--------------------|")
	for _, r := range results {
		takeover := "No"
		if r.TakeoverPossible {
			takeover = "Yes"
		}
		fmt.Printf("| %s | %s | %s | %s |\n", r.Subdomain, r.Provider, r.Confidence, takeover)
	}
	return nil
}
