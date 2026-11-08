package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ZerkerEOD/heimdall-listener/pkg/export"
	"github.com/ZerkerEOD/heimdall-listener/pkg/run"
)

func newExportCmd() *cobra.Command {
	var format, outPath string
	cmd := &cobra.Command{
		Use:   "export RUN.json",
		Short: "Render a saved run as CSV or a remediation summary",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := run.Load(args[0])
			if err != nil {
				return err
			}
			w, closeFn, err := openOutput(outPath, cmd.OutOrStdout())
			if err != nil {
				return err
			}
			defer closeFn()
			switch format {
			case "csv":
				return export.WriteCSV(w, r)
			case "summary", "text":
				return export.WriteSummaryText(w, r)
			case "summary-csv":
				return export.WriteSummaryCSV(w, r)
			case "json":
				return run.Write(w, r)
			default:
				return fmt.Errorf("unknown format %q (csv, summary, summary-csv, json)", format)
			}
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "summary", "output format: csv, summary, summary-csv, json")
	cmd.Flags().StringVarP(&outPath, "output", "o", "", "write to this file instead of stdout")
	return cmd
}
