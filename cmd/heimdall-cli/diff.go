package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ZerkerEOD/heimdall-listener/pkg/export"
	"github.com/ZerkerEOD/heimdall-listener/pkg/run"
)

func newDiffCmd() *cobra.Command {
	var format, outPath string
	cmd := &cobra.Command{
		Use:   "diff BASELINE.json CURRENT.json",
		Short: "Compare two runs: what appeared, what was resolved, what persists",
		Long: `Diff compares two run files produced by 'capture -o' (or saved from the GUI).
Pairs are (source host, protocol, kind). A pair present in the baseline but
absent now is RESOLVED: the remediation worked. A pair only present now is
NEW. Unchanged pairs list names added (+) or gone (-).`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			base, err := run.Load(args[0])
			if err != nil {
				return err
			}
			cur, err := run.Load(args[1])
			if err != nil {
				return err
			}
			d := run.Diff(base, cur, args[0], args[1])
			w, closeFn, err := openOutput(outPath, cmd.OutOrStdout())
			if err != nil {
				return err
			}
			defer closeFn()
			switch format {
			case "table", "text":
				return export.WriteDiffTable(w, d)
			case "json":
				return export.WriteDiffJSON(w, d)
			case "csv":
				return export.WriteDiffCSV(w, d)
			default:
				return fmt.Errorf("unknown format %q (table, json, csv)", format)
			}
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table, json, csv")
	cmd.Flags().StringVarP(&outPath, "output", "o", "", "write to this file instead of stdout")
	return cmd
}
