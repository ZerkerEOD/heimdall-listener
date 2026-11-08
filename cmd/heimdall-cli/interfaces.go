package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ZerkerEOD/heimdall-listener/pkg/capture"
)

func newInterfacesCmd() *cobra.Command {
	var asJSON, all bool
	cmd := &cobra.Command{
		Use:   "interfaces",
		Short: "List network interfaces available for capture",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ifs, err := capture.Interfaces()
			if err != nil {
				return err
			}
			if !all {
				var usable []capture.Interface
				for _, i := range ifs {
					if i.Usable() {
						usable = append(usable, i)
					}
				}
				ifs = usable
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(ifs)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tDESCRIPTION\tADDRESSES\tUP")
			for _, i := range ifs {
				addrs := make([]string, len(i.Addrs))
				for k, a := range i.Addrs {
					addrs[k] = a.String()
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%v\n", i.Name, i.Description, strings.Join(addrs, ", "), i.Up)
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			if len(ifs) == 0 {
				fmt.Fprintln(cmd.ErrOrStderr(), "no usable interfaces found (try --all)")
			}
			fmt.Fprintln(cmd.ErrOrStderr(), "backend:", capture.Backend())
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	cmd.Flags().BoolVar(&all, "all", false, "include loopback and interfaces without routable addresses")
	return cmd
}
