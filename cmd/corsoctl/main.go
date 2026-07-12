package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/azemoning/corso/pkg/banner"
	corsoebpf "github.com/azemoning/corso/pkg/ebpf"
	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
)

func main() {
	klog.InitFlags(nil)

	rootCmd := &cobra.Command{
		Use:   "corsoctl",
		Short: banner.Short(),
		Long:  banner.Full(),
	}

	// scan command - enumerate all loaded eBPF programs
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan for loaded eBPF programs on this node",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Scanning eBPF programs...")

			programs, err := corsoebpf.EnumeratePrograms()
			if err != nil {
				return fmt.Errorf("failed to enumerate programs: %w", err)
			}

			if len(programs) == 0 {
				fmt.Println("No eBPF programs loaded.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID	NAME	TYPE	TAG")
			fmt.Fprintln(w, "--	----	----	---")
			for _, p := range programs {
				fmt.Fprintf(w, "%d	%s	%s	%s\n",
					p.ID, p.Name, p.Type, p.Tag)
			}
			w.Flush()

			fmt.Printf("\n%s", corsoebpf.FormatProgramSummary(programs))
			return nil
		},
	}

	// stats command - show program type statistics
	statsCmd := &cobra.Command{
		Use:   "stats",
		Short: "Show eBPF program type statistics",
		RunE: func(cmd *cobra.Command, args []string) error {
			stats, err := corsoebpf.ProgramTypeStats()
			if err != nil {
				return fmt.Errorf("failed to get stats: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "TYPE\tCOUNT")
			fmt.Fprintln(w, "----\t-----")
			for ptype, count := range stats {
				fmt.Fprintf(w, "%s\t%d\n", ptype, count)
			}
			w.Flush()
			return nil
		},
	}

	// count command - quick program count
	countCmd := &cobra.Command{
		Use:   "count",
		Short: "Count loaded eBPF programs",
		RunE: func(cmd *cobra.Command, args []string) error {
			count, err := corsoebpf.GetProgramCount()
			if err != nil {
				return fmt.Errorf("failed to count programs: %w", err)
			}
			fmt.Printf("Loaded eBPF programs: %d\n", count)
			return nil
		},
	}

	// nodes command - show eBPF programs per node (placeholder)
	nodesCmd := &cobra.Command{
		Use:   "nodes",
		Short: "Show eBPF programs per node in the cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Fetching node eBPF status...")
			fmt.Println("NOTE: This requires Corso DaemonSet to be running on cluster nodes")
			fmt.Println("Use 'corsoctl scan' on a node to see local programs")
			return nil
		},
	}

	// status command - show audit status
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show Corso audit status",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Corso eBPF Auditor")
			fmt.Println("==================")
			fmt.Println("Status: Running (requires DaemonSet)")
			fmt.Println("Node: (set via NODE_NAME env)")
			fmt.Println("")
			fmt.Println("Use 'corsoctl scan' to enumerate loaded eBPF programs")
			return nil
		},
	}

	rootCmd.AddCommand(scanCmd, statsCmd, countCmd, nodesCmd, statusCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
