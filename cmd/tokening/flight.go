package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/softdevstudio/tokening/internal/flight"
	"github.com/softdevstudio/tokening/internal/store"
)

const flightUsage = `Usage:
  tokening flight verify [--db tokening.db | --file flight.jsonl] [--head SEQ:HASH] [--partial]
  tokening flight export [--db tokening.db] [--agent A] [--grant G] [--since T] [--until T] [--output F]
  tokening flight replay [--db tokening.db | --file flight.jsonl] [--agent A] [--grant G] [--since T] [--until T]
  tokening flight head   [--db tokening.db]
Times are RFC 3339 (2026-10-31T10:00:00Z) or a UTC date (2026-10-31). --since is inclusive, --until is not.`

func flightCommand(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, flightUsage)
		return 2
	}
	if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(out, flightUsage)
		return 0
	}
	flags := flag.NewFlagSet("flight "+args[0], flag.ContinueOnError)
	flags.SetOutput(errOut)
	flags.Usage = func() { fmt.Fprintln(errOut, flightUsage) }
	db := flags.String("db", "tokening.db", "Tokening database file")
	var file, head, agent, grant, since, until, output *string
	var partial *bool
	switch args[0] {
	case "verify":
		file = flags.String("file", "", "verify an exported JSONL file instead of the database (- for stdin)")
		head = flags.String("head", "", "a SEQ:HASH saved earlier from tokening flight head")
		partial = flags.Bool("partial", false, "accept a filtered export (file only)")
	case "export", "replay":
		agent = flags.String("agent", "", "only this agent")
		grant = flags.String("grant", "", "only this grant ID")
		since = flags.String("since", "", "from this time (inclusive)")
		until = flags.String("until", "", "up to this time (exclusive)")
		if args[0] == "export" {
			output = flags.String("output", "-", "new JSONL file, or - for stdout")
		} else {
			file = flags.String("file", "", "replay an exported JSONL file instead of the database (- for stdin)")
		}
	case "head":
	default:
		fmt.Fprintln(errOut, flightUsage)
		return 2
	}
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return 2
	}
	dbSet := false
	flags.Visit(func(f *flag.Flag) { dbSet = dbSet || f.Name == "db" })
	if file != nil && *file != "" && dbSet {
		fmt.Fprintln(errOut, "Use --db or --file, not both.")
		return 2
	}
	var filter flight.Filter
	if agent != nil {
		var err error
		filter = flight.Filter{Agent: *agent, Grant: *grant}
		if filter.Since, err = parseFlightTime(*since); err != nil {
			fmt.Fprintln(errOut, "--since:", err)
			return 2
		}
		if filter.Until, err = parseFlightTime(*until); err != nil {
			fmt.Fprintln(errOut, "--until:", err)
			return 2
		}
		if !filter.Since.IsZero() && !filter.Until.IsZero() && !filter.Until.After(filter.Since) {
			fmt.Fprintln(errOut, "--until must be later than --since.")
			return 2
		}
	}
	ctx := context.Background()
	if file != nil && *file != "" {
		switch args[0] {
		case "verify":
			var anchor *flight.Anchor
			if *head != "" {
				a, err := flight.ParseAnchor(*head)
				if err != nil {
					fmt.Fprintln(errOut, err)
					return 2
				}
				anchor = &a
			}
			return withInput(*file, errOut, func(r io.Reader) int {
				report, err := flight.VerifyReader(r, flight.Options{Partial: *partial, Head: anchor})
				if err != nil {
					fmt.Fprintln(errOut, "Could not read the file:", err)
					return 1
				}
				return printReport(out, report)
			})
		default:
			return withInput(*file, errOut, func(r io.Reader) int { return replayFile(r, filter, out, errOut) })
		}
	}
	if partial != nil && *partial {
		fmt.Fprintln(errOut, "--partial applies to --file; the database log is always checked whole.")
		return 2
	}
	s, err := store.OpenReadOnly(ctx, *db)
	if err != nil {
		fmt.Fprintln(errOut, "flight:", err)
		return 1
	}
	defer s.Close()
	switch args[0] {
	case "head":
		anchor, ok, err := s.FlightHead(ctx)
		if err != nil {
			fmt.Fprintln(errOut, "flight:", err)
			return 1
		}
		if !ok {
			fmt.Fprintln(errOut, "The flight log is empty.")
			return 1
		}
		fmt.Fprintln(out, anchor.String())
		return 0
	case "verify":
		var anchor *flight.Anchor
		if *head != "" {
			a, err := flight.ParseAnchor(*head)
			if err != nil {
				fmt.Fprintln(errOut, err)
				return 2
			}
			anchor = &a
		}
		report, err := s.VerifyFlight(ctx, flight.Options{Head: anchor})
		if err != nil {
			fmt.Fprintln(errOut, "flight:", err)
			return 1
		}
		return printReport(out, report)
	case "export":
		return exportFlight(ctx, s, filter, *output, out, errOut)
	default:
		return replayDB(ctx, s, filter, out, errOut)
	}
}

func parseFlightTime(text string) (time.Time, error) {
	if text == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, text); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse("2006-01-02", text); err == nil {
		return t, nil
	}
	return time.Time{}, errors.New("use RFC 3339, such as 2026-10-31T10:00:00Z, or a date such as 2026-10-31")
}

func withInput(name string, errOut io.Writer, fn func(io.Reader) int) int {
	if name == "-" {
		return fn(os.Stdin)
	}
	f, err := os.Open(name)
	if err != nil {
		fmt.Fprintln(errOut, "Could not open", name+".")
		return 1
	}
	defer f.Close()
	return fn(f)
}

func printReport(out io.Writer, r flight.Report) int {
	if r.OK {
		switch {
		case r.Entries == 0:
			fmt.Fprintln(out, "Intact: the flight log is empty.")
		case r.Gaps > 0 || r.FirstSeq != 1:
			fmt.Fprintf(out, "Intact as a partial export: %d entries from %d to %d, every hash checked, links checked where entries are consecutive.\n", r.Entries, r.FirstSeq, r.LastSeq)
		default:
			fmt.Fprintf(out, "Intact: %d entries, 1 to %d.\n", r.Entries, r.LastSeq)
		}
		if r.Entries > 0 {
			fmt.Fprintf(out, "Head: %d:%s\n", r.LastSeq, r.LastHash)
		}
		if r.HeadFound {
			fmt.Fprintln(out, "The saved head is in the chain.")
		}
		return 0
	}
	if r.Problem.Seq != 0 {
		fmt.Fprintf(out, "Broken at entry %d: %s.\n", r.Problem.Seq, r.Problem.Reason)
	} else {
		fmt.Fprintf(out, "Broken: %s.\n", r.Problem.Reason)
	}
	if r.Entries > 0 {
		fmt.Fprintf(out, "Entries %d to %d verify. Last good head: %d:%s\n", r.FirstSeq, r.LastSeq, r.LastSeq, r.LastHash)
	} else {
		fmt.Fprintln(out, "No entry before it verifies.")
	}
	return 1
}

func exportFlight(ctx context.Context, s *store.Store, filter flight.Filter, output string, out, errOut io.Writer) int {
	if output == "-" {
		if _, err := s.ExportFlight(ctx, out, filter); err != nil {
			fmt.Fprintln(errOut, "flight:", err)
			return 1
		}
		return 0
	}
	if _, err := os.Lstat(output); err == nil {
		fmt.Fprintln(errOut, "The output file exists; existing files are never overwritten.")
		return 1
	}
	// Write a temporary file next to the target and rename it when complete, so
	// an interrupted export never leaves a file that looks finished.
	tmp, err := os.CreateTemp(filepath.Dir(output), ".tokening-flight-*")
	if err != nil {
		fmt.Fprintln(errOut, "Could not create the export file.")
		return 1
	}
	rows, err := s.ExportFlight(ctx, tmp, filter)
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		if _, statErr := os.Lstat(output); statErr == nil {
			err = errors.New("the output file appeared during the export")
		} else {
			err = os.Rename(tmp.Name(), output)
		}
	}
	if err != nil {
		os.Remove(tmp.Name())
		fmt.Fprintln(errOut, "Could not write a complete export:", err)
		return 1
	}
	fmt.Fprintf(errOut, "Exported %d entries.\n", rows)
	return 0
}

func replayDB(ctx context.Context, s *store.Store, filter flight.Filter, out, errOut io.Writer) int {
	report, err := s.VerifyFlight(ctx, flight.Options{})
	if err != nil {
		fmt.Fprintln(errOut, "flight:", err)
		return 1
	}
	shown := 0
	err = s.WalkFlight(ctx, filter, func(e flight.Entry) error {
		shown++
		_, err := fmt.Fprintln(out, flight.FormatEntry(e))
		return err
	})
	if err != nil {
		fmt.Fprintln(errOut, "flight:", err)
		return 1
	}
	return replayFooter(out, report, shown)
}

func replayFile(r io.Reader, filter flight.Filter, out, errOut io.Writer) int {
	data, err := io.ReadAll(io.LimitReader(r, 1<<30))
	if err != nil {
		fmt.Fprintln(errOut, "Could not read the file:", err)
		return 1
	}
	report, err := flight.VerifyReader(strings.NewReader(string(data)), flight.Options{Partial: true})
	if err != nil {
		fmt.Fprintln(errOut, "Could not read the file:", err)
		return 1
	}
	shown := 0
	for _, line := range strings.SplitAfter(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		e, err := flight.UnmarshalLine([]byte(line))
		if err != nil {
			break
		}
		if filter.Match(e) {
			shown++
			fmt.Fprintln(out, flight.FormatEntry(e))
		}
	}
	return replayFooter(out, report, shown)
}

func replayFooter(out io.Writer, r flight.Report, shown int) int {
	if shown == 0 {
		fmt.Fprintln(out, "No entries match.")
	}
	if r.OK {
		// Every hash checked and every link between consecutive entries holds,
		// but entries missing from a file could be a filter or a removal.
		if missing := r.LastSeq - uint64(r.Entries); r.Entries > 0 && missing > 0 {
			fmt.Fprintf(out, "Every entry here checks out, but %d of entries 1 to %d are missing from this file: it is a filtered export, or entries were removed. Verify the whole log with tokening flight verify --db.\n", missing, r.LastSeq)
			return 0
		}
		fmt.Fprintf(out, "Chain intact through entry %d.\n", r.LastSeq)
		return 0
	}
	if r.Problem.Seq != 0 {
		fmt.Fprintf(out, "Warning: the chain is broken at entry %d: %s. Entries from there on cannot be trusted.\n", r.Problem.Seq, r.Problem.Reason)
	} else {
		fmt.Fprintf(out, "Warning: %s.\n", r.Problem.Reason)
	}
	return 1
}
