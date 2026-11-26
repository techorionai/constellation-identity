//go:build integration

package services_test

import "strings"

// spansText returns the names, the attributes, and the events of all recorded
// spans as one text. A strings.Builder keeps the cost linear. The exporter holds
// the spans of all tests of the package, so the text is large.
func spansText() string {
	var b strings.Builder
	for _, s := range spanExporter.GetSpans() {
		b.WriteString(s.Name)
		b.WriteByte('\n')
		for _, a := range s.Attributes {
			b.WriteString(string(a.Key))
			b.WriteByte('=')
			b.WriteString(a.Value.String())
			b.WriteByte('\n')
		}
		for _, e := range s.Events {
			b.WriteString(e.Name)
			b.WriteByte('\n')
			for _, a := range e.Attributes {
				b.WriteString(string(a.Key))
				b.WriteByte('=')
				b.WriteString(a.Value.String())
				b.WriteByte('\n')
			}
		}
	}
	return b.String()
}
