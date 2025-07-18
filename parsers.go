package main

import (
	"regexp"
	"strings"
)

func parseARIN(raw string) string {
	if org := extractField(raw, `OrgName:\s*(.*)`); org != "" {
		return org
	}
	return extractField(raw, `NetName:\s*(.*)`)
}

func parseRIPE(raw string) string {
	if org := extractField(raw, `org-name:\s*(.*)`); org != "" {
		return org
	}
	return extractField(raw, `netname:\s*(.*)`)
}

func parseAPNIC(raw string) string {
	return extractField(raw, `org-name:\s*(.*)`)
}

func parseLACNIC(raw string) string {
	return extractField(raw, `owner:\s*(.*)`)
}

func parseAFRINIC(raw string) string {
	return extractField(raw, `org-name:\s*(.*)`)
}

func parseGeneric(raw string) string {
	fields := []string{
		extractField(raw, `OrgName:\s*(.*)`),
		extractField(raw, `org-name:\s*(.*)`),
		extractField(raw, `NetName:\s*(.*)`),
		extractField(raw, `netname:\s*(.*)`),
		extractField(raw, `owner:\s*(.*)`),
	}
	for _, f := range fields {
		if f != "" {
			return f
		}
	}
	return "unknown"
}

func extractField(raw, pattern string) string {
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(raw)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}
