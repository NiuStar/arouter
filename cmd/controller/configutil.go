package main

import "encoding/json"

func syncIntervalFromConfig(data []byte) string {
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		return "60s"
	}
	if v, ok := cfg["poll_period"].(string); ok && v != "" {
		return v
	}
	return "60s"
}
