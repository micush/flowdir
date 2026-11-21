package main

import (
	"testing"
	"time"
)

// A name or a definite "no name" stands for 30 minutes; a failed lookup is tried again after a minute.
func TestFlowDNSFailedLookupIsRetriedSoon(t *testing.T) {
	old := time.Now().Add(-2 * time.Minute)
	if (dnsEnt{"", old, dnsRetry}).fresh() {
		t.Fatal("a failed lookup must not stand for 30 minutes")
	}
	if !(dnsEnt{"sw1.example.com", old, dnsTTL}).fresh() || !(dnsEnt{"x", old, 0}).fresh() {
		t.Fatal("an answer must stand for 30 minutes")
	}
}
