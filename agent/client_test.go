package main

import (
	"net/http"
	"testing"
)

func TestPendingHeartbeatProofDoesNotAcknowledgeBusinessPayload(t *testing.T) {
	response, err := decodeHeartbeatResponse(http.StatusTooEarly, []byte(
		`{"accepted":false,"server_time":"2026-07-18T00:00:00Z","identity_state":"pending","identity_version":2,"tasks":[]}`,
	))
	if err != nil {
		t.Fatalf("valid pending response was rejected: %v", err)
	}
	if response.Accepted || response.IdentityState != "pending" || response.IdentityVersion != 2 {
		t.Fatalf("unexpected pending response: %+v", response)
	}
}

func TestHeartbeatResponseFailsClosedOnContradictoryAcceptance(t *testing.T) {
	if _, err := decodeHeartbeatResponse(http.StatusTooEarly, []byte(
		`{"accepted":true,"identity_state":"pending"}`,
	)); err == nil {
		t.Fatal("accepted pending response was not rejected")
	}
	if _, err := decodeHeartbeatResponse(http.StatusAccepted, []byte(
		`{"accepted":false,"identity_state":"active"}`,
	)); err == nil {
		t.Fatal("unaccepted active response was not rejected")
	}
}
