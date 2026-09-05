package ca_test

import (
	"strings"
	"testing"

	"tornato.dev/ggrok/v2/internal/ca"
)

func TestRevokedSerialNormalization(t *testing.T) {
	t.Parallel()
	serials, err := ca.ParseRevokedSerials(strings.NewReader("  00ABCD \n\nabcd\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := serials["abcd"]; !ok || len(serials) != 1 {
		t.Fatalf("unexpected serials: %v", serials)
	}
	for _, input := range []string{"0", "-1", "+1", "0xabc", "typo"} {
		if _, err := ca.ParseRevokedSerials(strings.NewReader(input)); err == nil {
			t.Errorf("accepted invalid serial %q", input)
		}
	}
}
