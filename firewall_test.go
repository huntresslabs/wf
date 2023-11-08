// Copyright (c) 2021 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wf

import (
	"os"
	"sort"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/windows"
)

func skipIfUnprivileged(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		if os.Getenv("CI") != "" {
			t.Fatal("test requires admin privileges")
		}
		t.Skipf("skipping test that requires admin privileges")
	}
}

func TestSession(t *testing.T) {
	skipIfUnprivileged(t)

	tests := []struct {
		name string
		opts *Options
	}{
		{
			name: "nil",
			opts: nil,
		},
		{
			name: "name_only",
			opts: &Options{
				Name: "test",
			},
		},
		{
			name: "name_and_desc",
			opts: &Options{
				Name:        "test2",
				Description: "unit test session",
			},
		},
		{
			name: "dynamic",
			opts: &Options{
				Name:    "test2",
				Dynamic: true,
			},
		},
		{
			name: "tx_timeout",
			opts: &Options{
				Name:                    "test2",
				TransactionStartTimeout: 5 * time.Minute,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sess, err := New(test.opts)
			if err != nil {
				t.Fatalf("failed to open session: %v", err)
			}
			if err := sess.Close(); err != nil {
				t.Errorf("closing session: %v", err)
			}
		})
	}
}

func TestLayers(t *testing.T) {
	skipIfUnprivileged(t)

	s, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	layers, err := s.Layers()
	if err != nil {
		t.Fatalf("getting layers: %v", err)
	}

	// Try to find a couple of the well-known layers that Windows
	// should definitely have.
	wantLayers := map[LayerID]*Layer{
		LayerALEAuthRecvAcceptV4: {
			ID:              LayerALEAuthRecvAcceptV4,
			KernelID:        44,
			Name:            "ALE Receive/Accept v4 Layer",
			DefaultSublayer: guidSublayerUniversal,
			Fields: []*Field{
				{FieldALEAppID, typeString},
				{FieldALENAPContext, typeUint32},
				{FieldALEPackageID, typeSID},
				{FieldALERemoteMachineID, typeSecurityDescriptor},
				{FieldALERemoteUserID, typeSecurityDescriptor},
				{FieldALESecurityAttributeFqbnValue, typeBytes},
				{FieldALESioFirewallSystemPort, typeUint32},
				{FieldALEUserID, typeSecurityDescriptor},
				{FieldArrivalInterfaceIndex, typeUint32},
				{FieldArrivalInterfaceType, typeUint32},
				{FieldArrivalTunnelType, typeUint32},
				{FieldCompartmentID, typeUint32},
				{FieldCurrentProfileID, typeUint32},
				{FieldFlags, typeUint32},
				{FieldInterfaceIndex, typeUint32},
				{FieldInterfaceQuarantineEpoch, typeUint64},
				{FieldInterfaceType, typeUint32},
				{FieldIPArrivalInterface, typeUint64},
				{FieldIPLocalAddress, typeIP},
				{FieldIPLocalAddressType, typeUint8},
				{FieldIPLocalInterface, typeUint64},
				{FieldIPLocalPort, typeUint16},
				{FieldIPNexthopInterface, typeUint64},
				{FieldIPProtocol, typeUint8},
				{FieldIPRemoteAddress, typeIP},
				{FieldIPRemotePort, typeUint16},
				{FieldNexthopInterfaceIndex, typeUint32},
				{FieldNexthopInterfaceType, typeUint32},
				{FieldNexthopSubInterfaceIndex, typeUint32},
				{FieldNexthopTunnelType, typeUint32},
				{FieldOriginalICMPType, typeUint16},
				{FieldOriginalProfileID, typeUint32},
				{FieldReauthorizeReason, typeUint32},
				{FieldSubInterfaceIndex, typeUint32},
				{FieldTunnelType, typeUint32},
			},
		},
		LayerStreamV4Discard: {
			ID:              LayerStreamV4Discard,
			KernelID:        21,
			Name:            "Stream v4 Discard Layer",
			DefaultSublayer: guidSublayerUniversal,
			Fields: []*Field{
				{FieldCompartmentID, typeUint32},
				{FieldDirection, typeUint32},
				{FieldFlags, typeUint32},
				{FieldIPLocalAddress, typeIP},
				{FieldIPLocalAddressType, typeUint8},
				{FieldIPLocalPort, typeUint16},
				{FieldIPRemoteAddress, typeIP},
				{FieldIPRemotePort, typeUint16},
			},
		},
	}

	for guid, want := range wantLayers {
		found := false
		for _, got := range layers {
			if got.ID != guid {
				continue
			}
			found = true
			sort.Slice(got.Fields, func(i, j int) bool {
				return got.Fields[i].ID.String() < got.Fields[j].ID.String()
			})
			fieldCmp := func(a, b *Field) bool {
				return a.ID == b.ID && a.Type == b.Type
			}
			if diff := cmp.Diff(got, want, cmp.Comparer(fieldCmp)); diff != "" {
				t.Errorf("unexpected layer def (-got+want):\n%s", diff)
			}
			break
		}
		if !found {
			t.Errorf("layer %s (%s) not found", guid, windows.GUID(guid))
		}
	}
}

func TestSublayers(t *testing.T) {
	skipIfUnprivileged(t)

	s, err := New(&Options{
		Dynamic: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	guid, err := windows.GenerateGUID()
	if err != nil {
		t.Fatal(err)
	}

	sl := &Sublayer{
		ID:           SublayerID(guid),
		Name:         "test sublayer",
		Description:  "a test sublayer",
		ProviderData: []byte("byte blob"),
		Weight:       0x4242,
	}
	if err := s.AddSublayer(sl); err != nil {
		t.Fatalf("add sublayer failed: %v", err)
	}

	sublayers, err := s.Sublayers(ProviderID{})
	if err != nil {
		t.Fatalf("get sublayers failed: %v", err)
	}

	found := false
	for _, got := range sublayers {
		if got.ID != sl.ID {
			continue
		}
		found = true
		if diff := cmp.Diff(got, sl); diff != "" {
			t.Fatalf("sublayer is wrong (-got+want):\n%s", diff)
		}
		break
	}
	if !found {
		t.Fatal("sublayer added but not found")
	}

	if err := s.DeleteSublayer(sl.ID); err != nil {
		t.Fatalf("delete sublayer failed: %v", err)
	}

	sublayers, err = s.Sublayers(ProviderID{})
	if err != nil {
		t.Fatalf("get sublayers failed: %v", err)
	}
	for _, got := range sublayers {
		if got.ID == sl.ID {
			t.Fatalf("deleted sublayer but it's still there: %#v", got)
		}
	}
}

func TestProviders(t *testing.T) {
	skipIfUnprivileged(t)

	s, err := New(&Options{
		Dynamic: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	guid, err := windows.GenerateGUID()
	if err != nil {
		t.Fatal(err)
	}

	p := &Provider{
		ID:          ProviderID(guid),
		Name:        "test provider",
		Description: "a test provider",
		Data:        []byte("byte blob"),
	}
	if err := s.AddProvider(p); err != nil {
		t.Fatalf("add provider failed: %v", err)
	}

	providers, err := s.Providers()
	if err != nil {
		t.Fatalf("get providers failed: %v", err)
	}

	found := false
	for _, got := range providers {
		if got.ID != p.ID {
			continue
		}
		found = true
		if diff := cmp.Diff(got, p); diff != "" {
			t.Fatalf("provider is wrong (-got+want):\n%s", diff)
		}
		break
	}
	if !found {
		t.Fatal("provider added but not found")
	}

	if err := s.DeleteProvider(p.ID); err != nil {
		t.Fatalf("delete provider failed: %v", err)
	}

	providers, err = s.Providers()
	if err != nil {
		t.Fatalf("get providers failed: %v", err)
	}
	for _, got := range providers {
		if got.ID == p.ID {
			t.Fatalf("deleted provider but it's still there: %#v", got)
		}
	}
}

func TestFilter(t *testing.T) {
	// Create a new dynamic session
	s, err := New(&Options{
		Dynamic: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	guid, err := windows.GenerateGUID()
	if err != nil {
		t.Fatal(err)
	}

	// Create a new provider
	p := &Provider{
		ID:          ProviderID(guid),
		Name:        "test provider",
		Description: "a test provider",
		Data:        []byte("byte blob"),
	}
	if err := s.AddProvider(p); err != nil {
		t.Fatalf("add provider failed: %v", err)
	}

	rule_id, err := windows.GenerateGUID()
	if err != nil {
		t.Fatal(err)
	}

	// Create a rule so we can test enumeration
	r := Rule{
		ID:          RuleID(rule_id),
		Name:        "inetaf-wf-test-rule",
		Description: "A disabled rule for testing the inet.af/wf library",
		Layer:       LayerALEAuthConnectV4,
		Weight:      0x4242,
		Conditions: []*Match{
			{
				Field: FieldALEAppID,
				Op:    MatchTypeEqual,
				Value: "test",
			},
		},
		Action:     ActionPermit,
		Persistent: false,
		BootTime:   false,
		Provider:   ProviderID(guid),
		Disabled:   true,
	}
	if err := s.AddRule(&r); err != nil {
		t.Fatal(err)
	}

	// Filter for rules from our provider
	rules, err := s.EnumerateRules(FilterEnumTypeOverlapping, LayerALEAuthConnectV4).
		WithProvider(ProviderID(guid)).
		WithActionMask(ActionFlagIgnore).
		WithFlags(FilterEnumFlagsSorted).
		Execute()
	if err != nil {
		t.Fatal(err)
	} else if len(rules) != 1 {
		t.Fatalf("expected 1 rule in filter, but found %v", len(rules))
	} else if rules[0].ID != RuleID(rule_id) {
		t.Fatalf("wrong rule enumerated (expected %v; got %v)", rule_id, rules[0].ID)
	}
}

func TestTransactionSessionClosed(t *testing.T) {
	// Attempt to open a new WFP session
	s, err := New(&Options{
		Name:                    "huntress-isolation",
		Description:             "Huntress Isolation Context Session",
		Dynamic:                 false,
		StartTransaction:        true,
		TransactionFlags:        TransactionReadWrite,
		TransactionStartTimeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatal("unable to start a new session")
	}

	status := s.TransactionStatus()
	if status.Err != nil {
		t.Fatalf("transaction err: %v", status.Err)
	}
	if status.State != BeganTransaction {
		t.Fatalf("transaction in wrong state: %v", status.State.String())
	}

	// This should abort the transaction
	s.Close()
	status = s.TransactionStatus()
	if status.Err != nil {
		t.Fatalf("unexpected transaction err: %v", status.Err)
	}
	if status.State != AbortedTransaction {
		t.Fatalf("transaction in wrong state: %v", status.State.String())
	}

	// We should not be able to commit a transaction
	s.CommitTransaction()
	status = s.TransactionStatus()
	if status.Err != syscall.Errno(NilPointer) {
		t.Fatalf("unexpected transaction err: %v", status.Err)
	}
	if status.State != AbortedTransaction {
		t.Fatalf("Transaction in wrong state: %v", status.State.String())
	}

	// We should not be able to abort a transaction
	s.AbortTransaction()
	status = s.TransactionStatus()
	if status.Err != syscall.Errno(NilPointer) {
		t.Fatalf("unexpected transaction err: %v", status.Err)
	}
	if status.State != AbortedTransaction {
		t.Fatalf("Transaction in wrong state: %v", status.State.String())
	}
}

func TestTransactionNeverStarted(t *testing.T) {
	// Attempt to open a new WFP session
	s, err := New(&Options{
		Name:                    "huntress-isolation",
		Description:             "Huntress Isolation Context Session",
		Dynamic:                 false,
		StartTransaction:        false,
		TransactionFlags:        TransactionReadWrite,
		TransactionStartTimeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatal("unable to start a new session")
	}

	status := s.TransactionStatus()
	if status.Err != nil {
		t.Fatalf("transaction err: %v", status.Err)
	}
	if status.State != NoTransaction {
		t.Fatalf("transaction in wrong state: %v", status.State.String())
	}

	// We should not be able to commit a transaction
	s.CommitTransaction()
	status = s.TransactionStatus()
	if status.Err != syscall.Errno(NoTransactionInProgress) {
		t.Fatalf("unexpected transaction err: %v", status.Err)
	}
	if status.State != NoTransaction {
		t.Fatalf("Transaction in wrong state: %v", status.State.String())
	}

	// We should not be able to abort a transaction
	s.AbortTransaction()
	status = s.TransactionStatus()
	if status.Err != syscall.Errno(NoTransactionInProgress) {
		t.Fatalf("unexpected transaction err: %v", status.Err)
	}
	if status.State != NoTransaction {
		t.Fatalf("Transaction in wrong state: %v", status.State.String())
	}
}

func TestBlockedTransaction(t *testing.T) {
	// Attempt to open a new WFP session
	b, err := New(&Options{
		Name:                    "huntress-isolation",
		Description:             "Huntress Isolation Context Session",
		Dynamic:                 false,
		StartTransaction:        true,
		TransactionFlags:        TransactionReadWrite,
		TransactionStartTimeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatal("unable to start a new session")
	}
	defer func() {
		b.Close()

		if b.TransactionStatus().State != AbortedTransaction {
			t.Fatal("Transaction should now be in the aborted state")
		}
	}()

	status := b.TransactionStatus()
	if status.Err != nil {
		t.Fatalf("transaction err: %v", status.Err)
	}
	if status.State != BeganTransaction {
		t.Fatalf("transaction in wrong state: %v", status.State.String())
	}

	// We know we're going to timeout, so keep Timeout value 1 millisecond
	// DON'T SET IT TO ZERO, THE DEFAULT TIMEOUT IS VERY LONG
	_, err = New(&Options{
		Name:                    "huntress-isolation",
		Description:             "Huntress Isolation Context Session",
		Dynamic:                 false,
		StartTransaction:        false,
		TransactionFlags:        TransactionReadWrite,
		TransactionStartTimeout: time.Millisecond * 1,
	})
	if err != syscall.Errno(Timeout) {
		t.Fatalf("unexpected transaction err: %v", err)
	}
}

func TestBeginTransactionAlreadyInProgress(t *testing.T) {
	// Create a session that is started in a transaction
	s, err := New(&Options{
		Name:                    "huntress-isolation",
		Description:             "Huntress Isolation Context Session",
		Dynamic:                 false,
		StartTransaction:        true,
		TransactionFlags:        TransactionReadWrite,
		TransactionStartTimeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatal("unable to start a new session")
	}
	defer func() {
		s.Close()

		if s.TransactionStatus().State != AbortedTransaction {
			t.Fatal("Transaction should now be in the aborted state")
		}
	}()

	s.BeginTransaction(TransactionReadWrite)

	if s.TransactionStatus().Err != syscall.Errno(TransactionInProgress) {
		t.Fatal("Wrong error code.")
	}
}

func TestTransactionCommitStarted(t *testing.T) {
	// Create a session that is started in a transaction
	s, err := New(&Options{
		Name:                    "huntress-isolation",
		Description:             "Huntress Isolation Context Session",
		Dynamic:                 false,
		StartTransaction:        true,
		TransactionFlags:        TransactionReadWrite,
		TransactionStartTimeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatal("unable to start a new session")
	}
	defer func() {
		s.Close()

		if s.TransactionStatus().State != CommittedTransaction {
			t.Fatal("Transaction should now be in the committed state")
		}
	}()

	if s.TransactionStatus().State != BeganTransaction {
		t.Fatal("Could not begin transaction")
	}

	s.CommitTransaction()

	if s.TransactionStatus().State != CommittedTransaction {
		t.Fatal("Could not commit transaction")
	}
}

func TestTransactionBeginCommit(t *testing.T) {
	// Create a session that is started in a transaction
	s, err := New(&Options{
		Name:                    "huntress-isolation",
		Description:             "Huntress Isolation Context Session",
		Dynamic:                 false,
		StartTransaction:        false,
		TransactionFlags:        TransactionReadWrite,
		TransactionStartTimeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatal("unable to start a new session")
	}
	defer func() {
		s.Close()

		if s.TransactionStatus().State != CommittedTransaction {
			t.Fatal("Transaction should now be in the committed state")
		}
	}()

	if s.TransactionStatus().State != NoTransaction {
		t.Fatal("Should be in a non-transacted state")
	}

	s.BeginTransaction(TransactionReadWrite)

	if s.TransactionStatus().State != BeganTransaction {
		t.Fatal("Could not begin transaction")
	}

	s.CommitTransaction()

	if s.TransactionStatus().State != CommittedTransaction {
		t.Fatal("Could not commit transaction")
	}
}

func TestTransactionAbort(t *testing.T) {
	// Create a session that is started in a transaction
	s, err := New(&Options{
		Name:                    "huntress-isolation",
		Description:             "Huntress Isolation Context Session",
		Dynamic:                 false,
		StartTransaction:        true,
		TransactionFlags:        TransactionReadWrite,
		TransactionStartTimeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatal("unable to start a new session")
	}
	defer func() {
		s.Close()

		if s.TransactionStatus().State != AbortedTransaction {
			t.Fatal("Transaction should now be in the aborted state")
		}
	}()

	if s.TransactionStatus().State != BeganTransaction {
		t.Fatal("Could not begin transaction")
	}

	s.AbortTransaction()

	if s.TransactionStatus().State != AbortedTransaction {
		t.Fatal("Could not abort transaction")
	}
}
