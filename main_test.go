package main

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConformance(t *testing.T) {
	srv := buildServer()
	sdk.RunConformance(t, srv)
}

func TestTrackConformance(t *testing.T) {
	srv := buildServer()
	sdk.RunForTrack(t, srv, registry.TrackSupplyChain)
}

func TestScanNPMNamespaceCollision(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, filepath.Join(testdataDir(t), "npm-confusion"))

	found := findByRule(resp.GetFindings(), "DEPCONF-001")
	if len(found) == 0 {
		t.Fatal("expected at least one DEPCONF-001 (namespace collision risk) finding for npm")
	}

	// Verify @internal/ and @private/ scoped packages are detected.
	hasInternal := false
	hasPrivate := false
	hasInternalPrefix := false
	hasCompanyPrefix := false
	for _, f := range found {
		pkg := f.GetMetadata()["package"]
		switch {
		case pkg == "@internal/auth-service":
			hasInternal = true
		case pkg == "@private/billing-api":
			hasPrivate = true
		case pkg == "internal-test-utils":
			hasInternalPrefix = true
		case pkg == "company-eslint-config":
			hasCompanyPrefix = true
		}
	}
	if !hasInternal {
		t.Error("expected @internal/auth-service to be flagged")
	}
	if !hasPrivate {
		t.Error("expected @private/billing-api to be flagged")
	}
	if !hasInternalPrefix {
		t.Error("expected internal-test-utils to be flagged")
	}
	if !hasCompanyPrefix {
		t.Error("expected company-eslint-config to be flagged")
	}

	for _, f := range found {
		if f.GetSeverity() != sdk.SeverityHigh {
			t.Errorf("DEPCONF-001 severity should be HIGH, got %v", f.GetSeverity())
		}
	}
}

func TestScanNPMAmbiguousSource(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, filepath.Join(testdataDir(t), "npm-confusion"))

	found := findByRule(resp.GetFindings(), "DEPCONF-003")
	if len(found) == 0 {
		t.Fatal("expected at least one DEPCONF-003 (ambiguous source) finding for scoped packages without .npmrc")
	}
}

func TestScanPipNamespaceCollision(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, filepath.Join(testdataDir(t), "pip-confusion"))

	found := findByRule(resp.GetFindings(), "DEPCONF-001")
	if len(found) == 0 {
		t.Fatal("expected at least one DEPCONF-001 finding for pip internal packages")
	}

	hasInternalAuth := false
	hasCompanyUtils := false
	hasPrivateML := false
	for _, f := range found {
		pkg := f.GetMetadata()["package"]
		switch pkg {
		case "internal-auth-client":
			hasInternalAuth = true
		case "company-utils":
			hasCompanyUtils = true
		case "private-ml-model":
			hasPrivateML = true
		}
	}
	if !hasInternalAuth {
		t.Error("expected internal-auth-client to be flagged")
	}
	if !hasCompanyUtils {
		t.Error("expected company-utils to be flagged")
	}
	if !hasPrivateML {
		t.Error("expected private-ml-model to be flagged")
	}
}

func TestScanPipMissingRegistryConfig(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, filepath.Join(testdataDir(t), "pip-confusion"))

	found := findByRule(resp.GetFindings(), "DEPCONF-002")
	if len(found) == 0 {
		t.Fatal("expected at least one DEPCONF-002 (missing private registry config) finding for pip")
	}

	for _, f := range found {
		if f.GetMetadata()["ecosystem"] != "pip" {
			t.Errorf("expected ecosystem=pip, got %q", f.GetMetadata()["ecosystem"])
		}
	}
}

func TestScanGoModNamespaceCollision(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, filepath.Join(testdataDir(t), "go-confusion"))

	found := findByRule(resp.GetFindings(), "DEPCONF-001")
	if len(found) == 0 {
		t.Fatal("expected at least one DEPCONF-001 finding for Go modules without domain prefix")
	}

	hasInternallib := false
	hasCorputil := false
	for _, f := range found {
		mod := f.GetMetadata()["module"]
		switch mod {
		case "internallib":
			hasInternallib = true
		case "corputil":
			hasCorputil = true
		}
	}
	if !hasInternallib {
		t.Error("expected internallib to be flagged for missing domain prefix")
	}
	if !hasCorputil {
		t.Error("expected corputil to be flagged for missing domain prefix")
	}
}

func TestScanSafeNPMNoCollisionFindings(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, filepath.Join(testdataDir(t), "safe-npm"))

	found := findByRule(resp.GetFindings(), "DEPCONF-001")
	if len(found) != 0 {
		t.Errorf("expected no DEPCONF-001 findings for safe npm project, got %d", len(found))
	}
}

func TestScanEmptyWorkspace(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, t.TempDir())

	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings for empty workspace, got %d", len(resp.GetFindings()))
	}
}

func TestScanNoWorkspace(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}
	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings when no workspace provided, got %d", len(resp.GetFindings()))
	}
}

// --- helpers ---

func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file path")
	}
	return filepath.Join(filepath.Dir(filename), "testdata")
}

func testClient(t *testing.T) pluginv1.PluginServiceClient {
	t.Helper()
	const bufSize = 1024 * 1024

	lis := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(grpcServer, buildServer())

	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(func() { grpcServer.Stop() })

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return pluginv1.NewPluginServiceClient(conn)
}

func invokeScan(t *testing.T, client pluginv1.PluginServiceClient, workspaceRoot string) *pluginv1.InvokeToolResponse {
	t.Helper()
	input, err := structpb.NewStruct(map[string]any{
		"workspace_root": workspaceRoot,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool(scan): %v", err)
	}
	return resp
}

func findByRule(findings []*pluginv1.Finding, ruleID string) []*pluginv1.Finding {
	var result []*pluginv1.Finding
	for _, f := range findings {
		if f.GetRuleId() == ruleID {
			result = append(result, f)
		}
	}
	return result
}
