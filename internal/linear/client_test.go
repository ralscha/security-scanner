package linear

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateIssueUsesExactLinearInputAndRejectsRedirects(t *testing.T) {
	var requestBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "secret-key" {
			t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(request.Body).Decode(&requestBody); err != nil {
			t.Fatal(err)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"data":{"issueCreate":{"success":true,"issue":{"identifier":"SEC-42","url":"https://linear.app/acme/issue/SEC-42/test"}}}}`))
	}))
	defer server.Close()
	client := newClient(server.URL, "secret-key", false, server.Client())
	issue, err := client.CreateIssue(context.Background(), CreateIssueInput{
		TeamID: "team", ProjectID: "project", AssigneeID: "user", Title: "title",
		Description: "description", Priority: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if issue.Identifier != "SEC-42" {
		t.Fatalf("issue = %#v", issue)
	}
	variables := requestBody["variables"].(map[string]any)
	input := variables["input"].(map[string]any)
	if input["teamId"] != "team" || input["projectId"] != "project" || input["assigneeId"] != "user" || input["priority"] != float64(2) {
		t.Fatalf("input = %#v", input)
	}

	redirect := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Location", server.URL)
		writer.WriteHeader(http.StatusFound)
	}))
	defer redirect.Close()
	client = newClient(redirect.URL, "secret-key", false, redirect.Client())
	if _, err := client.CreateIssue(context.Background(), CreateIssueInput{TeamID: "team", Title: "title"}); err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("redirect error = %v", err)
	}
}

func TestLinearErrorsNeverExposeCredential(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"errors":[{"message":"bad credential secret-key"}]}`))
	}))
	defer server.Close()
	client := newClient(server.URL, "secret-key", false, server.Client())
	_, err := client.Issue(context.Background(), "SEC-1")
	if err == nil || strings.Contains(err.Error(), "secret-key") || !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseIssueReferenceAndFilter(t *testing.T) {
	id, workspace, err := ParseIssueReference("https://linear.app/Acme/issue/SEC-123/title")
	if err != nil || id != "SEC-123" || workspace != "acme" {
		t.Fatalf("reference = %q %q %v", id, workspace, err)
	}
	if _, _, err := ParseIssueReference("https://example.com/acme/issue/SEC-123"); err == nil {
		t.Fatal("expected foreign host to be rejected")
	}
	filter, err := ParseIssueFilter(`{"state":{"type":{"eq":"completed"}}}`)
	if err != nil || filter["state"] == nil {
		t.Fatalf("filter = %#v, %v", filter, err)
	}
	if _, err := ParseIssueFilter("[]"); err == nil {
		t.Fatal("expected array filter to be rejected")
	}
}

func TestProjectIssuesDefaultsToOpenAndPaginates(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		var body struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		writer.Header().Set("Content-Type", "application/json")
		if strings.Contains(body.Query, "query Projects") {
			_, _ = writer.Write([]byte(`{"data":{"projects":{"nodes":[{"id":"project-1"}]}}}`))
			return
		}
		filter := body.Variables["filter"].(map[string]any)
		if filter["state"] == nil {
			t.Fatalf("open-state default missing: %#v", filter)
		}
		if body.Variables["after"] == nil {
			_, _ = writer.Write([]byte(`{"data":{"project":{"issues":{"nodes":[{"identifier":"SEC-1","title":"One","url":"https://linear.app/acme/issue/SEC-1/one"}],"pageInfo":{"hasNextPage":true,"endCursor":"next"}}}}}`))
			return
		}
		_, _ = writer.Write([]byte(`{"data":{"project":{"issues":{"nodes":[{"identifier":"SEC-2","title":"Two","url":"https://linear.app/acme/issue/SEC-2/two"}],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}}`))
	}))
	defer server.Close()
	client := newClient(server.URL, "secret-key", false, server.Client())
	issues, err := client.ProjectIssues(context.Background(), "Security backlog", map[string]any{"priority": map[string]any{"lte": 2}})
	if err != nil {
		t.Fatal(err)
	}
	if requests != 3 || len(issues) != 2 || issues[0].Identifier != "SEC-1" || issues[1].Identifier != "SEC-2" {
		t.Fatalf("requests=%d issues=%#v", requests, issues)
	}
}
