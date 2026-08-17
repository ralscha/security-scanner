package linear

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultEndpoint = "https://api.linear.app/graphql"
	maxResponseSize = 2 << 20
)

// Client is the small, read/write subset of Linear's GraphQL API used by the
// scanner. Keeping the boundary here avoids requiring Linear's JavaScript SDK.
type Client struct {
	endpoint   string
	credential string
	oauth      bool
	http       *http.Client
}

type Issue struct {
	Identifier  string `json:"identifier"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	URL         string `json:"url,omitempty"`
}

type CreateIssueInput struct {
	TeamID      string
	ProjectID   string
	AssigneeID  string
	Title       string
	Description string
	Priority    int
}

// NewClient configures personal API-key authentication.
func NewClient(apiKey string) *Client {
	return newClient(defaultEndpoint, strings.TrimSpace(apiKey), false, nil)
}

// NewOAuthClient configures OAuth access-token authentication for read-only
// issue intake.
func NewOAuthClient(accessToken string) *Client {
	return newClient(defaultEndpoint, strings.TrimSpace(accessToken), true, nil)
}

func newClient(endpoint, credential string, oauth bool, transport *http.Client) *Client {
	client := &http.Client{Timeout: 30 * time.Second}
	if transport != nil {
		clone := *transport
		client = &clone
	}
	// Linear data must never be sent through a redirect to another origin.
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{endpoint: endpoint, credential: credential, oauth: oauth, http: client}
}

func (c *Client) CreateIssue(ctx context.Context, input CreateIssueInput) (Issue, error) {
	variables := map[string]any{"input": map[string]any{
		"teamId": input.TeamID, "title": input.Title, "description": input.Description,
	}}
	issueInput := variables["input"].(map[string]any)
	if input.ProjectID != "" {
		issueInput["projectId"] = input.ProjectID
	}
	if input.AssigneeID != "" {
		issueInput["assigneeId"] = input.AssigneeID
	}
	if input.Priority != 0 {
		issueInput["priority"] = input.Priority
	}
	var response struct {
		IssueCreate struct {
			Success bool  `json:"success"`
			Issue   Issue `json:"issue"`
		} `json:"issueCreate"`
	}
	err := c.graphql(ctx, `mutation CreateIssue($input: IssueCreateInput!) {
  issueCreate(input: $input) { success issue { identifier url } }
}`, variables, &response)
	if err != nil {
		return Issue{}, err
	}
	if !response.IssueCreate.Success || strings.TrimSpace(response.IssueCreate.Issue.Identifier) == "" {
		return Issue{}, fmt.Errorf("Linear did not create an issue")
	}
	return response.IssueCreate.Issue, nil
}

func (c *Client) ResolveUser(ctx context.Context, email string) (string, error) {
	var response struct {
		Users struct {
			Nodes []struct {
				ID string `json:"id"`
			} `json:"nodes"`
		} `json:"users"`
	}
	err := c.graphql(ctx, `query ResolveUser($filter: UserFilter, $first: Int) {
  users(filter: $filter, first: $first) { nodes { id } }
}`, map[string]any{
		"filter": map[string]any{"email": map[string]any{"eqIgnoreCase": email}},
		"first":  2,
	}, &response)
	if err != nil {
		return "", err
	}
	if len(response.Users.Nodes) != 1 || strings.TrimSpace(response.Users.Nodes[0].ID) == "" {
		return "", fmt.Errorf("Linear could not resolve exactly one matching issue assignee")
	}
	return response.Users.Nodes[0].ID, nil
}

func (c *Client) Issue(ctx context.Context, reference string) (Issue, error) {
	id, workspace, err := ParseIssueReference(reference)
	if err != nil {
		return Issue{}, err
	}
	var response struct {
		Issue *Issue `json:"issue"`
	}
	if err := c.graphql(ctx, `query Issue($id: String!) {
  issue(id: $id) { identifier title description url }
}`, map[string]any{"id": id}, &response); err != nil {
		return Issue{}, err
	}
	if response.Issue == nil || strings.TrimSpace(response.Issue.Identifier) == "" {
		return Issue{}, fmt.Errorf("Linear issue %q was not found or is not accessible", id)
	}
	if workspace != "" {
		_, actualWorkspace, parseErr := ParseIssueReference(response.Issue.URL)
		if parseErr != nil || !strings.EqualFold(workspace, actualWorkspace) {
			return Issue{}, fmt.Errorf("fetched Linear issue does not match the workspace in the selected URL")
		}
	}
	return *response.Issue, nil
}

func (c *Client) ProjectIssues(ctx context.Context, projectName string, filter map[string]any) ([]Issue, error) {
	var projects struct {
		Projects struct {
			Nodes []struct {
				ID string `json:"id"`
			} `json:"nodes"`
		} `json:"projects"`
	}
	if err := c.graphql(ctx, `query Projects($filter: ProjectFilter, $first: Int) {
  projects(filter: $filter, first: $first) { nodes { id } }
}`, map[string]any{
		"filter": map[string]any{"name": map[string]any{"eqIgnoreCase": projectName}},
		"first":  2,
	}, &projects); err != nil {
		return nil, err
	}
	if len(projects.Projects.Nodes) != 1 {
		state := "was not found or is not accessible"
		if len(projects.Projects.Nodes) > 1 {
			state = "is ambiguous"
		}
		return nil, fmt.Errorf("Linear project %q %s", projectName, state)
	}
	if filter == nil {
		filter = map[string]any{}
	}
	if _, hasState := filter["state"]; !hasState {
		withDefault := make(map[string]any, len(filter)+1)
		withDefault["state"] = map[string]any{"type": map[string]any{"nin": []string{"completed", "canceled"}}}
		for key, value := range filter {
			withDefault[key] = value
		}
		filter = withDefault
	}
	issues := make([]Issue, 0)
	var after any
	for {
		var page struct {
			Project *struct {
				Issues struct {
					Nodes    []Issue `json:"nodes"`
					PageInfo struct {
						HasNextPage bool   `json:"hasNextPage"`
						EndCursor   string `json:"endCursor"`
					} `json:"pageInfo"`
				} `json:"issues"`
			} `json:"project"`
		}
		if err := c.graphql(ctx, `query ProjectIssues($id: String!, $filter: IssueFilter, $first: Int!, $after: String) {
  project(id: $id) { issues(filter: $filter, first: $first, after: $after) {
    nodes { identifier title description url }
    pageInfo { hasNextPage endCursor }
  } }
}`, map[string]any{
			"id": projects.Projects.Nodes[0].ID, "filter": filter, "first": 50, "after": after,
		}, &page); err != nil {
			return nil, err
		}
		if page.Project == nil {
			return nil, fmt.Errorf("Linear project %q was not found or is not accessible", projectName)
		}
		issues = append(issues, page.Project.Issues.Nodes...)
		if !page.Project.Issues.PageInfo.HasNextPage {
			break
		}
		if page.Project.Issues.PageInfo.EndCursor == "" {
			return nil, fmt.Errorf("Linear returned an invalid project issue page")
		}
		after = page.Project.Issues.PageInfo.EndCursor
	}
	if len(issues) == 0 {
		return nil, fmt.Errorf("no open Linear issues matched project %q and its filter", projectName)
	}
	return issues, nil
}

func ParseIssueFilter(input string) (map[string]any, error) {
	if strings.TrimSpace(input) == "" {
		return nil, nil
	}
	var filter map[string]any
	if err := json.Unmarshal([]byte(input), &filter); err != nil || filter == nil {
		return nil, fmt.Errorf("--linear-filter must be a JSON Linear issue filter")
	}
	return filter, nil
}

// ParseIssueReference accepts an issue identifier or a linear.app issue URL.
func ParseIssueReference(input string) (id, workspace string, err error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", "", fmt.Errorf("Linear issue reference cannot be blank")
	}
	if !strings.HasPrefix(strings.ToLower(input), "http://") && !strings.HasPrefix(strings.ToLower(input), "https://") {
		return input, "", nil
	}
	parsed, parseErr := url.Parse(input)
	if parseErr != nil || !strings.EqualFold(parsed.Hostname(), "linear.app") {
		return "", "", fmt.Errorf("Linear issue URL is invalid")
	}
	parts := strings.Split(strings.Trim(parsed.EscapedPath(), "/"), "/")
	if len(parts) < 3 || !strings.EqualFold(parts[1], "issue") {
		return "", "", fmt.Errorf("Linear issue URL is invalid")
	}
	identifier, unescapeErr := url.PathUnescape(parts[2])
	if unescapeErr != nil || !validIdentifier(identifier) {
		return "", "", fmt.Errorf("Linear issue URL is invalid")
	}
	workspace, unescapeErr = url.PathUnescape(parts[0])
	if unescapeErr != nil || strings.TrimSpace(workspace) == "" {
		return "", "", fmt.Errorf("Linear issue URL is invalid")
	}
	return identifier, strings.ToLower(workspace), nil
}

func validIdentifier(value string) bool {
	dash := strings.LastIndexByte(value, '-')
	if dash <= 0 || dash == len(value)-1 {
		return false
	}
	for _, r := range value[:dash] {
		if !(r >= 'A' && r <= 'Z') && !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') {
			return false
		}
	}
	for _, r := range value[dash+1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

type graphqlError struct {
	Message string `json:"message"`
}

func (c *Client) graphql(ctx context.Context, query string, variables map[string]any, destination any) error {
	if c == nil || strings.TrimSpace(c.credential) == "" {
		return fmt.Errorf("Linear authentication is required")
	}
	payload, err := json.Marshal(map[string]any{"query": query, "variables": variables})
	if err != nil {
		return fmt.Errorf("encode Linear request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create Linear request: %w", err)
	}
	authorization := c.credential
	if c.oauth {
		authorization = "Bearer " + c.credential
	}
	request.Header.Set("Authorization", authorization)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return c.safeError("Linear request failed", err)
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseSize+1))
	if readErr != nil {
		return c.safeError("read Linear response", readErr)
	}
	if len(body) > maxResponseSize {
		return fmt.Errorf("Linear response exceeded the size limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		switch response.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return fmt.Errorf("Linear authentication failed")
		case http.StatusTooManyRequests:
			return fmt.Errorf("Linear request was rate limited; wait and retry")
		default:
			return fmt.Errorf("Linear request failed with HTTP %d", response.StatusCode)
		}
	}
	var envelope struct {
		Data   json.RawMessage `json:"data"`
		Errors []graphqlError  `json:"errors"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return fmt.Errorf("decode Linear response: %w", err)
	}
	if len(envelope.Errors) > 0 {
		messages := make([]string, 0, len(envelope.Errors))
		for _, item := range envelope.Errors {
			if message := strings.TrimSpace(item.Message); message != "" {
				messages = append(messages, message)
			}
		}
		if len(messages) == 0 {
			return fmt.Errorf("Linear request failed")
		}
		return c.safeError("Linear request failed", errors.New(strings.Join(messages, "; ")))
	}
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return fmt.Errorf("Linear returned no data")
	}
	if err := json.Unmarshal(envelope.Data, destination); err != nil {
		return fmt.Errorf("decode Linear data: %w", err)
	}
	return nil
}

func (c *Client) safeError(prefix string, err error) error {
	message := err.Error()
	if c != nil && c.credential != "" && strings.Contains(message, c.credential) {
		message = "[redacted]"
	}
	return fmt.Errorf("%s: %s", prefix, message)
}
