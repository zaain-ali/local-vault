package machine

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func verifyAWS(client *http.Client, proof *AWSLoginProof, spec *AWSSpec, serverID string) bool {
	if proof == nil || spec == nil || spec.RoleARN == "" {
		return false
	}
	u, err := url.Parse(proof.URL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Host)
	if host != "sts.amazonaws.com" && !strings.HasPrefix(host, "sts.") || !strings.HasSuffix(host, ".amazonaws.com") && host != "sts.amazonaws.com" {
		if host != "sts.amazonaws.com" && !(strings.HasPrefix(host, "sts.") && strings.HasSuffix(host, ".amazonaws.com")) {
			return false
		}
	}
	if serverID == "" {
		serverID = "localvault"
	}
	got := ""
	if proof.Headers != nil {
		for _, v := range proof.Headers["X-Lv-Server-Id"] {
			got = v
		}
		if got == "" {
			for _, v := range proof.Headers["x-lv-server-id"] {
				got = v
			}
		}
	}
	if got != serverID {
		return false
	}
	method := proof.Method
	if method == "" {
		method = http.MethodPost
	}
	req, err := http.NewRequest(method, proof.URL, strings.NewReader(proof.Body))
	if err != nil {
		return false
	}
	for k, vs := range proof.Headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false
	}
	body, _ := io.ReadAll(resp.Body)
	arn := extractAssumedRoleARN(body)
	return roleMatches(spec.RoleARN, arn)
}

func extractAssumedRoleARN(body []byte) string {
	var doc struct {
		ARN string `xml:"GetCallerIdentityResult>Arn"`
	}
	if xml.Unmarshal(body, &doc) == nil && doc.ARN != "" {
		return doc.ARN
	}
	// fallback: scan for arn:aws:sts
	s := string(body)
	const pfx = "arn:aws:sts::"
	i := strings.Index(s, pfx)
	if i < 0 {
		return ""
	}
	end := i
	for end < len(s) && s[end] != '<' && s[end] != '"' && s[end] != ' ' && s[end] != '\n' {
		end++
	}
	return s[i:end]
}

func roleMatches(wantRole, assumed string) bool {
	// want: arn:aws:iam::ACCT:role[/path]/NAME
	// got:  arn:aws:sts::ACCT:assumed-role/NAME/session
	want := strings.TrimSpace(wantRole)
	got := strings.TrimSpace(assumed)
	if want == "" || got == "" {
		return false
	}
	wParts := strings.Split(want, ":")
	gParts := strings.Split(got, ":")
	if len(wParts) < 6 || len(gParts) < 6 {
		return false
	}
	if wParts[4] != gParts[4] { // account
		return false
	}
	wName := wParts[5]
	wName = strings.TrimPrefix(wName, "role/")
	if i := strings.LastIndex(wName, "/"); i >= 0 {
		wName = wName[i+1:]
	}
	gRest := gParts[5]
	gRest = strings.TrimPrefix(gRest, "assumed-role/")
	gName, _, _ := strings.Cut(gRest, "/")
	return wName != "" && wName == gName
}
