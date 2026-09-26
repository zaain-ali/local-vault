package email

import (
	"strings"
	"testing"
)

func TestRenderer_RendersAllKinds(t *testing.T) {
	r, err := NewRenderer()
	if err != nil {
		t.Fatalf("NewRenderer: %v", err)
	}

	jobs := []EmailJob{
		{Kind: KindWorkspaceInvite, Name: "Acme", URL: "https://app.example.com/invite?t=abc"},
		{Kind: KindVaultCollaboratorInvite, Name: "prod-vault", Inviter: "Alex", Envs: "development, staging"},
	}

	for _, job := range jobs {
		t.Run(string(job.Kind), func(t *testing.T) {
			subj, html, err := r.Render(job)
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			if subj == "" {
				t.Fatal("empty subject")
			}
			if !strings.Contains(html, "LocalVault") {
				t.Fatal("missing LocalVault brand")
			}
			if !strings.Contains(html, "#e5b567") {
				t.Fatal("missing gold accent")
			}
			if !strings.Contains(html, "#1a1815") {
				t.Fatal("missing dark card surface")
			}
			if job.URL != "" && !strings.Contains(html, job.URL) {
				t.Fatal("missing URL")
			}
			if job.Kind == KindVaultCollaboratorInvite {
				want := "Alex gave you access to vault prod-vault (development, staging)"
				if !strings.Contains(strings.Join(strings.Fields(html), " "), want) {
					t.Fatalf("missing %q", want)
				}
				if !strings.Contains(html, "lv link") {
					t.Fatal("missing lv link instruction")
				}
			}
		})
	}
}
