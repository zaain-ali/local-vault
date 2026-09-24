package email

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
)

// Embed the templates/ folder into the binary at build time - no files to ship.
//go:embed templates/*.html
var templateFS embed.FS

// emailTemplate pairs in email's subject with it's content template file.
type emailTemplate struct {
	subject		string
	file 		string
}

// register is the single source of truth: each kind -> its subject + template
// Add an email = one row here + one .html file. That is the "centralized subject".
var registry = map[EmailKind]emailTemplate{
	KindWorkspaceInvite: {
		subject: "You've been invited to a LocalVault workspace",
		file: "invite.html",
	},
	KindVaultCollaboratorInvite: {
		subject: "You've been given access to a LocalVault vault",
		file: "vault_collaborator_invite.html",
	},
}

// Renderer holds one parsed template set per kind (base.html + that kind's content).
type Renderer struct {
	templates map[EmailKind]*template.Template
}

// NewRenderer parses every registered template once, at startup.
func NewRenderer() (*Renderer, error) {
	fmt.Print(templateFS)
	templates := make(map[EmailKind]*template.Template)
	
	for kind, meta := range registry {
		t, err := template.ParseFS(templateFS, "templates/base.html", "templates/"+meta.file)

		if err != nil {
			return nil, fmt.Errorf("parse template for %s: %w", kind, err)
		}
		templates[kind] = t
	}

	return &Renderer{templates: templates}, nil
}

// Render returns the subject + rendered HTML for a job, or an error for an unknown kind.
func (r *Renderer) Render(job EmailJob) (subject, html string, err error) {
	meta, ok := registry[job.Kind] // unknown kind = malformed message, not a panic
	if !ok {
		return "", "", fmt.Errorf("unknown email kind: %s", job.Kind)
	}
	var buf bytes.Buffer
	// Execute base.html; where it has {{block "content"}} it runs the child's {{define "content"}}.
	if err := r.templates[job.Kind].ExecuteTemplate(&buf, "base.html", job); err != nil {
		return "", "", fmt.Errorf("render %s: %w", job.Kind, err)
	}
	return meta.subject, buf.String(), nil
}
