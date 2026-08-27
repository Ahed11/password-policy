package report

import (
	"bytes"
	"fmt"
	"html/template"
)

const auditHTMLTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Password Policy Audit Report</title>
  <style>
    body {
      font-family: sans-serif;
      max-width: 1100px;
      margin: 40px auto;
      padding: 0 20px;
      color: #222;
    }

    h1, h2 {
      margin-bottom: 12px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 32px;
    }

    th, td {
      padding: 8px 10px;
      border: 1px solid #ccc;
      text-align: left;
      vertical-align: top;
    }

    th {
      background: #f3f3f3;
    }

    .passed {
      font-weight: bold;
    }

    .failed {
      font-weight: bold;
    }

    .rules {
      margin: 0;
      padding-left: 20px;
    }
  </style>
</head>
<body>
  <h1>Password Policy Audit Report</h1>

  <p>
    <strong>Report version:</strong> {{.ReportVersion}}<br>
    <strong>Policy:</strong> {{.Policy}}
  </p>

  <h2>Totals</h2>

  <table>
    <thead>
      <tr>
        <th>Checked</th>
        <th>Passed</th>
        <th>Failed</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>{{.Totals.Checked}}</td>
        <td>{{.Totals.Passed}}</td>
        <td>{{.Totals.Failed}}</td>
      </tr>
    </tbody>
  </table>

  <h2>Violations</h2>

  {{if .Violations}}
  <table>
    <thead>
      <tr>
        <th>Rule</th>
        <th>Count</th>
      </tr>
    </thead>
    <tbody>
      {{range .Violations}}
      <tr>
        <td>{{.Rule}}</td>
        <td>{{.Count}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
  {{else}}
  <p>No violations.</p>
  {{end}}

  <h2>Subjects</h2>

  {{if .Subjects}}
  <table>
    <thead>
      <tr>
        <th>Subject</th>
        <th>Status</th>
        <th>Rules</th>
      </tr>
    </thead>
    <tbody>
      {{range .Subjects}}
      <tr>
        <td>{{.Subject}}</td>
        <td>
          {{if .Passed}}
          <span class="passed">passed</span>
          {{else}}
          <span class="failed">failed</span>
          {{end}}
        </td>
        <td>
          {{if .Rules}}
          <ul class="rules">
            {{range .Rules}}
            <li>{{.}}</li>
            {{end}}
          </ul>
          {{else}}
          —
          {{end}}
        </td>
      </tr>
      {{end}}
    </tbody>
  </table>
  {{else}}
  <p>No subjects.</p>
  {{end}}
</body>
</html>
`

func MarshalHTML(report AuditReport) ([]byte, error) {
	tmpl, err := template.New("audit-report").Parse(auditHTMLTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse audit report HTML template: %w", err)
	}

	var buffer bytes.Buffer

	if err := tmpl.Execute(&buffer, report); err != nil {
		return nil, fmt.Errorf("execute audit report HTML template: %w", err)
	}

	if buffer.Len() == 0 ||
		buffer.Bytes()[buffer.Len()-1] != '\n' {
		buffer.WriteByte('\n')
	}

	return buffer.Bytes(), nil
}
