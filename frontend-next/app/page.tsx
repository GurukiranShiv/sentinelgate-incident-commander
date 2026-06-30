'use client';

import { useState } from 'react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

export default function Page() {
  const [report, setReport] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  async function runDemo() {
    setLoading(true);
    const response = await fetch(`${API}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        incident_type: 'cloud_iam_abuse',
        severity: 'high',
        environment: 'AWS production / hybrid enterprise',
        analyst: 'SOC L2 Cloud Triage',
        affected_assets: ['AWS-Prod', 'IAM-user-backupsvc', 'S3-customer-records'],
        indicators: ['CloudTrail CreateAccessKey', 'AttachUserPolicy', 'unknown source IP', 'S3 ListBuckets'],
        notes: 'GuardDuty alerted on anomalous IAM activity with no approved change ticket.',
      }),
    });
    setReport(await response.json());
    setLoading(false);
  }

  return (
    <main className="shell">
      <section className="hero">
        <p>Next.js optional frontend</p>
        <h1>Evidence-Gated Incident Commander</h1>
        <span>Uses the same FastAPI evidence-gated engine behind the UI.</span>
        <button onClick={runDemo}>{loading ? 'Generating...' : 'Run Cloud IAM Demo'}</button>
      </section>
      {report && (
        <section className="grid">
          <article>
            <h2>{report.incident_type}</h2>
            <p>{report.case_summary.commander_brief}</p>
            <strong>{Math.round(report.playbook_confidence_score * 100)}% playbook confidence</strong>
          </article>
          <article>
            <h2>Evidence-Gated Actions</h2>
            {report.evidence_gated_actions.map((gate: any) => (
              <div className="gate" key={gate.action}>
                <b>{gate.approval_level}</b>
                <span>{gate.action}</span>
                <small>{gate.status}</small>
              </div>
            ))}
          </article>
        </section>
      )}
    </main>
  );
}
