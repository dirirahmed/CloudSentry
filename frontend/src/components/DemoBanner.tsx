export default function DemoBanner() {
  return (
    <section className="demo-banner" aria-label="About this demo">
      <p>
        <strong>Live demo.</strong> Scans run against a dedicated sandbox AWS account that was set up with a few
        intentional misconfigurations, so there is something to find. Every check is read-only and nothing in the
        account is changed.
      </p>
      <a href="https://github.com/dirirahmed/CloudSentry" target="_blank" rel="noreferrer">
        Source on GitHub
      </a>
    </section>
  );
}
