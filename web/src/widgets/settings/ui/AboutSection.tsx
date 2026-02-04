/**
 * About Section
 *
 * Information about RefMD.
 */

export function AboutSection() {
  return (
    <div className="p-6 space-y-6">
      <div>
        <h3 className="text-lg font-semibold mb-1">RefMD</h3>
        <p className="text-sm text-muted-foreground">
          End-to-end encrypted markdown editor for teams.
        </p>
      </div>

      <div className="space-y-4">
        <div>
          <h4 className="text-sm font-medium mb-1">Version</h4>
          <p className="text-sm text-muted-foreground font-mono">0.1.0</p>
        </div>

        <div>
          <h4 className="text-sm font-medium mb-1">License</h4>
          <p className="text-sm text-muted-foreground">GPL-3.0</p>
        </div>

        <div>
          <h4 className="text-sm font-medium mb-1">Source Code</h4>
          <a
            href="https://github.com/refmdio/refmd"
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-primary hover:underline"
          >
            github.com/refmdio/refmd
          </a>
        </div>
      </div>

      <div className="pt-4 border-t border-border/60">
        <h4 className="text-sm font-medium mb-2">Security</h4>
        <p className="text-sm text-muted-foreground leading-relaxed">
          RefMD uses end-to-end encryption to protect your documents.
          Your data is encrypted on your device before being sent to the server,
          and only you and your team members have the keys to decrypt it.
        </p>
      </div>
    </div>
  )
}
