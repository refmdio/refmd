export function AboutSection() {
  return (
    <div class="p-6 space-y-6">
      <div>
        <h3 class="text-lg font-semibold mb-1">RefMD</h3>
        <p class="text-sm text-muted-foreground">End-to-end encrypted markdown editor for teams.</p>
      </div>

      <div class="space-y-4">
        <div>
          <h4 class="text-sm font-medium mb-1">Version</h4>
          <p class="text-sm text-muted-foreground font-mono">2.0.0-dev</p>
        </div>

        <div>
          <h4 class="text-sm font-medium mb-1">License</h4>
          <p class="text-sm text-muted-foreground">GPL-3.0</p>
        </div>

        <div>
          <h4 class="text-sm font-medium mb-1">Source Code</h4>
          <a
            href="https://github.com/refmdio/refmd"
            target="_blank"
            rel="noopener noreferrer"
            class="text-sm text-primary hover:underline"
          >
            github.com/refmdio/refmd
          </a>
        </div>
      </div>

      <div class="pt-4 border-t border-border/60">
        <h4 class="text-sm font-medium mb-2">Security</h4>
        <p class="text-sm text-muted-foreground leading-relaxed">
          RefMD uses end-to-end encryption to protect your documents. Your data is encrypted on your
          device before being sent to the server, and only you and your team members have the keys
          to decrypt it.
        </p>
      </div>
    </div>
  );
}
