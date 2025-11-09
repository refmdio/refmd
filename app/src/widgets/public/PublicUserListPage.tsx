import PublicShell from '@/widgets/public/PublicShell'

import { PublicDocCard } from '@/features/public'

type Summary = { id: string; title: string; updated_at: string; published_at: string }

type Props = {
  name: string
  items: Summary[]
}

export default function PublicUserListPage({ name, items }: Props) {
  const total = items.length
  const subtitle = `${total} public ${total === 1 ? 'document' : 'documents'}`
  return (
    <PublicShell pageType="list" title={`@${name}`} subtitle={subtitle} author={{ name }}>
      <section className="space-y-8">
        <div className="flex flex-col justify-between gap-3 rounded-2xl border border-border/70 bg-card/80 px-6 py-5 text-sm text-muted-foreground shadow-sm md:flex-row md:items-center">
          <div className="space-y-1">
            <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground/80">Overview</p>
            <p>
              {total === 0
                ? `@${name} has not published any documents yet.`
                : `Displaying ${total} publicly shared ${total === 1 ? 'document' : 'documents'} from @${name}.`}
            </p>
          </div>
          {total > 0 && (
            <p className="text-xs text-muted-foreground/70">Sorted by most recently updated first.</p>
          )}
        </div>

        {items.length === 0 ? (
          <div className="rounded-3xl border border-dashed border-muted-foreground/30 bg-background/80 p-12 text-center text-muted-foreground">
            <p className="text-base font-medium text-foreground">Nothing public just yet</p>
            <p className="mt-2 text-sm">
              When {`@${name}`} publishes documents, they will appear here with live updates.
            </p>
          </div>
        ) : (
          <div className="grid gap-5 sm:grid-cols-2">
            {items.map((doc) => (
              <PublicDocCard
                key={doc.id}
                href={`/u/${encodeURIComponent(name)}/${doc.id}`}
                title={doc.title}
                publishedAt={doc.published_at}
                updatedAt={doc.updated_at}
              />
            ))}
          </div>
        )}
      </section>
    </PublicShell>
  )
}
