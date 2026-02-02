import { createFileRoute } from '@tanstack/react-router'

export const Route = createFileRoute('/')({ component: Home })

function Home() {
  return (
    <main className="min-h-screen bg-gradient-to-b from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center">
      <div className="text-center">
        <h1 className="text-4xl font-bold text-white mb-4">RefMD</h1>
        <p className="text-gray-400">
          End-to-end encrypted collaborative Markdown editor
        </p>
      </div>
    </main>
  )
}
