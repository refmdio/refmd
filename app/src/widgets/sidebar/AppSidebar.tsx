import FileTree from '@/widgets/sidebar/FileTree'

export default function AppSidebar() {
  return (
    <div className="flex h-full flex-col gap-4 py-5 sm:py-6">
      <FileTree />
    </div>
  )
}
