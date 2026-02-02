import { Link } from '@tanstack/react-router'

export default function Header() {
  return (
    <header className="p-4 flex items-center border-b">
      <h1 className="text-xl font-semibold">
        <Link to="/">RefMD</Link>
      </h1>
    </header>
  )
}
