import { FormField } from '@/shared/ui/form-field'

interface AuthFieldProps {
  value: string
  onChange: (value: string) => void
  disabled?: boolean
}

export function EmailField({ value, onChange, disabled }: AuthFieldProps) {
  return (
    <FormField
      id="email"
      label="Email"
      type="email"
      placeholder="you@example.com"
      value={value}
      onChange={onChange}
      required
      disabled={disabled}
      autoComplete="email"
    />
  )
}

export function PasswordField({
  value,
  onChange,
  disabled,
  autoComplete = 'current-password',
  label = 'Password',
  id = 'password',
}: AuthFieldProps & { autoComplete?: string; label?: string; id?: string }) {
  return (
    <FormField
      id={id}
      label={label}
      type="password"
      placeholder="••••••••"
      value={value}
      onChange={onChange}
      required
      disabled={disabled}
      autoComplete={autoComplete}
    />
  )
}
