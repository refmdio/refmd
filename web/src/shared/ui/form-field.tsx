import { Label } from '@/shared/ui/label'
import { Input } from '@/shared/ui/input'

interface FormFieldProps {
  id: string
  label: string
  type?: string
  placeholder?: string
  value: string
  onChange: (value: string) => void
  required?: boolean
  disabled?: boolean
  autoComplete?: string
}

export function FormField({
  id,
  label,
  type = 'text',
  placeholder,
  value,
  onChange,
  required,
  disabled,
  autoComplete,
}: FormFieldProps) {
  return (
    <div className="space-y-2">
      <Label htmlFor={id}>{label}</Label>
      <Input
        id={id}
        type={type}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        required={required}
        disabled={disabled}
        autoComplete={autoComplete}
      />
    </div>
  )
}
