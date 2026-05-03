import { toast } from "solid-sonner";

interface ActiveNotice {
  refCount: number;
  message: string;
  description?: string;
}

const activeNotices = new Map<string, ActiveNotice>();

export function retainUxLimitNotice(id: string, message: string, description?: string): () => void {
  const existing = activeNotices.get(id);
  if (existing) {
    existing.refCount += 1;
    if (existing.message !== message || existing.description !== description) {
      existing.message = message;
      existing.description = description;
      toast.warning(message, { id, description, duration: Infinity });
    }
  } else {
    activeNotices.set(id, { refCount: 1, message, description });
    toast.warning(message, { id, description, duration: Infinity });
  }

  let released = false;
  return () => {
    if (released) return;
    released = true;
    const notice = activeNotices.get(id);
    if (!notice) return;
    notice.refCount -= 1;
    if (notice.refCount > 0) return;
    activeNotices.delete(id);
    toast.dismiss(id);
  };
}

export function notifyUxLimitResolved(message: string, id?: string): void {
  toast.success(message, { id, duration: 3500 });
}
