import { toast } from "solid-sonner";

const DEFAULT_DURATION = 5000;

export class Notice {
  private toastId: string | number;

  constructor(message: string, duration?: number) {
    const d = duration ?? DEFAULT_DURATION;
    this.toastId = toast(message, {
      duration: d === 0 ? Infinity : d,
    });
  }

  setMessage(message: string): this {
    toast(message, { id: this.toastId });
    return this;
  }

  hide(): void {
    toast.dismiss(this.toastId);
  }
}
