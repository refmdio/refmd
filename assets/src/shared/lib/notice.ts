import { toast } from "solid-sonner";

const DEFAULT_DURATION = 5000;

export class Notice {
  containerEl: HTMLElement;
  messageEl: HTMLElement;
  private toastId: string | number;

  constructor(message: string | DocumentFragment, duration?: number) {
    this.containerEl = document.createElement("div");
    this.messageEl = document.createElement("div");
    this.containerEl.appendChild(this.messageEl);
    this.applyMessage(message);

    const d = duration ?? DEFAULT_DURATION;
    this.toastId = toast(this.currentText(), {
      duration: d === 0 ? Infinity : d,
    });
  }

  setMessage(message: string | DocumentFragment): this {
    this.applyMessage(message);
    toast(this.currentText(), {
      id: this.toastId,
    });
    return this;
  }

  hide(): void {
    toast.dismiss(this.toastId);
  }

  private applyMessage(message: string | DocumentFragment): void {
    this.messageEl.textContent = "";
    if (typeof message === "string") {
      this.messageEl.textContent = message;
    } else {
      this.messageEl.appendChild(message);
    }
  }

  private currentText(): string {
    return this.messageEl.textContent ?? "";
  }
}
