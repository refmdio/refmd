export class StatusBarState {
  private container: HTMLElement | null = null;
  private pendingItems: HTMLElement[] = [];

  reset(): void {
    if (this.container) {
      this.container.replaceChildren();
    }
    this.pendingItems = [];
  }

  setContainer(element: HTMLElement | null): void {
    this.container = element;
    if (!element) return;

    for (const item of this.pendingItems) {
      element.appendChild(item);
    }
    this.pendingItems = [];
  }

  addItem(): HTMLElement {
    const item = document.createElement("span");
    item.classList.add("status-bar-item");

    if (this.container) {
      this.container.appendChild(item);
    } else {
      this.pendingItems.push(item);
    }

    return item;
  }
}
