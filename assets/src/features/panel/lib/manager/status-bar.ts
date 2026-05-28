import type {
  StatusBarItemConfig,
  WorkspaceSurfaceOwner,
  WorkspaceSurfaceOwnerPredicate,
} from "@/shared/lib/workspace/app";

const statusBarItemOwners = new WeakMap<HTMLElement, StatusBarItemConfig["owner"]>();

export class StatusBarState {
  private container: HTMLElement | null = null;
  private pendingItems: HTMLElement[] = [];
  private items: { element: HTMLElement; owner?: WorkspaceSurfaceOwner }[] = [];

  reset(): void {
    if (this.container) {
      this.container.replaceChildren();
    }
    this.pendingItems = [];
    this.items = [];
  }

  setContainer(element: HTMLElement | null): void {
    this.container = element;
    if (!element) return;

    for (const item of this.items) {
      element.appendChild(item.element);
    }
    this.pendingItems = [];
  }

  addItem(config: StatusBarItemConfig = {}): HTMLElement {
    const item = document.createElement("span");
    const record = { element: item, owner: config.owner };
    const remove = item.remove.bind(item);
    item.remove = () => {
      this.items = this.items.filter((candidate) => candidate !== record);
      this.pendingItems = this.pendingItems.filter((candidate) => candidate !== item);
      remove();
    };
    item.classList.add("status-bar-item");
    if (config.label) item.setAttribute("aria-label", config.label);
    if (config.owner) {
      statusBarItemOwners.set(item, config.owner);
    }
    this.items.push(record);

    if (this.container) {
      this.container.appendChild(item);
    } else {
      this.pendingItems.push(item);
    }

    return item;
  }

  removeByOwner(predicate: WorkspaceSurfaceOwnerPredicate): void {
    const remaining: { element: HTMLElement; owner?: WorkspaceSurfaceOwner }[] = [];
    for (const item of this.items) {
      if (item.owner && predicate(item.owner)) {
        item.element.remove();
      } else {
        remaining.push(item);
      }
    }
    this.items = remaining;
    this.pendingItems = this.pendingItems.filter((element) =>
      remaining.some((item) => item.element === element),
    );
  }
}
