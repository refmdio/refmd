export type ViewCreator = (leaf: WorkspaceLeaf) => View;
type ViewAppRef = object;
interface ViewState {
  type: string;
  state?: Record<string, unknown>;
}
export abstract class View {
  app: ViewAppRef | null = null;
  containerEl: HTMLElement;
  icon = "";
  navigation = true;
  leaf: WorkspaceLeaf;
  constructor(leaf: WorkspaceLeaf) {
    this.leaf = leaf;
    this.containerEl = document.createElement("div");
    this.containerEl.classList.add("view-content");
    this.containerEl.style.height = "100%";
    this.containerEl.style.minHeight = "0";
  }
  abstract getViewType(): string;
  abstract getDisplayText(): string;
  async onOpen(): Promise<void> {}
  async onClose(): Promise<void> {}
  getState(): Record<string, unknown> {
    return {};
  }
  async setState(_state: unknown): Promise<void> {}
  getEphemeralState(): Record<string, unknown> {
    return {};
  }
  setEphemeralState(_state: unknown): void {}
  getIcon(): string {
    return this.icon;
  }
  onResize(): void {}
  onPaneMenu(_menu: unknown, _source: string): void {}
}
export abstract class ItemView extends View {
  contentEl: HTMLElement;
  constructor(leaf: WorkspaceLeaf) {
    super(leaf);
    this.contentEl = document.createElement("div");
    this.contentEl.classList.add("view-content-inner");
    this.containerEl.appendChild(this.contentEl);
  }
  addAction(icon: string, title: string, callback: (evt: MouseEvent) => void): HTMLElement {
    const btn = document.createElement("button");
    btn.classList.add("view-action");
    btn.setAttribute("aria-label", title);
    btn.dataset.icon = icon;
    btn.addEventListener("click", callback);
    this.containerEl.prepend(btn);
    return btn;
  }
}
let leafIdCounter = 0;
export class WorkspaceLeaf {
  readonly id: string;
  view!: View;
  private _viewState: ViewState = { type: "" };
  private _detached = false;
  private _viewResolver: ((type: string) => ViewCreator | undefined) | null = null;
  private _appRef: ViewAppRef | null = null;
  private _onViewStateChange: ((leaf: WorkspaceLeaf) => void) | null = null;
  constructor(id?: string) {
    this.id = id ?? `leaf-${Date.now()}-${++leafIdCounter}`;
  }
  setViewResolver(resolver: (type: string) => ViewCreator | undefined): void {
    this._viewResolver = resolver;
  }
  setAppRef(app: ViewAppRef): void {
    this._appRef = app;
  }
  setOnViewStateChange(cb: (leaf: WorkspaceLeaf) => void): void {
    this._onViewStateChange = cb;
  }
  async open(view: View): Promise<View> {
    if (this.view) {
      await this.view.onClose();
    }
    this.view = view;
    view.app = this._appRef;
    this._viewState = { type: view.getViewType() };
    await view.onOpen();
    return view;
  }
  getViewState(): ViewState {
    return {
      ...this._viewState,
      state: this.view?.getState(),
    };
  }
  async setViewState(state: ViewState): Promise<void> {
    this._viewState = { ...state };
    if (state.type && (!this.view || this.view.getViewType() !== state.type)) {
      const creator = this._viewResolver?.(state.type);
      if (creator) {
        if (this.view) await this.view.onClose();
        const view = creator(this);
        view.app = this._appRef;
        this.view = view;
        await view.onOpen();
      }
    }
    if (this.view && state.state) {
      await this.view.setState(state.state);
    }
    this._onViewStateChange?.(this);
  }
  detach(): void {
    if (this._detached) return;
    this._detached = true;
    if (this.view) {
      this.view.onClose();
      this.view.containerEl.remove();
    }
  }
  get isDetached(): boolean {
    return this._detached;
  }
  getDisplayText(): string {
    return this.view?.getDisplayText() ?? "";
  }
  getIcon(): string {
    return this.view?.getIcon() ?? "";
  }
  onResize(): void {
    this.view?.onResize();
  }
}
