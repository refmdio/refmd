export interface EventRef {
  readonly _brand: "EventRef";
}

interface EventEntry {
  id: number;
  name: string;
  callback: (...data: unknown[]) => unknown;
  ctx: unknown;
}

let nextEventId = 0;

export class Events {
  private _events = new Map<string, Set<EventEntry>>();

  on(name: string, callback: (...data: unknown[]) => unknown, ctx?: unknown): EventRef {
    const entry: EventEntry = {
      id: nextEventId++,
      name,
      callback,
      ctx: ctx ?? null,
    };
    let set = this._events.get(name);
    if (!set) {
      set = new Set();
      this._events.set(name, set);
    }
    set.add(entry);
    return entry as unknown as EventRef;
  }

  off(name: string, callback: (...data: unknown[]) => unknown): void {
    const set = this._events.get(name);
    if (!set) return;
    for (const entry of set) {
      if (entry.callback === callback) {
        set.delete(entry);
        break;
      }
    }
    if (set.size === 0) this._events.delete(name);
  }

  offref(ref: EventRef): void {
    const entry = ref as unknown as EventEntry;
    const set = this._events.get(entry.name);
    if (!set) return;
    set.delete(entry);
    if (set.size === 0) this._events.delete(entry.name);
  }

  trigger(name: string, ...data: unknown[]): void {
    const set = this._events.get(name);
    if (!set) return;
    for (const entry of set) {
      if (entry.ctx) {
        entry.callback.call(entry.ctx, ...data);
      } else {
        entry.callback(...data);
      }
    }
  }

  tryTrigger(name: string, ...data: unknown[]): void {
    const set = this._events.get(name);
    if (!set) return;
    for (const entry of set) {
      try {
        if (entry.ctx) {
          entry.callback.call(entry.ctx, ...data);
        } else {
          entry.callback(...data);
        }
      } catch {
        // swallow errors from listeners
      }
    }
  }
}
