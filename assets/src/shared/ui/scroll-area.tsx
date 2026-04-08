import {
  Show,
  children,
  createContext,
  createEffect,
  createMemo,
  createSignal,
  onCleanup,
  splitProps,
  useContext,
  type Accessor,
  type JSX,
  type ParentProps,
} from "solid-js";

import { cn } from "@/shared/lib/utils";

type ScrollMetrics = {
  clientHeight: number;
  clientWidth: number;
  scrollHeight: number;
  scrollLeft: number;
  scrollTop: number;
  scrollWidth: number;
};

type ScrollAreaContextValue = {
  metrics: Accessor<ScrollMetrics>;
  viewport: Accessor<HTMLDivElement | undefined>;
};

const defaultMetrics: ScrollMetrics = {
  clientHeight: 0,
  clientWidth: 0,
  scrollHeight: 0,
  scrollLeft: 0,
  scrollTop: 0,
  scrollWidth: 0,
};

const ScrollAreaContext = createContext<ScrollAreaContextValue>({
  metrics: () => defaultMetrics,
  viewport: () => undefined,
});

function flattenChildren(value: unknown): unknown[] {
  if (Array.isArray(value)) {
    return value.flatMap(flattenChildren);
  }

  return value == null || value === false ? [] : [value];
}

function isScrollAreaAdornment(value: unknown) {
  return (
    typeof Element !== "undefined" &&
    value instanceof Element &&
    (value.getAttribute("data-slot") === "scroll-area-scrollbar" ||
      value.getAttribute("data-slot") === "scroll-area-corner")
  );
}

function ScrollArea(props: ParentProps<{ class?: string } & JSX.HTMLAttributes<HTMLDivElement>>) {
  const [local, rest] = splitProps(props, ["class", "children"]);
  const resolvedChildren = children(() => local.children);
  const nodes = createMemo(() => flattenChildren(resolvedChildren()));
  const viewportChildren = createMemo(() => nodes().filter((node) => !isScrollAreaAdornment(node)));
  const adornments = createMemo(() => nodes().filter((node) => isScrollAreaAdornment(node)));
  const [metrics, setMetrics] = createSignal(defaultMetrics);
  const [viewportRef, setViewportRef] = createSignal<HTMLDivElement>();

  createEffect(() => {
    const viewport = viewportRef();
    if (!viewport) return;

    const updateMetrics = () => {
      setMetrics({
        clientHeight: viewport.clientHeight,
        clientWidth: viewport.clientWidth,
        scrollHeight: viewport.scrollHeight,
        scrollLeft: viewport.scrollLeft,
        scrollTop: viewport.scrollTop,
        scrollWidth: viewport.scrollWidth,
      });
    };

    updateMetrics();

    const onScroll = () => updateMetrics();
    viewport.addEventListener("scroll", onScroll, { passive: true });

    const resizeObserver = new ResizeObserver(() => updateMetrics());
    resizeObserver.observe(viewport);

    const content = viewport.firstElementChild;
    if (content) {
      resizeObserver.observe(content);
    }

    onCleanup(() => {
      viewport.removeEventListener("scroll", onScroll);
      resizeObserver.disconnect();
    });
  });

  const hasVerticalScrollbar = createMemo(() =>
    adornments().some(
      (node) => node instanceof Element && node.getAttribute("data-orientation") === "vertical",
    ),
  );

  const hasCorner = createMemo(() =>
    adornments().some(
      (node) => node instanceof Element && node.getAttribute("data-slot") === "scroll-area-corner",
    ),
  );

  const showCorner = createMemo(() => {
    const current = metrics();
    return current.scrollHeight > current.clientHeight && current.scrollWidth > current.clientWidth;
  });

  return (
    <ScrollAreaContext.Provider value={{ metrics, viewport: viewportRef }}>
      <div data-slot="scroll-area" class={cn("relative overflow-hidden", local.class)} {...rest}>
        <div
          ref={setViewportRef}
          data-slot="scroll-area-viewport"
          class="focus-visible:ring-ring/50 size-full overflow-auto rounded-[inherit] transition-[color,box-shadow] outline-none focus-visible:ring-[3px] focus-visible:outline-1 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden"
        >
          <div>{viewportChildren() as unknown as JSX.Element}</div>
        </div>
        <Show when={!hasVerticalScrollbar()}>
          <ScrollBar />
        </Show>
        {adornments() as unknown as JSX.Element}
        <Show when={showCorner() && !hasCorner()}>
          <div
            data-slot="scroll-area-corner"
            class="bg-background absolute right-0 bottom-0 size-2.5"
          />
        </Show>
      </div>
    </ScrollAreaContext.Provider>
  );
}

function ScrollBar(
  props: ParentProps<
    {
      class?: string;
      orientation?: "vertical" | "horizontal";
    } & JSX.HTMLAttributes<HTMLDivElement>
  >,
) {
  const [local, rest] = splitProps(props, ["class", "orientation"]);
  const context = useContext(ScrollAreaContext);
  const orientation = () => local.orientation ?? "vertical";
  const isVertical = () => orientation() === "vertical";

  const isVisible = createMemo(() => {
    const current = context.metrics();
    return isVertical()
      ? current.scrollHeight > current.clientHeight
      : current.scrollWidth > current.clientWidth;
  });

  const thumbStyle = createMemo<JSX.CSSProperties>(() => {
    const current = context.metrics();

    if (!isVisible()) {
      return {};
    }

    if (isVertical()) {
      const trackSize = current.clientHeight;
      const ratio = current.clientHeight / current.scrollHeight;
      const thumbSize = Math.max(trackSize * ratio, 20);
      const maxOffset = trackSize - thumbSize;
      const scrollable = current.scrollHeight - current.clientHeight;
      const offset = scrollable > 0 ? (current.scrollTop / scrollable) * maxOffset : 0;

      return {
        height: `${thumbSize}px`,
        transform: `translateY(${offset}px)`,
      };
    }

    const trackSize = current.clientWidth;
    const ratio = current.clientWidth / current.scrollWidth;
    const thumbSize = Math.max(trackSize * ratio, 20);
    const maxOffset = trackSize - thumbSize;
    const scrollable = current.scrollWidth - current.clientWidth;
    const offset = scrollable > 0 ? (current.scrollLeft / scrollable) * maxOffset : 0;

    return {
      width: `${thumbSize}px`,
      transform: `translateX(${offset}px)`,
    };
  });

  return (
    <Show when={isVisible()}>
      <div
        data-slot="scroll-area-scrollbar"
        data-orientation={orientation()}
        class={cn(
          "absolute z-10 flex touch-none p-px transition-colors select-none",
          isVertical() && "top-0 right-0 h-full w-2.5 border-l border-l-transparent",
          !isVertical() && "right-0 bottom-0 left-0 h-2.5 flex-col border-t border-t-transparent",
          local.class,
        )}
        {...rest}
      >
        <div
          data-slot="scroll-area-thumb"
          class="bg-border relative flex-1 rounded-full"
          style={thumbStyle()}
        />
      </div>
    </Show>
  );
}

export { ScrollArea, ScrollBar };
