import { splitProps, Show, For, createMemo, type ParentProps, type JSX } from "solid-js";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/shared/lib/utils";
import { Label } from "@/shared/ui/label";
import { Separator } from "@/shared/ui/separator";

function FieldSet(
  props: ParentProps<{ class?: string } & JSX.HTMLAttributes<HTMLFieldSetElement>>,
) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <fieldset
      data-slot="field-set"
      class={cn(
        "flex flex-col gap-6",
        "has-[>[data-slot=checkbox-group]]:gap-3 has-[>[data-slot=radio-group]]:gap-3",
        local.class,
      )}
      {...rest}
    />
  );
}

function FieldLegend(
  props: ParentProps<
    {
      class?: string;
      variant?: "legend" | "label";
    } & JSX.HTMLAttributes<HTMLLegendElement>
  >,
) {
  const [local, rest] = splitProps(props, ["class", "variant"]);
  const variant = () => local.variant ?? "legend";
  return (
    <legend
      data-slot="field-legend"
      data-variant={variant()}
      class={cn(
        "mb-3 font-medium",
        "data-[variant=legend]:text-base",
        "data-[variant=label]:text-sm",
        local.class,
      )}
      {...rest}
    />
  );
}

function FieldGroup(props: ParentProps<{ class?: string } & JSX.HTMLAttributes<HTMLDivElement>>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <div
      data-slot="field-group"
      class={cn(
        "group/field-group @container/field-group flex w-full flex-col gap-7 data-[slot=checkbox-group]:gap-3 [&>[data-slot=field-group]]:gap-4",
        local.class,
      )}
      {...rest}
    />
  );
}

const fieldVariants = cva("group/field flex w-full gap-3 data-[invalid=true]:text-destructive", {
  variants: {
    orientation: {
      vertical: ["flex-col [&>*]:w-full [&>.sr-only]:w-auto"],
      horizontal: [
        "flex-row items-center",
        "[&>[data-slot=field-label]]:flex-auto",
        "has-[>[data-slot=field-content]]:items-start has-[>[data-slot=field-content]]:[&>[role=checkbox],[role=radio]]:mt-px",
      ],
      responsive: [
        "flex-col [&>*]:w-full [&>.sr-only]:w-auto @md/field-group:flex-row @md/field-group:items-center @md/field-group:[&>*]:w-auto",
        "@md/field-group:[&>[data-slot=field-label]]:flex-auto",
        "@md/field-group:has-[>[data-slot=field-content]]:items-start @md/field-group:has-[>[data-slot=field-content]]:[&>[role=checkbox],[role=radio]]:mt-px",
      ],
    },
  },
  defaultVariants: {
    orientation: "vertical",
  },
});

function Field(
  props: ParentProps<{ class?: string } & JSX.HTMLAttributes<HTMLDivElement>> &
    VariantProps<typeof fieldVariants>,
) {
  const [local, rest] = splitProps(props, ["class", "orientation"]);
  const orientation = () => local.orientation ?? "vertical";
  return (
    <div
      role="group"
      data-slot="field"
      data-orientation={orientation()}
      class={cn(fieldVariants({ orientation: orientation() }), local.class)}
      {...rest}
    />
  );
}

function FieldContent(props: ParentProps<{ class?: string } & JSX.HTMLAttributes<HTMLDivElement>>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <div
      data-slot="field-content"
      class={cn("group/field-content flex flex-1 flex-col gap-1.5 leading-snug", local.class)}
      {...rest}
    />
  );
}

function FieldLabel(
  props: ParentProps<{ class?: string } & JSX.LabelHTMLAttributes<HTMLLabelElement>>,
) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <Label
      data-slot="field-label"
      class={cn(
        "group/field-label peer/field-label flex w-fit gap-2 leading-snug group-data-[disabled=true]/field:opacity-50",
        "has-[>[data-slot=field]]:w-full has-[>[data-slot=field]]:flex-col has-[>[data-slot=field]]:rounded-md has-[>[data-slot=field]]:border [&>*]:data-[slot=field]:p-4",
        "has-data-[state=checked]:bg-primary/5 has-data-[state=checked]:border-primary dark:has-data-[state=checked]:bg-primary/10",
        local.class,
      )}
      {...rest}
    />
  );
}

function FieldTitle(props: ParentProps<{ class?: string } & JSX.HTMLAttributes<HTMLDivElement>>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <div
      data-slot="field-label"
      class={cn(
        "flex w-fit items-center gap-2 text-sm leading-snug font-medium group-data-[disabled=true]/field:opacity-50",
        local.class,
      )}
      {...rest}
    />
  );
}

function FieldDescription(
  props: ParentProps<{ class?: string } & JSX.HTMLAttributes<HTMLParagraphElement>>,
) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <p
      data-slot="field-description"
      class={cn(
        "text-muted-foreground text-sm leading-normal font-normal group-has-[[data-orientation=horizontal]]/field:text-balance",
        "last:mt-0 nth-last-2:-mt-1 [[data-variant=legend]+&]:-mt-1.5",
        "[&>a:hover]:text-primary [&>a]:underline [&>a]:underline-offset-4",
        local.class,
      )}
      {...rest}
    />
  );
}

function FieldSeparator(
  props: ParentProps<{ class?: string } & JSX.HTMLAttributes<HTMLDivElement>>,
) {
  const [local, rest] = splitProps(props, ["class", "children"]);
  return (
    <div
      data-slot="field-separator"
      data-content={!!local.children}
      class={cn(
        "relative -my-2 h-5 text-sm group-data-[variant=outline]/field-group:-mb-2",
        local.class,
      )}
      {...rest}
    >
      <Separator class="absolute inset-0 top-1/2" />
      <Show when={local.children}>
        <span
          class="bg-background text-muted-foreground relative mx-auto block w-fit px-2"
          data-slot="field-separator-content"
        >
          {local.children}
        </span>
      </Show>
    </div>
  );
}

function FieldError(
  props: ParentProps<
    {
      class?: string;
      errors?: Array<{ message?: string } | undefined>;
    } & JSX.HTMLAttributes<HTMLDivElement>
  >,
) {
  const [local, rest] = splitProps(props, ["class", "children", "errors"]);

  const content = createMemo(() => {
    if (local.children) {
      return local.children;
    }

    if (!local.errors) {
      return null;
    }

    if (local.errors.length === 1 && local.errors[0]?.message) {
      return local.errors[0].message;
    }

    return (
      <ul class="ml-4 flex list-disc flex-col gap-1">
        <For each={local.errors}>
          {(error) => (
            <Show when={error?.message}>
              <li>{error!.message}</li>
            </Show>
          )}
        </For>
      </ul>
    );
  });

  return (
    <Show when={content()}>
      <div
        role="alert"
        data-slot="field-error"
        class={cn("text-destructive text-sm font-normal", local.class)}
        {...rest}
      >
        {content()}
      </div>
    </Show>
  );
}

export {
  Field,
  FieldLabel,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLegend,
  FieldSeparator,
  FieldSet,
  FieldContent,
  FieldTitle,
};
