import type { RequestHandlerTable } from "./shared";
import { documentRequestHandlers } from "./document";
import { kekRequestHandlers } from "./kek";
import { keyRequestHandlers } from "./keys";
import { lifecycleRequestHandlers } from "./lifecycle";
import { signingRequestHandlers } from "./signing";
import { trustRequestHandlers } from "./trust";

export const requestHandlers = {
  ...lifecycleRequestHandlers,
  ...keyRequestHandlers,
  ...documentRequestHandlers,
  ...kekRequestHandlers,
  ...signingRequestHandlers,
  ...trustRequestHandlers,
} satisfies RequestHandlerTable;
