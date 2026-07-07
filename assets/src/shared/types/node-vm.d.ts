declare module "node:vm" {
  export class Script {
    constructor(code: string);
    runInContext(context: object): unknown;
  }

  export function createContext(contextObject: object): object;
}
