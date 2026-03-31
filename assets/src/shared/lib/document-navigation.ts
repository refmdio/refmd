export class DocumentNavigation {
  private navigateToDocumentFn: ((id: string) => void) | null = null;

  init(navigateToDocumentFn: (id: string) => void): void {
    this.navigateToDocumentFn = navigateToDocumentFn;
  }

  openDocument(id: string): void {
    this.navigateToDocumentFn?.(id);
  }
}

export const documentNavigation = new DocumentNavigation();
