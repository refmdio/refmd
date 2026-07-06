export function hasCanonicalLocalChanges(params: {
  savedText: string | null;
  liveText: string;
  serverText: string;
}): boolean {
  if (params.savedText !== null) return params.liveText !== params.savedText;
  return params.liveText.length > 0 && params.liveText !== params.serverText;
}
