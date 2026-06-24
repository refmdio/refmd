export function shouldRenderEditorPane(width: string, keepMounted: boolean) {
  return width !== '0%' || keepMounted
}
