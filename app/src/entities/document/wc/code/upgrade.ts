const COPY_ICON = '<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"></rect><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"></path></svg>'
const CHECK_ICON = '<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"></path></svg>'
const ALERT_ICON = '<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m10.29 3.86-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.71-3l-8-14a2 2 0 0 0-3.42 0"></path><line x1="12" x2="12" y1="9" y2="13"></line><line x1="12" x2="12.01" y1="17" y2="17"></line></svg>'

function attachCopyButton(container: HTMLElement, pre: HTMLElement) {
  const code = pre.querySelector('code') as HTMLElement | null
  const textSource = code ?? pre
  const button = document.createElement('button')
  button.type = 'button'
  button.className = 'code-copy-button'
  button.setAttribute('aria-label', 'Copy code block')
  button.setAttribute('data-state', 'idle')
  button.innerHTML = COPY_ICON
  container.appendChild(button)

  let resetTimer: number | null = null
  const resetState = () => {
    button.classList.remove('copied', 'copy-failed')
    button.setAttribute('data-state', 'idle')
    button.innerHTML = COPY_ICON
    resetTimer = null
  }

  const copyHandler = async () => {
    const text = textSource.textContent || ''
    const attemptClipboardWrite = async () => {
      if (navigator.clipboard?.writeText) {
        try {
          await navigator.clipboard.writeText(text)
          return true
        } catch {}
      }
      const textarea = document.createElement('textarea')
      textarea.value = text
      textarea.setAttribute('readonly', '')
      textarea.style.position = 'absolute'
      textarea.style.left = '-9999px'
      document.body.appendChild(textarea)
      const selection = document.getSelection()
      const currentRange = selection?.rangeCount ? selection.getRangeAt(0) : null
      textarea.select()
      let success = false
      try { success = document.execCommand('copy') } catch { success = false }
      textarea.remove()
      if (currentRange && selection) {
        selection.removeAllRanges()
        selection.addRange(currentRange)
      }
      return success
    }

    const copied = await attemptClipboardWrite()
    if (!copied) {
      button.classList.add('copy-failed')
      button.setAttribute('data-state', 'error')
      button.innerHTML = ALERT_ICON
      if (resetTimer) window.clearTimeout(resetTimer)
      resetTimer = window.setTimeout(() => {
        button.classList.remove('copy-failed')
        resetState()
      }, 2000)
      return
    }

    button.classList.remove('copy-failed')
    button.classList.add('copied')
    button.setAttribute('data-state', 'copied')
    button.innerHTML = CHECK_ICON
    if (resetTimer) window.clearTimeout(resetTimer)
    resetTimer = window.setTimeout(resetState, 2000)
  }

  button.addEventListener('click', copyHandler)
  return () => {
    if (resetTimer) window.clearTimeout(resetTimer)
    button.removeEventListener('click', copyHandler)
    if (button.parentElement === container) {
      container.removeChild(button)
    }
  }
}

export function upgradeCodeBlocks(root: Element) {
  const cleanupFns: Array<() => void> = []
  const pres = Array.from(root.querySelectorAll('pre')) as HTMLElement[]

  for (const pre of pres) {
    const parentNode = pre.parentNode as (Element | DocumentFragment | null)
    let container = (pre.parentElement?.classList.contains('code-copy-container')
      ? (pre.parentElement as HTMLElement)
      : null)

    if (!container) {
      container = document.createElement('div')
      container.className = 'code-copy-container'
      if (parentNode) {
        parentNode.insertBefore(container, pre)
      }
      container.appendChild(pre)
    }

    if (container.dataset.copyButton === 'true') continue
    container.dataset.copyButton = 'true'
    const detach = attachCopyButton(container, pre)
    cleanupFns.push(() => {
      delete container.dataset.copyButton
      detach()
      if (container.classList.contains('code-copy-container')) {
        const btn = container.querySelector('.code-copy-button')
        if (!btn && container.childElementCount === 1 && container.firstElementChild === pre) {
          container.replaceWith(pre)
        }
      }
    })
  }

  return cleanupFns
}
