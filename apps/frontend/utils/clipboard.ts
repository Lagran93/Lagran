/**
 * Copy text in both secure and non-secure contexts.
 *
 * `navigator.clipboard` is only available on HTTPS/localhost and can still be
 * denied by permissions policy. Fall back to the legacy selection-based API so
 * the console keeps working behind an HTTP admin origin or an embedded webview.
 */
export async function copyText(text: string): Promise<boolean> {
  if (import.meta.client && window.isSecureContext && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text)
      return true
    } catch {
      // Fall through to the legacy path.
    }
  }

  if (!import.meta.client || !document?.body) return false

  const ta = document.createElement('textarea')
  ta.value = text
  ta.setAttribute('readonly', '')
  ta.style.position = 'fixed'
  ta.style.top = '-9999px'
  ta.style.left = '-9999px'
  ta.style.opacity = '0'
  document.body.appendChild(ta)
  ta.focus()
  ta.select()
  ta.setSelectionRange(0, text.length)

  let ok = false
  try {
    ok = document.execCommand('copy')
  } catch {
    ok = false
  } finally {
    document.body.removeChild(ta)
  }
  return ok
}
