export interface ToastItem {
  id: number
  type: 'success' | 'error' | 'info'
  text: string
}

export function useToast() {
  const items = useState<ToastItem[]>('lagran_toasts', () => [])

  let seq = 0

  function push(type: ToastItem['type'], text: string, duration = 3000) {
    seq += 1
    const id = Date.now() + seq
    items.value = [...items.value, { id, type, text }]
    if (import.meta.client) {
      window.setTimeout(() => {
        items.value = items.value.filter(t => t.id !== id)
      }, duration)
    }
  }

  return {
    items,
    success: (text: string) => push('success', text),
    error: (text: string) => push('error', text, 4200),
    info: (text: string) => push('info', text),
  }
}
