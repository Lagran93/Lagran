export interface ConfirmOptions {
  title: string
  message?: string
  confirmText?: string
  cancelText?: string
  danger?: boolean
}

interface ConfirmState extends ConfirmOptions {
  open: boolean
}

let resolver: ((ok: boolean) => void) | null = null

/**
 * Promise-based confirmation dialog. The `<ConfirmHost />` in the default
 * layout renders it, so pages only need:
 *   if (!(await ask({ title: '删除域名', message: '...', danger: true }))) return
 */
export function useConfirm() {
  const state = useState<ConfirmState>('lagran_confirm', () => ({
    open: false,
    title: '',
  }))

  function ask(options: ConfirmOptions): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
      resolver = resolve
      state.value = {
        open: true,
        confirmText: '确定',
        cancelText: '取消',
        ...options,
      }
    })
  }

  function settle(ok: boolean) {
    state.value = { ...state.value, open: false }
    const fn = resolver
    resolver = null
    fn?.(ok)
  }

  return { state, ask, settle }
}
