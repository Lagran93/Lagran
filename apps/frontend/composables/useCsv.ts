export interface CsvColumn<T> {
  key: string
  label: string
  value?: (row: T) => unknown
}

function escape(value: unknown): string {
  if (value === null || value === undefined) return ''
  let text = typeof value === 'object' ? JSON.stringify(value) : String(value)
  if (/^[=+\-@]/.test(text)) text = `'${text}`
  return `"${text.replaceAll('"', '""')}"`
}

/** Download rows as an Excel-friendly UTF-8 CSV. */
export function exportCsv<T>(filename: string, rows: T[], columns: CsvColumn<T>[]) {
  if (!import.meta.client) return
  const head = columns.map((c) => escape(c.label)).join(',')
  const body = rows
    .map((row) =>
      columns
        .map((c) => escape(c.value ? c.value(row) : (row as Record<string, unknown>)[c.key]))
        .join(','),
    )
    .join('\r\n')
  const blob = new Blob([`\ufeff${head}\r\n${body}`], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename.endsWith('.csv') ? filename : `${filename}.csv`
  a.click()
  URL.revokeObjectURL(url)
}
