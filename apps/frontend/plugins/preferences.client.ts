export default defineNuxtPlugin(() => {
  const theme = useTheme()
  const locale = useLocale()
  theme.init()
  locale.init()
})
