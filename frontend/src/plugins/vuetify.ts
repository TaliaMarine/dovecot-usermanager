import 'vuetify/styles'
import '@mdi/font/css/materialdesignicons.css'
import { createVuetify } from 'vuetify'

export default createVuetify({
  theme: {
    defaultTheme: 'system',
    themes: {
      light: {
        dark: false,
        colors: { primary: '#1867C0', background: '#F5F5F7', surface: '#FFFFFF' },
      },
      dark: {
        dark: true,
        colors: { primary: '#42A5F5', background: '#121212', surface: '#1E1E1E' },
      },
    },
  },
})
