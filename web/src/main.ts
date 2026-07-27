import { createApp } from 'vue'

import App from './App.vue'
import { i18n, setLocale } from './i18n'
import router from './router'
import './styles.css'
import './ui-v3.css'
import './rc5.css'

setLocale(i18n.global.locale.value)
createApp(App).use(i18n).use(router).mount('#app')
