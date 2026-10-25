import { createApp } from 'vue';
import { createRouter, createWebHistory } from 'vue-router';
import App from './App.vue';
import Overview from './pages/Overview.vue';
import Banks from './pages/Banks.vue';
import Findings from './pages/Findings.vue';
import Matrix from './pages/Matrix.vue';
import Quality from './pages/Quality.vue';
import Runs from './pages/Runs.vue';
import Uptime from './pages/Uptime.vue';
import './style.css';

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: Overview },
    { path: '/banks', component: Banks },
    { path: '/findings', component: Findings },
    { path: '/incompatibility', component: Matrix },
    { path: '/quality', component: Quality },
    { path: '/uptime', component: Uptime },
    { path: '/runs', component: Runs },
  ],
});

createApp(App).use(router).mount('#app');
