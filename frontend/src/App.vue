<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue';
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router';
import { Loader2, FileDown, Moon, Sun } from 'lucide-vue-next';
import Button from '@/components/ui/Button.vue';
import BankPicker from '@/components/BankPicker.vue';
import { api } from '@/lib/api';
import { loadQuota, loadReport, loadSchedule, setBank, store } from '@/lib/store';
import { fmtShort, fmtTime, TZ_LABEL } from '@/lib/utils';

const nav = [
  { to: '/', label: 'Scorecard' },
  { to: '/banks', label: 'Banks' },
  { to: '/findings', label: 'Findings' },
  { to: '/incompatibility', label: 'Incompatibility' },
  { to: '/quality', label: 'Quality' },
  { to: '/uptime', label: 'Uptime' },
  { to: '/runs', label: 'Runs' },
];

const route = useRoute();
const router = useRouter();

// Bank filter in the URL (?bank=), so a filtered page can be shared; a bank missing from the report resets to all.
watch(
  () => [store.bank, route.path] as const,
  () => {
    const want = store.bank === 'all' ? undefined : store.bank;
    if (route.query.bank !== want) router.replace({ query: { ...route.query, bank: want } });
  },
);
watch(
  () => store.report,
  (r) => {
    if (r && store.bank !== 'all' && !r.targets.some((t) => t.id === store.bank)) setBank('all');
  },
);

// Header height as a CSS variable, for sticky table headers below it (the header wraps on small screens).
const headerEl = ref<HTMLElement | null>(null);
let headerObs: ResizeObserver | undefined;
onMounted(() => {
  if (!headerEl.value || typeof ResizeObserver === 'undefined') return;
  headerObs = new ResizeObserver(() => document.documentElement.style.setProperty('--header-h', `${headerEl.value!.offsetHeight}px`));
  headerObs.observe(headerEl.value);
});
onUnmounted(() => headerObs?.disconnect());
// Small screens: the nav strip scrolls sideways; keep the active tab in view after navigation.
const navEl = ref<HTMLElement | null>(null);
watch(
  () => route.path,
  async () => {
    await nextTick();
    const a = navEl.value?.querySelector<HTMLElement>('[aria-current="page"]');
    if (a && navEl.value) navEl.value.scrollTo({ left: a.offsetLeft - navEl.value.clientWidth / 2 + a.clientWidth / 2, behavior: 'smooth' });
  },
);
const theme = ref<string | null>(null);
function toggleTheme() {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === 'dark'
    : matchMedia('(prefers-color-scheme: dark)').matches;
  theme.value = dark ? 'light' : 'dark';
  document.documentElement.dataset.theme = theme.value;
  try { localStorage.setItem('theme', theme.value); } catch {}
}

onMounted(() => {
  try {
    const t = localStorage.getItem('theme');
    if (t) { document.documentElement.dataset.theme = t; theme.value = t; }
    else document.documentElement.dataset.theme = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  } catch {}
  loadReport();
  loadQuota();
  loadSchedule();
});

// Manual runs are allowed only when the schedule says so (default: schedule + CLI only).
const manual = computed(() => store.schedule?.manualRuns === true);
// Times in Tbilisi (UTC+4), whatever the viewer's zone is.
const nextAudit = computed(() => fmtShort(store.schedule?.next?.at ?? store.schedule?.nextAt ?? undefined));
const slotLabel = (t: string) => (t === 'all' ? 'all targets' : 'mock only');
// All daily slots, e.g. "09:00 (all targets), 15:00 (mock only), 21:00 (mock only)"; older servers send one time.
const slotsText = computed(() =>
  store.schedule?.slots?.length ? store.schedule.slots.map((s) => `${s.time} (${slotLabel(s.targets)})`).join(', ') : (store.schedule?.time ?? ''),
);
const nextTargets = computed(() => (store.schedule?.next ? ` (${slotLabel(store.schedule.next.targets)})` : ''));

const quotaUsed = computed(() => store.quota?.remaining === 0);
// Reset time shown in Tbilisi time (the quota's days are Tbilisi days), whatever the viewer's zone is.
const quotaReset = computed(() => (store.quota ? fmtShort(store.quota.resetsAt) : ''));

</script>

<template>
  <div class="min-h-screen font-sans">
    <header ref="headerEl" class="sticky top-0 z-30 border-b border-border bg-background/90 backdrop-blur">
      <!-- Small screens: logo + actions on one row, nav below it as a scrollable strip. md and up: one row. -->
      <div class="mx-auto flex max-w-7xl flex-wrap items-center gap-x-6 gap-y-2 px-4 pt-3 pb-2 md:py-3 lg:flex-nowrap lg:gap-x-4">
        <div class="order-1 flex items-center gap-2">
          <!-- Logo: terminal prompt "> scio" with a block cursor -->
          <span class="flex items-center gap-1.5 font-mono text-lg leading-none" role="img" aria-label="Scio">
            <span class="font-medium text-muted-foreground">&gt;</span>
            <span class="font-bold tracking-tight">scio</span>
            <span class="h-[18px] w-2 rounded-[2px] bg-brand"></span>
          </span>
          <span class="hidden shrink-0 rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium whitespace-nowrap text-muted-foreground sm:inline">Georgia · v0.8</span>
        </div>
        <nav ref="navEl" aria-label="Sections" class="no-scrollbar scroll-fade order-3 -mx-4 flex w-[calc(100%+2rem)] md:min-w-0 gap-1 overflow-x-auto px-4 pb-0.5 text-sm whitespace-nowrap md:order-2 md:mx-0 md:w-auto md:px-0 md:[mask-image:none]">
          <RouterLink v-for="n in nav" :key="n.to" :to="n.to" class="shrink-0 rounded-md px-3 py-2 text-muted-foreground hover:bg-accent hover:text-foreground md:px-2.5 md:py-1.5" active-class="!bg-accent !text-foreground font-medium">{{ n.label }}</RouterLink>
        </nav>
        <div class="order-2 ml-auto flex shrink-0 items-center gap-1.5 sm:gap-2 md:order-3">
          <!-- Run time and next audit stacked in two short lines, so the header stays on one row on desktop. -->
          <div v-if="store.report" class="hidden text-right text-[11px] leading-tight whitespace-nowrap text-muted-foreground xl:block">
            <div>Run {{ fmtTime(store.report.run.startedAt) }}</div>
            <div v-if="!manual && store.schedule?.enabled && nextAudit" :title="`Audits run automatically every day at ${slotsText} ${TZ_LABEL} time`">Next {{ nextAudit }} {{ TZ_LABEL }}{{ nextTargets }}</div>
          </div>
          <!-- Report downloads for the run on screen: printable HTML, full JSON data. -->
          <template v-if="store.report">
            <a :href="api.downloadUrl(store.report.run.id, 'html')" download>
              <Button variant="outline" size="sm" title="Download the printable report" aria-label="Download HTML report"><FileDown class="size-4" />HTML</Button>
            </a>
            <a :href="api.downloadUrl(store.report.run.id, 'json')" download>
              <Button variant="outline" size="sm" title="Download the full report data" aria-label="Download JSON report data"><FileDown class="size-4" />JSON</Button>
            </a>
          </template>
          <span v-if="manual && store.quota && store.quota.limit > 0" class="hidden text-xs text-muted-foreground md:inline" :title="`Limit resets at midnight ${TZ_LABEL} time (${quotaReset})`">
            Audits today: {{ store.quota.used }}/{{ store.quota.limit }}<template v-if="quotaUsed"> · next after {{ quotaReset }} {{ TZ_LABEL }}</template>
          </span>
          <Button variant="ghost" size="sm" class="w-9 px-0 sm:w-8" aria-label="Toggle theme" @click="toggleTheme">
            <Moon class="size-4 dark:hidden" /><Sun class="hidden size-4 dark:block" />
          </Button>
        </div>
      </div>
    </header>

    <main class="mx-auto max-w-7xl px-4 py-4 sm:py-6">
      <p v-if="store.error && store.report" class="mb-4 rounded-md border border-border bg-muted px-3 py-2 text-sm">{{ store.error }}</p>
      <!-- Uptime comes from the monitor and works before the first audit run. -->
      <!-- Bank filter for every page except the run list. -->
      <BankPicker v-if="route.path !== '/runs'" />
      <RouterView v-if="route.path === '/uptime'" />
      <div v-else-if="store.error && !store.report" class="rounded-xl border border-border p-8 text-center">
        <p class="font-medium">No audit results yet</p>
        <p v-if="!manual" class="mt-1 text-sm text-muted-foreground">
          Audits run automatically every day at {{ slotsText }} {{ TZ_LABEL }} time<template v-if="nextAudit">; the next one starts {{ nextAudit }}{{ nextTargets }}</template>.
        </p>
        <p v-else class="mt-1 text-sm text-muted-foreground">{{ store.error }}</p>
      </div>
      <RouterView v-else-if="store.report" />
      <div v-else class="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 class="size-4 animate-spin" />Loading…</div>
    </main>
  </div>
</template>
