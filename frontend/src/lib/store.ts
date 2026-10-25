import { reactive } from 'vue';
import { api, type Report, type Run, type Schedule } from './api';

export const store = reactive({
  report: null as Report | null,
  runs: [] as Run[],
  selectedRun: 'latest',
  loading: false,
  error: '',
  activeRun: null as Run | null,
  schedule: null as Schedule | null,
  quota: null as { limit: number; used: number; remaining: number | null; resetsAt: string; timezone: string } | null,
  /** Bank filter shared by every page ('all' or a target id); kept in the URL (?bank=) and remembered per browser. */
  bank: readBank(),
});

function readBank(): string {
  try {
    const q = new URLSearchParams(location.search).get('bank');
    return q || localStorage.getItem('scio.bank') || 'all';
  } catch {
    return 'all';
  }
}

/** Sets the bank filter; the URL is updated by App.vue. */
export function setBank(id: string) {
  store.bank = id || 'all';
  try {
    localStorage.setItem('scio.bank', store.bank);
  } catch {
    /* storage blocked: the choice lasts for this page only */
  }
}

/** True when a target passes the bank filter. */
export const inBank = (targetId: string) => store.bank === 'all' || store.bank === targetId;

/** Automated audit schedule; with manual runs off the Run button is hidden. */
export async function loadSchedule() {
  store.schedule = await api.schedule().catch(() => null);
}

/** Daily audit quota; the Run button is disabled when it is used up. */
export async function loadQuota() {
  store.quota = await api.quota().catch(() => null);
}

export async function loadReport(id = store.selectedRun) {
  store.loading = true;
  store.error = '';
  try {
    store.report = await api.report(id);
    store.runs = await api.runs();
  } catch (e: any) {
    store.error = e.message;
    store.runs = await api.runs().catch(() => []);
  } finally {
    store.loading = false;
  }
}

/** Starts an audit and polls until it finishes, then loads its report. */
export async function startAudit(targets?: string[]) {
  const run = await api.start(targets);
  store.activeRun = run;
  while (store.activeRun?.status === 'running') {
    await new Promise((r) => setTimeout(r, 1500));
    store.activeRun = await api.run(run.id);
  }
  store.selectedRun = run.id;
  await loadReport(run.id);
  store.activeRun = null;
  await loadQuota();
}
