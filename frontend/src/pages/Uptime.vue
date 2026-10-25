<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { Activity, FileDown, Loader2 } from 'lucide-vue-next';
import Card from '@/components/ui/Card.vue';
import CardHeader from '@/components/ui/CardHeader.vue';
import CardContent from '@/components/ui/CardContent.vue';
import Button from '@/components/ui/Button.vue';
import StatusBadge from '@/components/ui/StatusBadge.vue';
import { api, type LatencyHour, type LatencyProfile, type Uptime, type UptimeBucket, type UptimeTz } from '@/lib/api';
import { inBank, store } from '@/lib/store';
import { fmtTime } from '@/lib/utils';
import AlertsPanel from '@/components/AlertsPanel.vue';

// Continuous monitor: daily and monthly uptime per target (NBG asks for both).
const days = ref(31);
// Calendar for daily/monthly buckets and every time on this page: Tbilisi (banks, NBG). Tashkent (operator) stays available in the API and CSV only.
const TZ: Record<UptimeTz, { label: string; iana: string; offsetH: number }> = {
  tbilisi: { label: 'Tbilisi', iana: 'Asia/Tbilisi', offsetH: 4 },
  tashkent: { label: 'Tashkent', iana: 'Asia/Tashkent', offsetH: 5 },
};
// No zone switch any more: a Tashkent choice stored by older versions of this page is ignored.
const tz = ref<UptimeTz>('tbilisi');
const data = ref<Uptime | null>(null);
const error = ref('');
let timer: ReturnType<typeof setInterval> | undefined;

async function load() {
  loadProfile();
  try {
    data.value = await api.uptime(days.value, tz.value);
    error.value = '';
  } catch (e: any) {
    error.value = e.message;
  }
}

// Hour-of-day latency (last 7 days, Tbilisi hours): latency and uptime differ between 09:00, 15:00 and 21:00.
const profile = ref<LatencyProfile | null>(null);
const profileError = ref('');
const metric = ref<'p95' | 'p50'>('p95');
async function loadProfile() {
  try {
    profile.value = await api.latencyProfile(7);
    profileError.value = '';
  } catch (e: any) {
    profileError.value = e.message;
  }
}
const OP_LABEL: Record<string, string> = {
  'monitor.front-door': 'Front door',
  'monitor.ais.accounts': 'Accounts',
  'monitor.ais.balances': 'Balances',
  'monitor.ais.transactions': 'Transactions',
};
const hours = Array.from({ length: 24 }, (_, h) => h);
const pad = (h: number) => String(h).padStart(2, '0');
const enough = (c: LatencyHour) => c.httpSamples >= (profile.value?.minSamples ?? 3);
const cellValue = (c: LatencyHour) => (metric.value === 'p95' ? c.p95 : c.p50);
/** Colour vs the latency threshold (p95 target): within half of it good, within it warning, above critical; greyed below minSamples. */
function latencyStyle(c: LatencyHour) {
  const v = cellValue(c);
  if (!enough(c) || v === null) return { background: 'var(--muted)', color: 'var(--muted-foreground)' };
  const thr = profile.value?.latencyP95Ms ?? 1000;
  if (v > thr / 2 && v <= thr) return { background: 'var(--status-warning)', color: '#1a1a1a' };
  return { background: v <= thr ? 'var(--status-good)' : 'var(--status-critical)', color: '#fff' };
}
function hourText(op: string, c: LatencyHour) {
  return `${OP_LABEL[op] ?? op}, ${pad(c.hour)}:00-${pad(c.hour)}:59 Tbilisi: ${c.samples} samples (${c.httpSamples} with HTTP answer), p50 ${c.p50 ?? '-'} ms, p95 ${c.p95 ?? '-'} ms, up ${c.upPct ?? '-'}%`;
}
onMounted(() => {
  load();
  timer = setInterval(load, 60_000);
});
onUnmounted(() => clearInterval(timer));

const names = computed<Record<string, string>>(() => Object.fromEntries((store.report?.targets ?? []).map((t) => [t.id, t.name])));

/** Last N calendar days in the chosen time zone, oldest first, so missing days show as gaps. */
const dayList = computed(() => {
  const out: string[] = [];
  const now = Date.now() + TZ[tz.value].offsetH * 3600_000;
  for (let i = days.value - 1; i >= 0; i--) out.push(new Date(now - i * 86400_000).toISOString().slice(0, 10));
  return out;
});

const fmtPct = (v: number | null | undefined) => (v === null || v === undefined ? '-' : `${v}%`);
const meets = (v: number | null | undefined) => v !== null && v !== undefined && v >= (data.value?.availabilityPct ?? 99.5);
function cellColor(b?: UptimeBucket) {
  if (!b || b.uptimePct === null) return 'var(--muted)';
  // Partial periods (monitor not running the whole day) are not judged against the threshold.
  if (b.partial) return 'var(--muted-foreground)';
  if (b.uptimePct >= (data.value?.availabilityPct ?? 99.5)) return 'var(--status-good)';
  return b.uptimePct >= 95 ? 'var(--status-warning)' : 'var(--status-critical)';
}
const byDay = (daily: UptimeBucket[]) => Object.fromEntries(daily.map((d) => [d.period, d]));
// Touch screens have no hover: tapping a day shows its numbers under the bar strip (per target).
const picked = ref<Record<string, string>>({});
// Hover previews a day; a click pins it (hover then no longer changes the line); clicking the pinned day releases it.
const hovered = ref<Record<string, string>>({});
const shown = (id: string) => picked.value[id] ?? hovered.value[id];
function togglePin(id: string, d: string) {
  if (picked.value[id] === d) delete picked.value[id];
  else picked.value[id] = d;
}
/** Last-sample error without the "fetch failed (...)" wrapper, so the code fits the tile. */
const shortError = (e?: string) => (e ?? '').replace(/^fetch failed \((.*)\)$/, '$1');
function dayText(daily: UptimeBucket[], d: string) {
  const b = byDay(daily)[d];
  return b ? `${d}: ${b.uptimePct}% (${b.up}/${b.samples} samples, coverage ${b.coveragePct ?? '-'}%${b.partial ? ', partial day' : ''}), p50 ${b.p50 ?? '-'} ms` : `${d}: no samples`;
}
</script>

<template>
  <div class="space-y-6">
    <AlertsPanel />
    <div class="flex flex-wrap items-start gap-3">
      <p class="max-w-3xl text-sm leading-relaxed text-muted-foreground">
        Continuous availability monitor, separate from audit runs. One unauthenticated, read-only request per target:
        every {{ data?.intervals?.simulatedMin ?? '?' }} min for the mock, every {{ data?.intervals?.realMin ?? '?' }} min for real banks (spec-only banks have no host to sample). A target counts as up when it answers below HTTP 500,
        or refuses at TLS level for a missing client certificate (alive and enforcing mTLS).
        Days, months and times are {{ TZ[tz].label }} time (UTC+{{ TZ[tz].offsetH }}). Target {{ data?.source === 'assumed' ? '(assumed)' : '' }}: ≥ {{ data?.availabilityPct ?? 99.5 }}%.
      </p>
      <!-- Phones: full-width control row (period grows, CSV keeps its size). -->
      <div class="flex w-full items-center gap-2 sm:ml-auto sm:w-auto">
        <select v-model.number="days" class="h-10 flex-1 rounded-md border border-border bg-background px-2 text-sm sm:h-8 sm:flex-none" aria-label="Period" @change="load">
          <option :value="7">7 days</option>
          <option :value="31">31 days</option>
          <option :value="100">100 days</option>
        </select>
        <a :href="api.uptimeCsvUrl(days, tz)" aria-label="Download daily uptime CSV"><Button variant="outline" size="sm" class="h-10 sm:h-8"><FileDown class="size-4" />CSV<span class="hidden sm:inline">&nbsp;daily</span></Button></a>
      </div>
    </div>

    <p v-if="error" class="text-sm text-muted-foreground">{{ error }}</p>
    <div v-else-if="!data" class="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 class="size-4 animate-spin" />Loading…</div>
    <p v-else-if="!data.enabled" class="text-sm">Monitor is off (MONITOR_ENABLED=false).</p>
    <p v-else-if="!data.targets.some((x) => inBank(x.targetId))" class="text-sm text-muted-foreground">This bank is not monitored: it publishes no host to sample (spec only).</p>

    <template v-if="data">
      <Card v-for="t in data.targets.filter((x) => inBank(x.targetId))" :key="t.targetId">
        <CardHeader :title="t.name ?? names[t.targetId] ?? t.targetId" :description="`Sampled every ${t.intervalMin} min`" />
        <CardContent class="space-y-5">
          <div v-if="!t.lastSample" class="text-sm text-muted-foreground">No samples yet. The first one arrives within a minute of start-up.</div>
          <template v-else>
            <div class="grid grid-cols-2 gap-3 md:grid-cols-4">
              <!-- Tiles: label on top, content centred in the remaining height so all four line up. -->
              <div class="flex min-w-0 flex-col rounded-lg border border-border p-3">
                <div class="text-xs text-muted-foreground">Last sample</div>
                <div class="flex flex-1 flex-col justify-center gap-1 pt-1">
                  <div class="flex min-w-0 items-center gap-2">
                    <StatusBadge class="shrink-0" :status="t.lastSample.up ? 'pass' : 'fail'" />
                    <span class="min-w-0 truncate font-mono text-xs text-muted-foreground" :title="t.lastSample.error || String(t.lastSample.status)">{{ t.lastSample.status ? `HTTP ${t.lastSample.status}` : shortError(t.lastSample.error) }}</span>
                  </div>
                  <div class="text-xs text-muted-foreground">{{ fmtTime(t.lastSample.ts, TZ[tz].iana) }}</div>
                </div>
              </div>
              <div v-for="k in (['last24h', 'last7d', 'last30d'] as const)" :key="k" class="flex flex-col rounded-lg border border-border p-3">
                <div class="text-xs text-muted-foreground">{{ k === 'last24h' ? 'Last 24 h' : k === 'last7d' ? 'Last 7 days' : 'Last 30 days' }}</div>
                <div class="flex flex-1 items-center gap-2 pt-1">
                  <span class="text-2xl font-semibold tabular-nums">{{ fmtPct(t[k]) }}</span>
                  <StatusBadge v-if="t[k] !== null" :status="meets(t[k]) ? 'pass' : 'fail'" compact />
                </div>
              </div>
            </div>

            <div>
              <div class="mb-1 flex items-center gap-2 text-xs text-muted-foreground"><Activity class="size-3.5" />Daily uptime, oldest → today (hover a day; click to pin)</div>
              <div class="flex gap-[2px] sm:gap-[3px]">
                <button
                  v-for="d in dayList"
                  :key="d"
                  type="button"
                  class="h-8 min-w-0 flex-1 rounded-sm outline-offset-1"
                  :class="picked[t.targetId] === d ? 'outline-2 outline-foreground' : !picked[t.targetId] && hovered[t.targetId] === d ? 'outline-1 outline-muted-foreground' : ''"
                  :style="{ background: cellColor(byDay(t.daily)[d]) }"
                  :aria-label="dayText(t.daily, d)"
                  :aria-pressed="picked[t.targetId] === d"
                  @mouseenter="hovered[t.targetId] = d"
                  @mouseleave="delete hovered[t.targetId]"
                  @click="togglePin(t.targetId, d)"
                />
              </div>
              <div class="mt-1.5 flex min-h-5 items-center gap-2 text-xs tabular-nums text-muted-foreground">
                <span>{{ shown(t.targetId) ? dayText(t.daily, shown(t.targetId)!) : '' }}</span>
                <button v-if="picked[t.targetId]" type="button" class="rounded border border-border px-1.5 text-[11px] hover:bg-accent hover:text-foreground" @click="delete picked[t.targetId]">pinned · release</button>
              </div>
            </div>

            <div class="grid gap-5 md:grid-cols-2">
              <div class="overflow-x-auto">
                <div class="mb-1 text-xs font-medium">Monthly</div>
                <table class="w-full text-sm">
                  <thead><tr class="border-b border-border text-left text-xs text-muted-foreground"><th class="py-1.5 font-medium">Month</th><th class="text-right font-medium">Samples</th><th class="text-right font-medium">Uptime</th><th class="text-right font-medium">Coverage</th><th class="text-right font-medium">p50 ms</th><th class="px-2 font-medium">Verdict</th></tr></thead>
                  <tbody>
                    <tr v-for="m in [...t.monthly].reverse()" :key="m.period" class="border-b border-border last:border-0">
                      <td class="py-1.5 tabular-nums">{{ m.period }}</td>
                      <td class="text-right tabular-nums">{{ m.samples }}</td>
                      <td class="text-right tabular-nums">{{ fmtPct(m.uptimePct) }}</td>
                      <td class="text-right text-xs tabular-nums text-muted-foreground">{{ fmtPct(m.coveragePct) }}<span v-if="m.partial"> · partial</span></td>
                      <td class="text-right tabular-nums">{{ m.p50 ?? '-' }}</td>
                      <td class="px-2"><StatusBadge :status="m.partial ? 'info' : meets(m.uptimePct) ? 'pass' : 'fail'" /></td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <div class="overflow-x-auto">
                <div class="mb-1 text-xs font-medium">Recent incidents (consecutive failed samples)</div>
                <table v-if="t.incidents.length" class="w-full text-sm">
                  <thead><tr class="border-b border-border text-left text-xs text-muted-foreground"><th class="py-1.5 font-medium">From</th><th class="font-medium">To</th><th class="text-right font-medium">Samples</th><th class="px-2 font-medium">Reason</th></tr></thead>
                  <tbody>
                    <tr v-for="i in t.incidents.slice(0, 8)" :key="i.start" class="border-b border-border last:border-0">
                      <td class="py-1.5 text-xs">{{ fmtTime(i.start, TZ[tz].iana) }}</td>
                      <td class="text-xs">{{ fmtTime(i.end, TZ[tz].iana) }}</td>
                      <td class="text-right tabular-nums">{{ i.samples }}</td>
                      <td class="px-2 font-mono text-xs text-muted-foreground">{{ i.reason }}</td>
                    </tr>
                  </tbody>
                </table>
                <p v-else class="text-sm text-muted-foreground">None in this period.</p>
              </div>
            </div>
          </template>
        </CardContent>
      </Card>
    </template>

    <Card v-if="profile?.enabled && profile.targets.some((x) => inBank(x.targetId))">
      <CardHeader
        title="Latency by hour (Tbilisi)"
        :description="`Last ${profile.days} days, by hour of the day. Front door measured every ${profile.intervals.simulatedMin} min (mock) / ${profile.intervals.realMin} min (real banks)${profile.intervals.authenticatedMin > 0 ? `; authenticated AIS reads on the mock every ${profile.intervals.authenticatedMin} min` : ''}. Colour vs the ${profile.latencyP95Ms} ms latency target${profile.source === 'assumed' ? ' (assumed)' : ''}; grey = fewer than ${profile.minSamples} answers.`"
      />
      <CardContent class="space-y-5">
        <div class="flex h-10 w-fit rounded-md border border-border p-0.5 text-sm sm:h-8" role="group" aria-label="Latency figure">
          <button
            v-for="m in (['p95', 'p50'] as const)"
            :key="m"
            type="button"
            class="rounded px-2.5 transition-colors"
            :class="metric === m ? 'bg-accent font-medium text-foreground' : 'text-muted-foreground hover:text-foreground'"
            :aria-pressed="metric === m"
            @click="metric = m"
          >
            {{ m }}
          </button>
        </div>
        <div v-for="t in profile.targets.filter((x) => inBank(x.targetId))" :key="t.targetId">
          <div class="mb-1 text-xs font-medium">{{ t.name }}</div>
          <!-- Only the table scrolls sideways on phones; the label column stays in view. -->
          <div class="overflow-x-auto">
            <table class="w-full border-separate border-spacing-[2px] text-[11px] tabular-nums">
              <thead>
                <tr class="text-muted-foreground">
                  <th class="sticky left-0 z-10 bg-card pr-2 text-left font-medium">ms</th>
                  <th v-for="h in hours" :key="h" class="min-w-9 font-normal" :class="[9, 15, 21].includes(h) ? 'font-semibold text-foreground' : ''">{{ pad(h) }}</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="r in t.rows" :key="r.operation">
                  <th class="sticky left-0 z-10 bg-card pr-2 text-left font-normal whitespace-nowrap">
                    {{ OP_LABEL[r.operation] ?? r.operation }}
                    <span class="block text-[10px] text-muted-foreground">every {{ r.operation === 'monitor.front-door' ? t.intervalMin : profile.intervals.authenticatedMin }} min</span>
                  </th>
                  <td v-for="c in r.hours" :key="c.hour" class="h-8 rounded-sm text-center transition-colors" :style="latencyStyle(c)" :title="hourText(r.operation, c)" :aria-label="hourText(r.operation, c)">
                    {{ c.httpSamples ? (cellValue(c) ?? c.p50) : '' }}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </CardContent>
    </Card>
    <p v-else-if="profileError" class="text-sm text-muted-foreground">Latency by hour: {{ profileError }}</p>
  </div>
</template>
