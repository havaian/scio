<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { RouterLink } from 'vue-router';
import { CheckCircle2, XCircle, AlertTriangle, MinusCircle, Circle, Cpu, ShieldCheck, ShieldAlert, ChevronRight } from 'lucide-vue-next';
import Card from '@/components/ui/Card.vue';
import CardHeader from '@/components/ui/CardHeader.vue';
import CardContent from '@/components/ui/CardContent.vue';
import Score from '@/components/ui/Score.vue';
import FindingCard from '@/components/FindingCard.vue';
import OverallScore from '@/components/OverallScore.vue';
import { api, type Finding, type TargetReport, type Uptime } from '@/lib/api';
import { setBank, store } from '@/lib/store';
import { ACCESS_LABEL, JOURNEY, LAYERS, LAYER_LABEL, LAYER_SHORT, accessOf } from '@/lib/utils';

// Per-bank summary: how far Scio got (journey), scores, worst findings, uptime, plain-language summary.
const r = computed(() => store.report!);
const bank = computed(() => r.value.targets.find((t) => t.id === store.bank) ?? null);

const own = (t: TargetReport) => r.value.findings.filter((f) => f.targetId === t.id && f.source !== 'ai');
const sevRank: Record<string, number> = { high: 0, medium: 1, low: 2, none: 3 };
const statusRank: Record<string, number> = { fail: 0, warn: 1, info: 2, skip: 3, pass: 4 };

interface Step { label: string; status: string; message?: string }
/** Journey steps from the findings; a step without a finding after a stop is "not reached". */
function journey(t: TargetReport): { steps: Step[]; notRun?: Finding; stoppedAt?: Step } | null {
  const defs = JOURNEY[accessOf(t)];
  if (!defs) return null;
  const fs = own(t);
  // "Not run": certificates or app keys missing. Any other skip of the whole flow (e.g. sandbox unreachable) stops at step 1.
  const flowSkip = fs.find((f) => (f.checkId === 'flow.sandbox' || f.checkId === 'bis.flow') && f.status === 'skip');
  const notRun = flowSkip && /^Not run/.test(flowSkip.message) ? flowSkip : undefined;
  const steps = defs.map((d) => {
    const f = d.checks.map((c) => fs.find((x) => x.checkId === c)).find(Boolean);
    return { label: d.label, status: f?.status ?? 'none', message: f?.message };
  });
  if (flowSkip && !notRun && steps[0].status === 'none') Object.assign(steps[0], { status: 'skip', message: flowSkip.message });
  // Not run at all: every step is simply not reached (the flow's own skip is shown as the note).
  if (notRun) for (const st of steps) Object.assign(st, { status: 'none', message: undefined });
  const stoppedAt = steps.find((s) => s.status !== 'pass');
  return { steps, notRun, stoppedAt };
}
const STEP_ICON: Record<string, { icon: unknown; color: string; label: string }> = {
  pass: { icon: CheckCircle2, color: 'var(--status-good)', label: 'passed' },
  fail: { icon: XCircle, color: 'var(--status-critical)', label: 'failed' },
  warn: { icon: AlertTriangle, color: 'var(--status-serious)', label: 'passed with a warning' },
  skip: { icon: MinusCircle, color: 'var(--muted-foreground)', label: 'could not be tested' },
  info: { icon: MinusCircle, color: 'var(--muted-foreground)', label: 'informational' },
  none: { icon: Circle, color: 'var(--muted-foreground)', label: 'not reached' },
};
const NO_JOURNEY: Record<string, string> = {
  probes: 'No sandbox access yet: public front-door probes and spec checks only.',
  spec: 'No reachable sandbox: only the published OpenAPI document is checked.',
};

const top = computed(() =>
  bank.value
    ? own(bank.value)
        .filter((f) => f.status === 'fail' || f.status === 'warn')
        .sort((a, b) => statusRank[a.status] - statusRank[b.status] || sevRank[a.severity] - sevRank[b.severity])
    : [],
);
const summary = computed(() => r.value.local?.summaries?.find((s) => s.targetId === store.bank));

// Uptime from the monitor, by Tbilisi calendar days (all times are Georgian time).
const uptime = ref<Uptime | null>(null);
onMounted(async () => {
  uptime.value = await api.uptime(31, 'tbilisi').catch(() => null);
});
const upOf = (id: string) => uptime.value?.targets.find((u) => u.targetId === id);
const fmtPct = (v: number | null | undefined) => (v === null || v === undefined ? '-' : `${v}%`);
const upTone = (v: number | null | undefined) =>
  v === null || v === undefined ? 'text-muted-foreground' : v >= (uptime.value?.availabilityPct ?? 99.5) ? 'text-[var(--status-good)]' : 'text-[var(--status-critical)]';
</script>

<template>
  <!-- All banks: one card each; tap to open its summary. -->
  <div v-if="!bank" class="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
    <button
      v-for="t in r.targets"
      :key="t.id"
      type="button"
      class="min-w-0 rounded-xl border border-border bg-card p-4 text-left transition-colors hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
      @click="setBank(t.id)"
    >
      <div class="flex items-start justify-between gap-3">
        <div class="min-w-0">
          <div class="font-medium leading-snug">{{ t.name }}</div>
          <span class="mt-1 inline-block rounded border border-border px-1 text-xs text-muted-foreground">{{ ACCESS_LABEL[accessOf(t)] }}</span>
        </div>
        <OverallScore class="shrink-0" :evaluated="t.evaluated" :overall="t.overall" :min="r.thresholds.minEvaluatedChecks" large />
      </div>
      <div v-if="journey(t)" class="mt-3 flex items-center gap-1" :aria-label="`Journey: ${journey(t)!.steps.map((s) => `${s.label} ${STEP_ICON[s.status].label}`).join(', ')}`">
        <template v-for="(s, i) in journey(t)!.steps" :key="s.label">
          <component :is="STEP_ICON[s.status].icon" class="size-4 shrink-0" :style="{ color: STEP_ICON[s.status].color }" />
          <span v-if="i < journey(t)!.steps.length - 1" class="h-px min-w-2 flex-1 bg-border" />
        </template>
      </div>
      <div class="mt-2 text-xs text-muted-foreground">
        <template v-if="journey(t)?.notRun">Journey not run yet: certificates pending</template>
        <template v-else-if="journey(t)?.stoppedAt">Stops at: {{ journey(t)!.stoppedAt!.label }} ({{ STEP_ICON[journey(t)!.stoppedAt!.status].label }})</template>
        <template v-else-if="journey(t)">Journey complete</template>
        <template v-else>{{ NO_JOURNEY[accessOf(t)] ?? '' }}</template>
      </div>
      <div class="mt-2 flex items-center justify-between text-xs text-muted-foreground">
        <span class="tabular-nums">{{ t.counts.fail }} fail · {{ t.counts.warn }} warn · {{ t.counts.pass }} pass</span>
        <span v-if="upOf(t.id)" class="tabular-nums">uptime 24 h <b :class="upTone(upOf(t.id)!.last24h)">{{ fmtPct(upOf(t.id)!.last24h) }}</b></span>
      </div>
    </button>
  </div>

  <!-- One bank. -->
  <div v-else class="space-y-6">
    <Card>
      <CardContent class="p-4 sm:p-5">
        <div class="flex items-start justify-between gap-3">
          <div class="min-w-0">
            <h2 class="text-lg font-semibold leading-snug">{{ bank.name }}</h2>
            <div class="mt-1 flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
              <span class="rounded border border-border px-1">{{ ACCESS_LABEL[accessOf(bank)] }}</span>
              <a v-if="bank.source" :href="bank.source" target="_blank" rel="noopener" class="underline underline-offset-2">source</a>
            </div>
            <div class="mt-1.5 truncate font-mono text-xs text-muted-foreground" :title="bank.baseUrl">{{ bank.baseUrl.replace(/^https?:\/\//, '') }}</div>
          </div>
          <OverallScore class="shrink-0" :evaluated="bank.evaluated" :overall="bank.overall" :min="r.thresholds.minEvaluatedChecks" large />
        </div>
        <p v-if="bank.note" class="mt-3 text-sm leading-relaxed text-muted-foreground">{{ bank.note }}</p>
      </CardContent>
    </Card>

    <Card>
      <CardHeader title="Journey" description="How far Scio got with this bank in this run." />
      <CardContent>
        <template v-if="journey(bank)">
          <p v-if="journey(bank)!.notRun" class="mb-3 rounded-md bg-muted px-3 py-2 text-sm">{{ journey(bank)!.notRun!.message }}</p>
          <ol class="grid gap-3 md:grid-flow-col md:auto-cols-fr">
            <li v-for="(s, i) in journey(bank)!.steps" :key="s.label" class="flex min-w-0 items-start gap-2 md:flex-col md:gap-1.5">
              <div class="flex items-center gap-2 md:w-full">
                <component :is="STEP_ICON[s.status].icon" class="size-5 shrink-0" :style="{ color: STEP_ICON[s.status].color }" />
                <span v-if="i < journey(bank)!.steps.length - 1" class="hidden h-px flex-1 bg-border md:block" />
              </div>
              <div class="min-w-0">
                <div class="text-sm font-medium">{{ s.label }}</div>
                <div class="text-xs text-muted-foreground">{{ STEP_ICON[s.status].label }}</div>
              </div>
            </li>
          </ol>
          <p v-if="journey(bank)!.stoppedAt?.message" class="mt-3 border-t border-border pt-3 text-sm leading-relaxed [overflow-wrap:anywhere]">
            <span class="font-medium">{{ journey(bank)!.stoppedAt!.label }}:</span> {{ journey(bank)!.stoppedAt!.message }}
          </p>
        </template>
        <p v-else class="text-sm text-muted-foreground">{{ NO_JOURNEY[accessOf(bank)] ?? 'No journey for this target.' }}</p>
      </CardContent>
    </Card>

    <div class="grid gap-6 lg:grid-cols-2">
      <Card>
        <CardHeader title="Scores" :description="`${bank.counts.fail} failures · ${bank.counts.warn} warnings · ${bank.counts.pass} passed`" />
        <CardContent class="grid grid-cols-3 gap-2 text-center sm:grid-cols-5">
          <div v-for="l in LAYERS" :key="l" class="rounded-md bg-muted px-1 py-2">
            <div class="truncate text-[11px] text-muted-foreground" :title="LAYER_LABEL[l]">{{ LAYER_SHORT[l] }}</div>
            <Score :value="bank.scores[l]" />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader title="Uptime" :description="upOf(bank.id) ? `Continuous monitor, sampled every ${upOf(bank.id)!.intervalMin} min` : 'Not monitored (no host to sample) or no samples yet.'" />
        <CardContent v-if="upOf(bank.id)" class="space-y-3">
          <div class="grid grid-cols-3 gap-2 text-center">
            <div v-for="k in (['last24h', 'last7d', 'last30d'] as const)" :key="k" class="rounded-md bg-muted px-1 py-2">
              <div class="text-[11px] text-muted-foreground">{{ k === 'last24h' ? '24 h' : k === 'last7d' ? '7 days' : '30 days' }}</div>
              <div class="font-semibold tabular-nums" :class="upTone(upOf(bank.id)![k])">{{ fmtPct(upOf(bank.id)![k]) }}</div>
            </div>
          </div>
          <RouterLink to="/uptime" class="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">Daily and monthly detail <ChevronRight class="size-3.5" /></RouterLink>
        </CardContent>
      </Card>
    </div>

    <Card v-if="summary">
      <CardHeader title="Plain-language summary" description="Written on this machine by a local model (QVAC) from computed findings only; numbers are checked against the data." />
      <CardContent>
        <div class="mb-1 flex items-center gap-2 text-xs text-muted-foreground">
          <Cpu class="size-3.5" />{{ summary.model }}
          <span class="ml-auto inline-flex items-center gap-1 rounded border border-border px-1.5 py-0.5">
            <ShieldCheck v-if="summary.verified" class="size-3.5" style="color: var(--status-good)" />
            <ShieldAlert v-else class="size-3.5" style="color: var(--status-serious)" />
            {{ summary.verified ? 'checked against data' : 'needs review' }}
          </span>
        </div>
        <div class="font-medium">{{ summary.headline }}</div>
        <p class="mt-1 text-sm leading-relaxed">{{ summary.summary }}</p>
        <ul class="mt-2 list-disc space-y-0.5 pl-5 text-sm">
          <li v-for="a in summary.actions" :key="a">{{ a }}</li>
        </ul>
      </CardContent>
    </Card>

    <div>
      <div class="mb-2 flex items-baseline justify-between gap-3">
        <h2 class="text-sm font-semibold">Top issues</h2>
        <RouterLink to="/findings" class="shrink-0 text-xs text-muted-foreground hover:text-foreground">All {{ top.length }} issues →</RouterLink>
      </div>
      <div class="grid gap-2">
        <FindingCard v-for="(f, i) in top.slice(0, 6)" :key="i" :f="f" :target-name="bank.name" />
        <p v-if="!top.length" class="py-6 text-center text-sm text-muted-foreground">No failures or warnings for this bank.</p>
      </div>
    </div>
  </div>
</template>
